package com.otilm.csc.utils.db;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.jdk.httpclient.JdkHttpClientBuilder;
import com.azure.identity.WorkloadIdentityCredentialBuilder;
import com.azure.identity.extensions.implementation.credential.TokenCredentialProviderOptions;
import com.azure.identity.extensions.implementation.credential.provider.TokenCredentialProvider;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.csc.utils.cert.CertificateUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * Stands in for the Microsoft Entra ID token endpoint, returning a fixed access token so that a
 * database connection can be exercised without a real tenant. It serves HTTPS with a certificate
 * it mints for {@code localhost} and publishes in {@value #CERTIFICATE_PROPERTY}, and writes the
 * federated token to a file named by {@value #TOKEN_FILE_PROPERTY} instead of passing it through
 * {@code AZURE_FEDERATED_TOKEN_FILE}. Both are forced by Azure library behaviour, recorded under
 * Dependency Management in CLAUDE.md.
 */
public final class MockEntraTokenIssuer implements AutoCloseable {

    /** System property carrying the Base64-encoded certificate the stub serves HTTPS with. */
    public static final String CERTIFICATE_PROPERTY = "csc.test.entra.certificate";

    /** System property carrying the path of the file holding the federated token to exchange. */
    public static final String TOKEN_FILE_PROPERTY = "csc.test.entra.federated-token-file";

    private static final String TOKEN_PATH = ".*/oauth2/v2\\.0/token";
    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String CERTIFICATE_ALIAS = "entra-stub";
    private static final String FEDERATED_TOKEN = "federated-token-value";
    private static final String JWT_BEARER_ASSERTION =
            "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";

    private final String token = UUID.randomUUID().toString();
    private final char[] keyStoreSecret = UUID.randomUUID().toString().toCharArray();

    private WireMockServer server;
    private Path keyStoreFile;
    private Path federatedTokenFile;

    public void start() {
        try {
            KeyPair keyPair = CertificateUtils.generateKeyPair();
            X509Certificate certificate = CertificateUtils.generateSelfSignedCertificate(
                    "CN=localhost", keyPair, localhostNames());
            keyStoreFile = writeKeyStore(keyPair, certificate);
            System.setProperty(CERTIFICATE_PROPERTY,
                    Base64.getEncoder().encodeToString(certificate.getEncoded()));

            federatedTokenFile = Files.createTempFile("entra-federated-token", ".txt");
            Files.writeString(federatedTokenFile, FEDERATED_TOKEN);
            System.setProperty(TOKEN_FILE_PROPERTY, federatedTokenFile.toString());

            server = new WireMockServer(options()
                    .httpDisabled(true)
                    .dynamicHttpsPort()
                    .keystorePath(keyStoreFile.toString())
                    .keystoreType(KEY_STORE_TYPE)
                    .keystorePassword(new String(keyStoreSecret))
                    .keyManagerPassword(new String(keyStoreSecret)));
            server.start();
            server.stubFor(post(urlMatching(TOKEN_PATH)).willReturn(okJson(
                    "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"ext_expires_in\":3600,"
                            + "\"access_token\":\"" + token + "\"}")));
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Failed to start the stub token endpoint", e);
        }
    }

    public String authorityHost() {
        return "https://localhost:" + requireStarted().httpsPort();
    }

    public String issuedToken() {
        return token;
    }

    public int tokenRequestCount() {
        return requireStarted().findAll(postRequestedFor(urlMatching(TOKEN_PATH))).size();
    }

    /**
     * Asserts the issued token was obtained by presenting the federated token as a JWT-bearer
     * client assertion, not by some other grant that would also have hit the token endpoint.
     */
    public void verifyFederatedTokenExchanged() {
        requireStarted().verify(postRequestedFor(urlMatching(TOKEN_PATH))
                .withRequestBody(containing("client_assertion=" + FEDERATED_TOKEN))
                .withRequestBody(containing("client_assertion_type=" + JWT_BEARER_ASSERTION)));
    }

    @Override
    public void close() {
        try {
            if (server != null) {
                server.stop();
            }
        } finally {
            System.clearProperty(CERTIFICATE_PROPERTY);
            System.clearProperty(TOKEN_FILE_PROPERTY);
            deleteQuietly(keyStoreFile);
            deleteQuietly(federatedTokenFile);
        }
    }

    private WireMockServer requireStarted() {
        if (server == null) {
            throw new IllegalStateException("The stub token endpoint is not running: call start() first");
        }
        return server;
    }

    private static GeneralNames localhostNames() {
        return new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")});
    }

    private static void deleteQuietly(Path file) {
        if (file == null) {
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            // Housekeeping only: leave it to the JVM rather than failing an otherwise passing test.
            file.toFile().deleteOnExit();
        }
    }

    private static String requiredProperty(String name) {
        String value = System.getProperty(name);
        if (value == null) {
            throw new IllegalStateException("System property " + name + " is not set: "
                    + "MockEntraTokenIssuer.start() must run before a credential is resolved");
        }
        return value;
    }

    private Path writeKeyStore(KeyPair keyPair, X509Certificate certificate)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        keyStore.load(null, null);
        keyStore.setKeyEntry(CERTIFICATE_ALIAS, keyPair.getPrivate(), keyStoreSecret,
                new X509Certificate[]{certificate});
        Path file = Files.createTempFile("entra-stub", ".p12");
        try (OutputStream out = Files.newOutputStream(file)) {
            keyStore.store(out, keyStoreSecret);
        }
        return file;
    }

    /**
     * Supplies the PostgreSQL authentication plugin with a workload identity credential aimed at
     * the stub, named in the {@code azure.tokenCredentialProviderClassName} connection property.
     * It resolves the same options the shipped provider does, differing only in the token file it
     * reads, instance discovery being off, and a transport that trusts the stub's certificate.
     */
    public static final class StubTokenCredentialProvider implements TokenCredentialProvider {

        private final TokenCredentialProviderOptions options;

        public StubTokenCredentialProvider(TokenCredentialProviderOptions options) {
            this.options = options;
        }

        @Override
        public TokenCredential get() {
            return get(options);
        }

        @Override
        public TokenCredential get(TokenCredentialProviderOptions credentialOptions) {
            if (credentialOptions.isManagedIdentityEnabled()) {
                throw new IllegalStateException("azure.managedIdentityEnabled is true, so the shipped "
                        + "DefaultTokenCredentialProvider would build a ManagedIdentityCredential and "
                        + "never exchange a federated token; this substitute no longer stands in for "
                        + "the branch production takes");
            }
            return new WorkloadIdentityCredentialBuilder()
                    .authorityHost(credentialOptions.getAuthorityHost())
                    .clientId(credentialOptions.getClientId())
                    .tenantId(credentialOptions.getTenantId())
                    .tokenFilePath(requiredProperty(TOKEN_FILE_PROPERTY))
                    .disableInstanceDiscovery()
                    .httpClient(trustingHttpClient())
                    .build();
        }

        private static HttpClient trustingHttpClient() {
            try {
                Certificate certificate = CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(Base64.getDecoder()
                                .decode(requiredProperty(CERTIFICATE_PROPERTY))));
                KeyStore trustStore = KeyStore.getInstance(KEY_STORE_TYPE);
                trustStore.load(null, null);
                trustStore.setCertificateEntry(CERTIFICATE_ALIAS, certificate);

                TrustManagerFactory trustManagers =
                        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagers.init(trustStore);
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagers.getTrustManagers(), null);

                return new JdkHttpClientBuilder(
                        java.net.http.HttpClient.newBuilder().sslContext(sslContext)).build();
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("Failed to trust the stub token endpoint", e);
            }
        }
    }
}
