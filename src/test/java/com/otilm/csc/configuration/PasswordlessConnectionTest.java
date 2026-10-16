package com.otilm.csc.configuration;

import com.otilm.csc.utils.db.MockEntraTokenIssuer;
import com.otilm.csc.utils.db.PasswordlessJdbcUrl;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Carries the passwordless path as far as the database: the authentication plugin resolves its
 * {@code azure.*} options, MSAL exchanges a federated token at a stubbed issuer, and PostgreSQL
 * accepts the returned token as the password. The container's password is the token the stub
 * issues, so the query succeeds only if the token travelled that route.
 *
 * <p>Substituted here, and therefore not covered:
 * <ul>
 *   <li>credential selection: production leaves {@code azure.tokenCredentialProviderClassName}
 *       unset, so {@code DefaultTokenCredentialProvider} builds a {@code DefaultAzureCredential}
 *       that reaches workload identity through environment variables.</li>
 *   <li>transport discovery: the substitute injects an {@code HttpClient} that trusts the stub's
 *       certificate, bypassing the {@code ServiceLoader} lookup of the JDK transport.</li>
 *   <li>instance discovery: disabled, because MSAL would otherwise resolve the authority against
 *       the real {@code login.microsoftonline.com}.</li>
 *   <li>the connection's own TLS leg: {@code sslmode} is removed for a plain-TCP container.</li>
 * </ul>
 */
@Testcontainers
class PasswordlessConnectionTest {

    private static final String CLIENT_ID = "00000000-0000-0000-0000-000000000000";
    private static final String TENANT_ID = "00000000-0000-0000-0000-000000000001";

    @Container
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16-alpine");

    @Test
    void connectsUsingATokenSuppliedByTheAuthenticationPlugin() throws Exception {
        try (MockEntraTokenIssuer issuer = new MockEntraTokenIssuer()) {
            issuer.start();
            resetDatabasePasswordTo(issuer.issuedToken());

            try (Connection connection = DriverManager.getConnection(
                         postgres.getJdbcUrl(), passwordlessProperties(issuer));
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT 1")) {
                assertThat(result.next()).isTrue();
                assertThat(result.getInt(1)).isEqualTo(1);
            }

            assertThat(issuer.tokenRequestCount()).isPositive();
            issuer.verifyFederatedTokenExchanged();
        }
    }

    private Properties passwordlessProperties(MockEntraTokenIssuer issuer) {
        Properties properties = PasswordlessJdbcUrl.enhancedConnectionProperties();
        properties.setProperty("user", postgres.getUsername());
        properties.remove("sslmode");
        properties.setProperty("azure.authorityHost", issuer.authorityHost());
        // The enhanced URL carries neither: production resolves them from the environment.
        properties.setProperty("azure.clientId", CLIENT_ID);
        properties.setProperty("azure.tenantId", TENANT_ID);
        properties.setProperty("azure.tokenCredentialProviderClassName",
                MockEntraTokenIssuer.StubTokenCredentialProvider.class.getName());
        return properties;
    }

    // ALTER USER takes no bind parameter for the password, so the token is inlined in the statement.
    private void resetDatabasePasswordTo(String token) throws Exception {
        try (Connection admin = DriverManager.getConnection(
                     postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
             Statement statement = admin.createStatement()) {
            statement.execute("ALTER USER \"" + postgres.getUsername() + "\" WITH PASSWORD '" + token + "'");
        }
    }
}
