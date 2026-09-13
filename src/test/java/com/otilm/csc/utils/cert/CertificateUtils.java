package com.otilm.csc.utils.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class CertificateUtils {

    /**
     * Generates an RSA key pair for use in certificate generation.
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }

    /**
     * Generates a self-signed X.509 certificate with the given subject and issuer DNs.
     *
     * @param subjectDn the subject distinguished name
     * @return a self signed X509Certificate
     */
    public static X509Certificate generateSelfSignedCertificate(String subjectDn) {
        return generateSelfSignedCertificate(subjectDn, generateKeyPair(), null);
    }

    /**
     * Generates a self-signed X.509 certificate for an existing key pair, optionally carrying a
     * subject alternative name. Callers that need to serve TLS with the certificate need both:
     * the private key, to configure the listener, and the SAN, because a hostname verifier only
     * consults the common name when no SAN is present.
     *
     * @param subjectDn              the subject and issuer distinguished name
     * @param keyPair                the key pair to certify and sign with
     * @param subjectAlternativeName the subject alternative name, or {@code null} to omit it
     * @return a self signed X509Certificate
     */
    public static X509Certificate generateSelfSignedCertificate(String subjectDn, KeyPair keyPair,
                                                                GeneralNames subjectAlternativeName) {
        try {
            X500Name subject = new X500Name(subjectDn);
            X500Name issuer = new X500Name(subjectDn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS);
            Instant notAfter = Instant.now().plus(365, ChronoUnit.DAYS);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serial,
                    Date.from(notBefore), Date.from(notAfter),
                    subject, keyPair.getPublic()
            );

            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            if (subjectAlternativeName != null) {
                certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeName);
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(signer);

            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate test certificate", e);
        }
    }

    /**
     * Generates a self-signed CA certificate (basicConstraints CA=true).
     *
     * @param dn      the subject/issuer distinguished name
     * @param keyPair the key pair for the CA
     * @return a self-signed CA X509Certificate
     */
    public static X509Certificate generateCaCertificate(String dn, KeyPair keyPair) {
        try {
            X500Name name = new X500Name(dn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS);
            Instant notAfter = Instant.now().plus(3650, ChronoUnit.DAYS);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    name, serial,
                    Date.from(notBefore), Date.from(notAfter),
                    name, keyPair.getPublic()
            );

            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(signer);

            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CA certificate", e);
        }
    }

    /**
     * Generates an end-entity certificate signed by the given CA key pair.
     *
     * @param subjectDn the subject distinguished name
     * @param caKeyPair the CA's key pair (used for signing)
     * @param caCert    the CA certificate (used as issuer)
     * @return an X509Certificate signed by the CA
     */
    public static X509Certificate generateSignedCertificate(String subjectDn, KeyPair caKeyPair, X509Certificate caCert) {
        try {
            KeyPair subjectKeyPair = generateKeyPair();
            X500Name subject = new X500Name(subjectDn);
            X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() + 1);
            Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS);
            Instant notAfter = Instant.now().plus(365, ChronoUnit.DAYS);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serial,
                    Date.from(notBefore), Date.from(notAfter),
                    subject, subjectKeyPair.getPublic()
            );

            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(caKeyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(signer);

            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate signed certificate", e);
        }
    }

    /**
     * Generates a self-signed end-entity certificate that is already expired.
     */
    public static X509Certificate generateExpiredCertificate(String subjectDn) {
        try {
            KeyPair keyPair = generateKeyPair();
            X500Name name = new X500Name(subjectDn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Instant notBefore = Instant.now().minus(2, ChronoUnit.DAYS);
            Instant notAfter = Instant.now().minus(1, ChronoUnit.DAYS);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    name, serial,
                    Date.from(notBefore), Date.from(notAfter),
                    name, keyPair.getPublic()
            );
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate expired certificate", e);
        }
    }

    /**
     * Generates a self-signed end-entity certificate that is not yet valid.
     */
    public static X509Certificate generateNotYetValidCertificate(String subjectDn) {
        try {
            KeyPair keyPair = generateKeyPair();
            X500Name name = new X500Name(subjectDn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Instant notBefore = Instant.now().plus(1, ChronoUnit.DAYS);
            Instant notAfter = Instant.now().plus(365, ChronoUnit.DAYS);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    name, serial,
                    Date.from(notBefore), Date.from(notAfter),
                    name, keyPair.getPublic()
            );
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate not-yet-valid certificate", e);
        }
    }

    public static X500Name getIssuerX500Name(X509Certificate cert) {
        try {
            return X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse issuer X500Name", e);
        }
    }

    public static X500Name getSubjectX500Name(X509Certificate cert) {
        try {
            return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse subject X500Name", e);
        }
    }

    public static PublicKey extractPublicKeyFromCertificateString(String pemCertificate) throws CertificateException {
        String base64Der = pemCertificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        byte[] derCrt = Base64.getDecoder().decode(base64Der);

        // Create a CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Generate the X509Certificate object
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(derCrt));

        // Extract the public key from the certificate
        return certificate.getPublicKey();
    }
}