package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record CreateCredentialDto(

        @Schema(
                description = """
                        A name of the crypto token which will hold the generated private key for the credential.
                        """,
                example = "EntrustSAMCryptoToken",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String cryptoTokenName,

        @Schema(
                description = """
                        A name of the credential profile to use when generating the certificate.
                        """,
                example = "long-term",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialProfileName,

        @Schema(
                description = """
                        Identifier of the user the credential will belong to.
                        This identifier must be unique within the identity provider.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String userId,

        @Schema(
                description = """
                        Identifier qualifying the type of signature this credential is suitable for.
                        See the list of supported signature qualifiers in the CSC API specification.
                        """,
                example = "eu_eidas_qes",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String signatureQualifier,

        @Schema(
                description = """
                        Maximum number of signatures that can be created with this credential with a single
                        authorization request.
                        """,
                example = "2",
                defaultValue = "1",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Integer numberOfSignaturesPerAuthorization,

        @Schema(
                description = """
                        Specifies if the credential should generate a signature activation data (SAD) or an access token
                        with scope `credential` that contains a link to the hash to-be-signed:
                        - `1`: The hash to-be-signed is not linked to the signature activation data.
                        - `2`: The hash to-be-signed is linked to the signature activation data.
                        """,
                example = "1",
                defaultValue = "1",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String scal,

        @Schema(
                description = """
                        A subject distinguished name (DN) of the credential for the certificate.
                        The format of the DN must be according to the X.500 standard. This field should contain
                        comma-separated key-value pairs, where the key is the type of the DN and the value is the
                        value of the DN.
                        """,
                example = "CN=John Doe,OU=IT,O=Company",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String dn,

        @Schema(
                description = """
                        A subject alternative name (SAN) of the credential for the certificate.
                        The format of the SAN must be according to the X.500 standard. This field should contain
                        comma-separated key-value pairs, where the key is the type of the SAN and the value is the
                        value of the SAN.
                        """,
                example = "rfc822Name=your.name@email.com",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String san,

        @Schema(
                description = """
                        A free form description of the credential in the lang language. The maximum size of the string
                        is 255 characters.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String description,

        @Schema(
                description = """
                        Indicates whether to use a pre-generated key from the key pool.
                        If set to true, a pre-generated key will be used; if false or not provided, a new key will be generated.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Boolean usePreGeneratedKey,

        @Schema(
                description = """
                        Specifies which certificates from the certificate chain SHALL be returned in
                        certs/certificates.
                        - “none”: No certificate SHALL be returned.
                        - “single”: Only the end entity certificate SHALL be returned.
                        - “chain”: The full certificate chain SHALL be returned.
                        The default value is “single”, so if the parameter is omitted then the method will
                        only return the end entity certificate(s).
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String certificates
) {
}
