package com.czertainly.csc.service.credentials;

import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.Success;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.components.CertificateValidityDecider;
import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.crypto.AlgorithmHelper;
import com.czertainly.csc.crypto.CertificateParser;
import com.czertainly.csc.crypto.PasswordGenerator;
import com.czertainly.csc.model.CertificateRevocationReason;
import com.czertainly.csc.model.csc.*;
import com.czertainly.csc.model.csc.requests.*;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.repository.CredentialsRepository;
import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import com.czertainly.csc.service.keys.LongTermKeysService;
import com.czertainly.csc.service.keys.SigningKey;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfile;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.ZoneId;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class CredentialsService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialsService.class);

    private final PasswordGenerator passwordGenerator;
    private final EjbcaClient ejbcaClient;
    private final SignserverClient signserverClient;
    private final CredentialsRepository credentialsRepository;
    private final WorkerRepository workerRepository;
    private final CertificateParser certificateParser;

    private final AlgorithmHelper algorithmHelper;
    private final DateConverter dateConverter;
    private final CertificateValidityDecider certificateValidityDecider;
    private final CredentialProfileRepository credentialProfileRepository;
    private final LongTermKeysService longTermKeysService;

    public CredentialsService(PasswordGenerator passwordGenerator, EjbcaClient ejbcaClient,
                              SignserverClient signserverClient, CredentialsRepository credentialsRepository,
                              WorkerRepository workerRepository, CertificateParser certificateParser,
                              AlgorithmHelper algorithmHelper, DateConverter dateConverter,
                              CertificateValidityDecider certificateValidityDecider,
                              CredentialProfileRepository credentialProfileRepository,
                              LongTermKeysService longTermKeysService
    ) {
        this.passwordGenerator = passwordGenerator;
        this.ejbcaClient = ejbcaClient;
        this.signserverClient = signserverClient;
        this.credentialsRepository = credentialsRepository;
        this.workerRepository = workerRepository;
        this.certificateParser = certificateParser;
        this.algorithmHelper = algorithmHelper;
        this.dateConverter = dateConverter;
        this.certificateValidityDecider = certificateValidityDecider;
        this.credentialProfileRepository = credentialProfileRepository;
        this.longTermKeysService = longTermKeysService;
    }

    public Result<Credential, TextError> createCredential(
            CreateCredentialRequest createCredentialRequest
    ) {
        logger.debug("Creating new credential for user '{}'.", createCredentialRequest.userId());
        logger.trace(createCredentialRequest.toString());

        var getCredentialProfileResult = credentialProfileRepository
                .getCredentialProfile(createCredentialRequest.credentialProfileName());
        if (getCredentialProfileResult instanceof Error(var err)) return Result.error(err);
        CredentialProfile credentialProfile = getCredentialProfileResult.unwrap();
        logger.info("Will use credential profile {} to create a credential.", credentialProfile.getName());
        logger.debug(credentialProfile.toString());

        String uniqueUserId = createUniqueUserId(createCredentialRequest.userId());
        String keyAlias = getUniqueKeyAlias(uniqueUserId);

        var geCryptoTokenResult = workerRepository.getCryptoToken(createCredentialRequest.cryptoTokenName())
                                                  .mapError(e -> e.extend(
                                                          "Crypto token configuration could not be retrieved."));
        if (geCryptoTokenResult instanceof Error(var err)) return Result.error(err);
        CryptoToken token = geCryptoTokenResult.unwrap();

        var generateKeyResult = getPregeneratedOrGenerateKey(token, keyAlias, credentialProfile, createCredentialRequest.usePreGeneratedKey());
        if (generateKeyResult instanceof Error(var err)) return Result.error(err);
        String generatedKeyAlias = generateKeyResult.unwrap();

        var generateCSRResult = signserverClient
                .generateCSR(
                        token, generatedKeyAlias,
                        createCredentialRequest.dn(),
                        credentialProfile.getCsrSignatureAlgorithm()
                )
                .mapError(e -> e.extend("CSR couldn't be generated."))
                .ifError(() -> rollbackKeyCreation(token, generatedKeyAlias));
        if (generateCSRResult instanceof Error(var err)) return Result.error(err);
        byte[] csr = generateCSRResult.unwrap();

        var createEndEntityResult = createEndEntity(
                uniqueUserId, createCredentialRequest.dn(),
                createCredentialRequest.san(),
                credentialProfile
        )
                .mapError(e -> e.extend("End entity couldn't be created."))
                .ifError(() -> rollbackKeyCreation(token, generatedKeyAlias));
        if (createEndEntityResult instanceof Error(var err)) return Result.error(err);
        EndEntity endEntity = createEndEntityResult.unwrap();

        var signCertificateResult = ejbcaClient
                .signCertificateRequest(endEntity, credentialProfile, csr)
                .mapError(e -> e.extend("Certificate signing request couldn't be signed."))
                .ifError(() -> rollbackKeyCreation(token, generatedKeyAlias));

        if (signCertificateResult instanceof Error(var err)) return Result.error(err);
        byte[] encodedCertificates = signCertificateResult.unwrap();

        var extractCertificateResult = certificateParser
                .getEndCertificateFromPkcs7Chain(encodedCertificates)
                .mapError(e -> e.extend(
                        "End certificate couldn't be extracted from PKCS7 chain."))
                .ifError(() -> rollbackKeyCreation(token,
                                                   generatedKeyAlias
                ));

        if (extractCertificateResult instanceof Error(var err)) return Result.error(err);
        X509CertificateHolder endCertificate = extractCertificateResult.unwrap();

        var parseChainResult = certificateParser.parsePkcs7ChainToList(encodedCertificates)
                .mapError(e -> e.extend("Failed to parse PKCS7 chain."))
                .ifError(() -> rollbackKeyCreation(token, generatedKeyAlias));
        if (parseChainResult instanceof Error(var err)) return Result.error(err);
        List<byte[]> parsedChain = parseChainResult.unwrap();

        var importChainResult = signserverClient
                .importCertificateChain(
                        token, generatedKeyAlias,
                        parsedChain
                )
                .mapError(e -> e.extend("Certificate chain couldn't be imported to the crypto token."))
                .ifError(() -> rollbackKeyCreation(token, generatedKeyAlias))
                .ifError(() -> revokeCertificate(endCertificate));
        if (importChainResult instanceof Error(var err)) return Result.error(err);

        return saveNewCredential(createCredentialRequest,
                                 generatedKeyAlias, token,
                                 endEntity,
                                 endCertificate
        )
                .flatMap(credentialMetadataEntity -> getCredential(credentialMetadataEntity, createCredentialRequest.certificateReturnType()))
                .mapError(e -> e.extend("A newly created credential couldn't be saved in the database."))
                .consume(credentialId -> logger.info("Credential {} was generated for user {} ", credentialId,
                                                     createCredentialRequest.userId()
                ))
                .ifError(() -> rollbackKeyCreation(token, generatedKeyAlias))
                .ifError(() -> revokeCertificate(endCertificate));
    }

    public Result<Void, TextError> deleteCredential(RemoveCredentialRequest removeCredentialRequest) {
        return deleteCredential(removeCredentialRequest.credentialID(), removeCredentialRequest.revocationReason());
    }

    private Result<Void, TextError> deleteCredential(UUID credentialId,
                                                     CertificateRevocationReason revocationReason
    ) {
        logger.info("Deleting credential with ID '{}'.", credentialId);

        return getCredentialMetadataEntity(credentialId, null)
                .mapError(e -> e.extend("Failed to obtain credential metadata."))
                .flatMap(credentialMetadata -> {
                    if (revocationReason == null) {
                        return Result.success(credentialMetadata);
                    }

                    // Revoke certificate if revocationReason is provided
                    return getCredential(credentialMetadata, CertificateReturnType.END_CERTIFICATE)
                            .map(credential -> {
                                revokeCertificate(credential.cert().serialNumber(), credential.cert().issuerDN(),
                                                  revocationReason
                                );
                                return credentialMetadata;
                            });
                })
                .flatMap(credentialMetadata ->
                                 workerRepository.getCryptoToken(credentialMetadata.getCryptoTokenName())
                                                 .flatMap(token ->
                                                                  signserverClient.removeKeyOkIfNotExists(token.id(),
                                                                                                          credentialMetadata.getKeyAlias()
                                                                  )
                                                 )
                )
                .flatMap(v -> {
                    try {
                        credentialsRepository.deleteById(credentialId);
                        return Result.emptySuccess();
                    } catch (Exception e) {
                        logger.error("Failed to delete credential '{}'.", credentialId, e);
                        return Result.error(TextError.of("Failed to delete credential '%s'.", credentialId));
                    }
                })
                .ifSuccess(() -> logger.info("Credential '{}' was deleted.", credentialId));
    }

    public Result<Void, TextError> disableCredential(UUID credentialId) {
        return updateCredentialStatus(credentialId, true);
    }

    public Result<Void, TextError> enableCredential(UUID credentialId) {
        return updateCredentialStatus(credentialId, false);
    }

    public Result<Void, TextError> rekey(RekeyCredentialRequest request) {
        logger.debug("Re keying credential '{}'.", request.credentialID());
        logger.trace(request.toString());

        var getCredentialMetadataResult = getCredentialMetadataEntity(request.credentialID(), null);

        if (getCredentialMetadataResult instanceof Error(var err)) return Result.error(err);
        CredentialMetadataEntity currentCredentialMetadata = getCredentialMetadataResult.unwrap();

        RekeyCredentialRequest mergedRequest = mergerRekeyRequestWithCurrentSettings(
                request, currentCredentialMetadata
        );

        var getCredentialProfileResult = credentialProfileRepository
                .getCredentialProfile(mergedRequest.credentialProfileName());
        if (getCredentialProfileResult instanceof Error(var err)) return Result.error(err);
        CredentialProfile credentialProfile = getCredentialProfileResult.unwrap();
        logger.info("Will use credential profile {} to rekey a credential.", credentialProfile.getName());
        logger.debug(credentialProfile.toString());

        var getCurrentCryptoTokenResult = workerRepository.getCryptoToken(
                currentCredentialMetadata.getCryptoTokenName()
        );
        if (getCurrentCryptoTokenResult instanceof Error(var err)) return Result.error(err);
        CryptoToken currentCryptoToken = getCurrentCryptoTokenResult.unwrap();

        var getCurrentKeyResult = signserverClient
                .getCryptoTokenKey(currentCryptoToken, currentCredentialMetadata.getKeyAlias());
        if (getCurrentKeyResult instanceof Error(var err)) return Result.error(err);
        CryptoTokenKey currentKey = getCurrentKeyResult.unwrap();


        var getDestinationCryptoTokenResult = workerRepository
                .getCryptoToken(mergedRequest.cryptoTokenName())
                .mapError(
                        e -> e.extend(
                                "Failed to get destination crypto token when rekeying credential '%s'.",
                                mergedRequest.credentialID()
                        )
                );
        if (getDestinationCryptoTokenResult instanceof Error(var err)) return Result.error(err);
        CryptoToken destinationCryptoToken = getDestinationCryptoTokenResult.unwrap();

        String newKeyAlias = getUniqueKeyAlias(currentCredentialMetadata.getEndEntityName());
        var newKeyGenerationResult = signserverClient
                .generateKey(destinationCryptoToken, newKeyAlias,
                             credentialProfile.getKeyAlgorithm(),
                             credentialProfile.getKeySpecification()
                )
                .mapError(e -> e.extend(
                        "Failed to generate a new key when rekeying credential '%s'.",
                        mergedRequest.credentialID()
                ));
        if (newKeyGenerationResult instanceof Error(var err)) return Result.error(err);
        newKeyAlias = newKeyGenerationResult.unwrap();

        String finalNewKeyAlias = newKeyAlias;
        var getEndEntityResult = ejbcaClient
                .getEndEntity(currentCredentialMetadata.getEndEntityName())
                .mapError(e -> e.extend(
                                  "Failed to get end entity when rekeying credential '%s'.",
                                  mergedRequest.credentialID()
                          )
                ).consumeError(e -> rollbackKeyCreation(destinationCryptoToken, finalNewKeyAlias));
        if (getEndEntityResult instanceof Error(var err)) return Result.error(err);
        EndEntity endEntity = getEndEntityResult.unwrap();

        var genarateCsrResult = signserverClient
                .generateCSR(destinationCryptoToken,
                             newKeyAlias, endEntity.subjectDN(),
                             credentialProfile.getCsrSignatureAlgorithm()
                )
                .mapError(e -> e.extend("Failed to generate CSR when rekeying credential '%s'",
                                        mergedRequest.credentialID()
                ))
                .consumeError(e -> rollbackKeyCreation(destinationCryptoToken, finalNewKeyAlias));
        if (genarateCsrResult instanceof Error(var err)) return Result.error(err);
        byte[] csr = genarateCsrResult.unwrap();

        var signCsrResult = ejbcaClient
                .signCertificateRequest(endEntity, credentialProfile, csr)
                .mapError(e -> e.extend("Failed to sign CSR when rekeying credential '%s'",
                                        mergedRequest.credentialID()
                          )
                )
                .consumeError(e -> rollbackKeyCreation(destinationCryptoToken, finalNewKeyAlias));
        if (signCsrResult instanceof Error(var err)) return Result.error(err);
        byte[] certificateChain = signCsrResult.unwrap();

        var extractCertificateResult = certificateParser
                .getEndCertificateFromPkcs7Chain(certificateChain)
                .mapError(e -> e.extend(
                        "End certificate couldn't be extracted from PKCS7 chain."))
                .ifError(() -> rollbackKeyCreation(destinationCryptoToken, finalNewKeyAlias));

        if (extractCertificateResult instanceof Error(var err)) return Result.error(err);
        X509CertificateHolder endCertificate = extractCertificateResult.unwrap();

        var parseChainResult = certificateParser.parsePkcs7ChainToList(certificateChain)
                .mapError(e -> e.extend("Failed to parse PKCS7 chain."))
                .ifError(() -> rollbackKeyCreation(destinationCryptoToken, finalNewKeyAlias));
        if (parseChainResult instanceof Error(var err)) return Result.error(err);
        List<byte[]> parsedChain = parseChainResult.unwrap();

        var importChainResult = signserverClient
                .importCertificateChain(
                        destinationCryptoToken, finalNewKeyAlias,
                        parsedChain
                )
                .mapError(e -> e.extend(
                        "Failed to import certificate chain for key '%s'",
                        finalNewKeyAlias
                ));
        if (importChainResult instanceof Error(var err)) return Result.error(err);

        var updateCredentialMetadataresult = updateCredentialMetadataWithNewKeyAndCertificate(
                currentCredentialMetadata, endCertificate, finalNewKeyAlias, destinationCryptoToken,
                credentialProfile.getName()
        )
                .mapError(e -> e.extend("Failed to update credential metadata with new key and certificate."))
                .ifError(() -> rollbackKeyCreation(destinationCryptoToken, finalNewKeyAlias))
                .ifError(() -> revokeCertificate(endCertificate));

        if (updateCredentialMetadataresult instanceof Error(var err)) return Result.error(err);

        signserverClient.removeKey(currentCryptoToken.id(), currentKey.keyAlias())
                        .consumeError(e -> logger.error(
                                "Failed to remove old key '{}' from crypto token {}({}) while performing rekey. " +
                                        "New key and certificate were successfully saved and credential is ready to use." +
                                        " Please remove the old key manually.",
                                currentKey.keyAlias(), currentCryptoToken.name(),
                                currentCryptoToken.id()
                        ));
        return Result.success(null);
    }


    public Result<Credential, TextError> getCredential(CredentialInfoRequest request) {
        logger.debug("Retrieving credential '{}'.", request.credentialID());
        logger.trace(request.toString());
        return getCredentialMetadataEntity(request.credentialID(), request.userID())
                .mapError(e -> e.extend("Failed to retrieve credential metadata."))
                .flatMap(metadata -> getCredential(metadata, request.certificateReturnType()));
    }

    public Result<List<Credential>, TextError> listUserCredentials(ListCredentialsRequest request) {
        try {
            List<CredentialMetadataEntity> credentialMetadata = credentialsRepository.findByUserId(request.userID());
            List<Credential> credentials = credentialMetadata
                    .stream()
                    .map(credential -> getCredential(credential, request.certificateReturnType()))
                    .filter(result -> {
                                if (result instanceof Error(var e)) {
                                    e = e.extend("Failed to load credential details while listing credentials " +
                                                         "for user %s. Credential will not be included in the list.",
                                                 request.userID()
                                    );
                                    logger.warn(e.toString());
                                    return false;
                                } else {
                                    return true;
                                }
                            }
                    )
                    .takeWhile(it -> it instanceof Success)
                    .map(Result::unwrap)
                    .toList();
            return Result.success(credentials);
        } catch (Exception e) {
            logger.error("Failed to retrieve credentials for user '{}'.", request.userID(), e);
            return Result.error(TextError.of(e));
        }
    }

    private Result<String, TextError> getPregeneratedOrGenerateKey(CryptoToken cryptoToken, String keyAlias,
                                                                   CredentialProfile credentialProfile,
                                                                   boolean usePreGeneratedKey
    ) {
        if (usePreGeneratedKey) {
            logger.debug("Will use pre-generated long-term key for the credential.");
            return longTermKeysService.acquireKey(cryptoToken, credentialProfile.getKeyAlgorithm())
                    .map(SigningKey::keyAlias);
        } else {
            logger.debug("Will generate a new long-term key for the credential.");
            return signserverClient
                    .generateKey(
                            cryptoToken, keyAlias,
                            credentialProfile.getKeyAlgorithm(),
                            credentialProfile.getKeySpecification()
                    )
                    .mapError(e -> e.extend(
                            "Key couldn't be generated on SignServer CryptoToken %s(%s).",
                            cryptoToken.name(), cryptoToken.id()
                    ));
        }
    }

    private Result<Void, TextError> updateCredentialStatus(UUID credentialId, boolean disabled) {
        logger.debug("Updating credential '{}', setting disabled={}.", credentialId, disabled);
        return getCredentialMetadataEntity(credentialId, null)
                .consume(metadata -> metadata.setDisabled(disabled))
                .flatMap(metadata -> {
                    try {
                        credentialsRepository.save(metadata);
                        return Result.emptySuccess();
                    } catch (Exception e) {
                        return Result.error(TextError.of(e));
                    }
                })
                .ifSuccess(
                        () -> logger.info("The property 'disabled' of Credential '{}' was set to '{}'", credentialId,
                                          disabled
                        )
                );

    }

    public Result<CredentialMetadata, TextError> getCredentialMetadata(UUID credentialId, String userId) {
        return getCredentialMetadataEntity(credentialId, userId)
                .map(metadata -> new CredentialMetadata(
                        metadata.getId(),
                        metadata.getUserId(),
                        metadata.getKeyAlias(),
                        metadata.getCredentialProfile(),
                        Optional.ofNullable(metadata.getSignatureQualifier()),
                        metadata.getMultisign(),
                        Optional.ofNullable(metadata.getScal()),
                        metadata.getCryptoTokenName(),
                        metadata.isDisabled()
                ));
    }

    private Result<CredentialMetadataEntity, TextError> getCredentialMetadataEntity(UUID credentialId, String userId) {
        try {
            if (userId == null) {
                return credentialsRepository.findById(credentialId)
                                            .<Result<CredentialMetadataEntity, TextError>>map(Result::success)
                                            .orElseGet(() -> Result.error(
                                                    TextError.of("No credential with id '%s' found in database.",
                                                                 credentialId
                                                    )));
            } else {
                return credentialsRepository.findByIdAndUserId(credentialId, userId)
                                            .<Result<CredentialMetadataEntity, TextError>>map(Result::success)
                                            .orElseGet(() -> Result.error(
                                                    TextError.of(
                                                            "No credential with id '%s' belonging to the user '%s' found in database.",
                                                            credentialId,
                                                            userId
                                                    )));
            }
        } catch (Exception e) {
            logger.debug("Failed to retrieve credential '{}' from database.", credentialId, e);
            return Result.error(TextError.of(e));
        }
    }

    private Result<Credential, TextError> getCredential(CredentialMetadataEntity credentialMetadata,
                                                        CertificateReturnType certificateReturnType
    ) {
        return workerRepository
                .getCryptoToken(credentialMetadata.getCryptoTokenName())
                .mapError(e -> e.extend("Failed to get crypto token for credential '%s'.", credentialMetadata.getId()))
                .flatMap(cryptoToken ->
                                 signserverClient
                                         .queryCryptoTokenKeys(
                                                 cryptoToken, true, 0, 2,
                                                 credentialMetadata.getKeyAlias()
                                         )
                                         .mapError(e -> e.extend(
                                                 "Failed to query keys for credential '%s' in SignServer CryptoToken '%s'(%d).",
                                                 credentialMetadata.getId(), cryptoToken.name(), cryptoToken.id()
                                         ))
                                         .validate(List::isEmpty,
                                                   TextError.of(
                                                           "Key '%s' belonging to credential '%s' not found in SignServer CryptoToken '%s'(%d).",
                                                           credentialMetadata.getKeyAlias(),
                                                           credentialMetadata.getId(),
                                                           cryptoToken.name(),
                                                           cryptoToken.id()
                                                   )
                                         )
                                         .validate(keys -> keys.size() > 1,
                                                   TextError.of(
                                                           "Multiple keys '%s' belonging to credential '%s' found in SignServer CryptoToken '%s'(%d).",
                                                           credentialMetadata.getKeyAlias(),
                                                           credentialMetadata.getId(),
                                                           cryptoToken.name(),
                                                           cryptoToken.id()
                                                   )
                                         )
                                         .map(List::getFirst)
                                         .flatMap(key ->
                                                          constructCredential(
                                                                  key, credentialMetadata,
                                                                  certificateReturnType
                                                          )
                                         )
                );
    }

    private Result<Credential, TextError> constructCredential(
            CryptoTokenKey key,
            CredentialMetadataEntity credentialMetadata,
            CertificateReturnType certificateReturnType
    ) {
        return extractKeyInfo(key, credentialMetadata)
                .flatMap(keyInfo -> certificateParser
                        .parseDerEncodedCertificate(key.chain().getFirst())
                        .flatMap(endCertificate -> {
                            var decideStatusResult = certificateValidityDecider.decideStatus(endCertificate)
                                                                               .mapError(e -> e.extend(
                                                                                       "Failed to decide the status of the certificate."));
                            if (decideStatusResult instanceof Error(var err)) return Result.error(err);
                            CertificateStatus certificateStatus = decideStatusResult.unwrap();

                            return getCertificatesByRequestedReturnType(certificateReturnType, key)
                                    .map(certificates -> {
                                             ZoneId utcZone = ZoneId.of("UTC");
                                             return new Credential(
                                                     credentialMetadata.getId().toString(),
                                                     credentialMetadata.getDescription(),
                                                     Optional.of(credentialMetadata.getSignatureQualifier()),
                                                     keyInfo,
                                                     new CertificateInfo(
                                                             certificateStatus,
                                                             certificates,
                                                             endCertificate.getSerialNumber().toString(16),
                                                             endCertificate.getIssuer().toString(),
                                                             endCertificate.getSubject().toString(),
                                                             dateConverter.dateToZonedDateTime(
                                                                     endCertificate.getNotBefore(),
                                                                     utcZone
                                                             ),
                                                             dateConverter.dateToZonedDateTime(
                                                                     endCertificate.getNotAfter(), utcZone)
                                                     ),
                                                     credentialMetadata.getMultisign()
                                             );
                                         }
                                    );
                        })
                )
                .flatMapError(
                        e -> Result.error(e.extend("Failed to construct credential {}.", credentialMetadata.getId())));
    }

    private Result<KeyInfo, TextError> extractKeyInfo(CryptoTokenKey key, CredentialMetadataEntity credentialMetadata) {
        KeyStatus keyStatus = credentialMetadata.isDisabled() ? KeyStatus.DISABLED : KeyStatus.ENABLED;
        final String curve;
        final Integer keyLength;
        final String keyAlgorithm;
        if (key.keyAlgorithm().equalsIgnoreCase("ECDSA") || key.keyAlgorithm().equalsIgnoreCase("EC")) {
            keyLength = null;
            curve = key.keySpecification();
            keyAlgorithm = "ECDSA";
        } else {
            curve = null;
            if (key.keyAlgorithm().equalsIgnoreCase("RSA")) {
                keyLength = Integer.parseInt(key.keySpecification());
                keyAlgorithm = "RSA";
            } else {
                return Result.error(TextError.of("Unsupported key algorithm '%s'.", key.keyAlgorithm()));
            }
        }

        var getAvailableAlgorithmsResult = workerRepository.getAvailableSignatureAlgorithmsForToken(
                credentialMetadata.getCryptoTokenName());
        if (getAvailableAlgorithmsResult instanceof Error) {
            TextError e = getAvailableAlgorithmsResult.unwrapError();
            return Result.error(e.extend("Failed to retrieve available signature algorithms for crypto token '%s'.",
                                         credentialMetadata.getCryptoTokenName()
            ));
        }
        List<String> algorithms = getAvailableAlgorithmsResult.unwrap();

        return Result.success(new KeyInfo(
                keyStatus,
                algorithms.stream()
                          .filter(algorithm -> algorithm.contains(keyAlgorithm))
                          .map(algorithmHelper::getKeyAlgorithmIdentifier)
                          .filter(Objects::nonNull)
                          .toList(),
                keyLength,
                curve
        ));
    }

    private Result<List<byte[]>, TextError> getCertificatesByRequestedReturnType(
            CertificateReturnType certificateReturnType,
            CryptoTokenKey key
    ) {
        List<byte[]> chain = key.chain();
        if (chain.isEmpty()) {
            return Result.error(TextError.of("Crypto Token Key '%s' has not certificates attached.", key.keyAlias()));
        }

        return switch (certificateReturnType) {
            case CERTIFICATE_CHAIN -> Result.success(key.chain());
            case END_CERTIFICATE -> Result.success(List.of(key.chain().getFirst()));
            case NONE -> Result.success(List.of());
        };
    }

    private Result<EndEntity, TextError> createEndEntity(String userId, String dn, String san,
                                                         CredentialProfile credentialProfile
    ) {
        var genResult = passwordGenerator.generate();
        if (genResult instanceof Error(var err)) {
            return Result.error(err.extend("Failed to generate password for end entity."));
        }
        String password = genResult.unwrap();
        EndEntity endEntity = new EndEntity(userId, password, dn, san);
        return ejbcaClient.createEndEntity(endEntity, credentialProfile);
    }

    private RekeyCredentialRequest mergerRekeyRequestWithCurrentSettings(
            RekeyCredentialRequest request,
            CredentialMetadataEntity credentialMetadata
    ) {
        String newCryptoTokenName = credentialMetadata.getCryptoTokenName();
        if (request.cryptoTokenName() != null) {
            credentialMetadata.setCryptoTokenName(request.cryptoTokenName());
        }

        var newCredentialProfileName = request.credentialProfileName() == null ? credentialMetadata.getCredentialProfile() : request.credentialProfileName();
        return new RekeyCredentialRequest(
                request.credentialID(),
                newCredentialProfileName,
                newCryptoTokenName
        );
    }

    private String createUniqueUserId(String userID) {
        String random_id = RandomStringUtils.secure().next(8, true, true);
        String uniqueUserId = String.format("%s-%s", userID, random_id);
        logger.trace("Generated new unique user id {}", uniqueUserId);
        return uniqueUserId;
    }

    private String getUniqueKeyAlias(String userId) {
        String random_id = RandomStringUtils.secure().next(8, true, true);
        String alias = String.format("%s-%s", userId, random_id);
        logger.trace("Generated new unique key alias {}", alias);
        return alias;
    }

    private Result<CredentialMetadataEntity, TextError> saveNewCredential(
            CreateCredentialRequest createCredentialRequest, String generatedKeyAlias,
            CryptoToken cryptoToken, EndEntity endEntity, X509CertificateHolder endCertificate
    ) {

        CredentialMetadataEntity credentialMetadata = new CredentialMetadataEntity();
        credentialMetadata.setId(UUID.randomUUID());
        credentialMetadata.setUserId(createCredentialRequest.userId());
        credentialMetadata.setKeyAlias(generatedKeyAlias);
        credentialMetadata.setCredentialProfile(createCredentialRequest.credentialProfileName());
        credentialMetadata.setCryptoTokenName(cryptoToken.name());
        credentialMetadata.setEndEntityName(endEntity.username());
        credentialMetadata.setCurrentCertificateSn(endCertificate.getSerialNumber().toString(16));
        credentialMetadata.setCurrentCertificateIssuer(endCertificate.getIssuer().toString());
        credentialMetadata.setSignatureQualifier(createCredentialRequest.signatureQualifier());
        credentialMetadata.setMultisign(createCredentialRequest.numberOfSignaturesPerAuthorization());
        credentialMetadata.setScal(createCredentialRequest.scal());
        credentialMetadata.setDescription(createCredentialRequest.description());
        credentialMetadata.setDisabled(false);
        try {
            logger.debug("Saving new credential '{}'.", credentialMetadata.getId());
            logger.trace(credentialMetadata.toString());
            var entity = credentialsRepository.save(credentialMetadata);
            logger.info("New credential '{}' was saved.", credentialMetadata.getId());
            return Result.success(entity);
        } catch (Exception e) {
            logger.debug("Failed to save new credential '{}'. {}", credentialMetadata.getId(), e.getMessage());
            return Result.error(TextError.of("Failed to save credential '%s'.", credentialMetadata.getId()));
        }
    }

    private Result<Void, TextError> updateCredentialMetadataWithNewKeyAndCertificate(
            CredentialMetadataEntity currentCredentialMetadata, X509CertificateHolder endCertificate,
            String finalNewKeyAlias, CryptoToken destinationCryptoToken, String credentialProfileName
    ) {
        try {
            currentCredentialMetadata.setCurrentCertificateSn(endCertificate.getSerialNumber().toString(16));
            currentCredentialMetadata.setCurrentCertificateIssuer(endCertificate.getIssuer().toString());
            currentCredentialMetadata.setKeyAlias(finalNewKeyAlias);
            currentCredentialMetadata.setCryptoTokenName(destinationCryptoToken.name());
            currentCredentialMetadata.setCredentialProfile(credentialProfileName);
            credentialsRepository.save(currentCredentialMetadata);
            return Result.emptySuccess();
        } catch (Exception e) {
            return Result.error(TextError.of(e));
        }

    }

    private void rollbackKeyCreation(CryptoToken token, String keyAlias) {
        logger.info(
                "Rollback creation of a key {} in crypto token {}({}) due to an error during credential creation.",
                keyAlias, token.name(), token.id()
        );
        signserverClient.removeKey(token.id(), keyAlias)
                        .consumeError(e -> logger.error(
                                "Failed to rollback creation of a key {} stored in crypto token {}({}). The key should be removed manually."
                                , keyAlias, token.name(), token.id()
                        ));
    }

    private void revokeCertificate(X509CertificateHolder certificate) {
        logger.info("Revoking certificate {} due to an error during credential creation.",
                    certificate.getSerialNumber()
        );
        ejbcaClient.revokeCertificate(certificate.getSerialNumber().toString(16), certificate.getIssuer().toString(),
                                      CertificateRevocationReason.UNSPECIFIED
                   )
                   .consumeError(e -> logger.error(
                           "Failed to revoke certificate '{}'. The certificate should be revoked manually.",
                           certificate.getSerialNumber()
                   ));
    }

    private void revokeCertificate(String serialNumber, String issuerDN, CertificateRevocationReason revocationReason) {
        ejbcaClient.revokeCertificate(serialNumber, issuerDN, revocationReason)
                   .consumeError(e -> logger.error(
                           "Failed to revoke certificate with serial number '{}' and issuer '{}'. The certificate should be revoked manually.",
                           serialNumber, issuerDN
                   ));
    }
}
