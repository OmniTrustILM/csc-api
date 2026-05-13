package com.czertainly.csc.service.credentials;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.CredentialMetadata;
import com.czertainly.csc.repository.CredentialsRepository;
import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class CredentialsServiceTest {

    private CredentialsRepository credentialsRepository;
    private CredentialsService credentialsService;

    @BeforeEach
    void setUp() {
        credentialsRepository = mock(CredentialsRepository.class);
        credentialsService = new CredentialsService(
                null, null, null, credentialsRepository,
                null, null, null, null, null, null, null
        );
    }

    @Test
    void getCredentialMetadataWrapsNullScalAndSignatureQualifierAsEmptyOptional() {
        // given
        UUID credentialId = UUID.randomUUID();
        CredentialMetadataEntity entity = new CredentialMetadataEntity();
        entity.setId(credentialId);
        entity.setUserId("user-1");
        entity.setKeyAlias("alias");
        entity.setCredentialProfile("profile");
        entity.setSignatureQualifier(null);
        entity.setMultisign(1);
        entity.setScal(null);
        entity.setCryptoTokenName("token");
        entity.setDisabled(false);
        when(credentialsRepository.findById(credentialId)).thenReturn(Optional.of(entity));

        // when
        Result<CredentialMetadata, TextError> result = credentialsService.getCredentialMetadata(credentialId, null);

        // then
        CredentialMetadata metadata = result.unwrap();
        assertTrue(metadata.signatureQualifier().isEmpty());
        assertTrue(metadata.scal().isEmpty());
    }

    @Test
    void getCredentialMetadataWrapsPresentScalAndSignatureQualifierAsOptional() {
        // given
        UUID credentialId = UUID.randomUUID();
        CredentialMetadataEntity entity = new CredentialMetadataEntity();
        entity.setId(credentialId);
        entity.setUserId("user-1");
        entity.setKeyAlias("alias");
        entity.setCredentialProfile("profile");
        entity.setSignatureQualifier("eu_eidas_ades");
        entity.setMultisign(1);
        entity.setScal("1");
        entity.setCryptoTokenName("token");
        entity.setDisabled(false);
        when(credentialsRepository.findByIdAndUserId(credentialId, "user-1")).thenReturn(Optional.of(entity));

        // when
        Result<CredentialMetadata, TextError> result = credentialsService.getCredentialMetadata(credentialId, "user-1");

        // then
        CredentialMetadata metadata = result.unwrap();
        assertEquals(Optional.of("eu_eidas_ades"), metadata.signatureQualifier());
        assertEquals(Optional.of("1"), metadata.scal());
    }
}
