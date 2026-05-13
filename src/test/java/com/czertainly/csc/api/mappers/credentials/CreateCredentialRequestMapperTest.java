package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.management.CreateCredentialDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.CertificateReturnType;
import com.czertainly.csc.model.csc.requests.CreateCredentialRequest;
import org.instancio.Instancio;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.instancio.Select.field;
import static org.junit.jupiter.api.Assertions.*;

class CreateCredentialRequestMapperTest {

    CreateCredentialRequestMapper mapper = new CreateCredentialRequestMapper();

    @Test
    void canMapRequest() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                            .set(field(CreateCredentialDto::certificates), "chain")
                            .create();

        // when
        CreateCredentialRequest request = mapper.map(dto);

        // then
        assertNotNull(request);
        assertEquals(dto.cryptoTokenName(), request.cryptoTokenName());
        assertEquals(dto.credentialProfileName(), request.credentialProfileName());
        assertEquals(dto.userId(), request.userId());
        assertEquals(dto.signatureQualifier(), request.signatureQualifier());
        assertEquals(dto.numberOfSignaturesPerAuthorization(), request.numberOfSignaturesPerAuthorization());
        assertEquals(dto.scal(), request.scal());
        assertEquals(dto.dn(), request.dn());
        assertEquals(dto.san(), request.san());
        assertEquals(dto.description(), request.description());
        assertEquals(CertificateReturnType.CERTIFICATE_CHAIN, request.certificateReturnType());
    }


    @Test
    void throwsWhenDtoNotProvided() {
        // given
        CreateCredentialDto dto = null;

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing request body.");
    }

    @Test
    void throwsOnMissingUserId() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .ignore(field(CreateCredentialDto::userId))
                                           .create();

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing string parameter userId.");
    }

    @Test
    void throwsOnMissingCryptoTokenName() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .ignore(field(CreateCredentialDto::cryptoTokenName))
                                           .create();

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing string parameter cryptoTokenName.");
    }

    @Test
    void throwsOnMissingDn() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .ignore(field(CreateCredentialDto::dn))
                                           .create();

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing string parameter dn.");
    }

    @Test
    void throwsOnMissingSan() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .ignore(field(CreateCredentialDto::san))
                                           .create();

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing string parameter san.");
    }

    @Test
    void throwsOnDescriptionTooLong() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .set(field(CreateCredentialDto::description), "a".repeat(256))
                                           .create();

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "The description field must be at most 255 characters long.");
    }

    @Test
    void numberOfSignaturesPerAuthorizationIsSetTo1WhenNull() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .ignore(field(CreateCredentialDto::numberOfSignaturesPerAuthorization))
                                           .set(field(CreateCredentialDto::certificates), "single")
                                           .create();

        // when
        CreateCredentialRequest request = mapper.map(dto);

        // then
        assertEquals(1, request.numberOfSignaturesPerAuthorization());
    }

    @Test
    void numberOfSignaturesPerAuthorizationIsSetTo1WhenLowerThan1() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .set(field(CreateCredentialDto::numberOfSignaturesPerAuthorization), 0)
                                           .set(field(CreateCredentialDto::certificates), "single")
                                           .create();

        // when
        CreateCredentialRequest request = mapper.map(dto);

        // then
        assertEquals(1, request.numberOfSignaturesPerAuthorization());
    }

    @Test
    void numberOfSignaturesPerAuthorizationIsSetToItsValueWhenHigherThan1() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .set(field(CreateCredentialDto::numberOfSignaturesPerAuthorization), 2)
                                           .set(field(CreateCredentialDto::certificates), "single")
                                           .create();

        // when
        CreateCredentialRequest request = mapper.map(dto);

        // then
        assertEquals(2, request.numberOfSignaturesPerAuthorization());
    }

    @Test
    void scalIsSetTo1WhenNull() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .ignore(field(CreateCredentialDto::scal))
                                           .set(field(CreateCredentialDto::certificates), "single")
                                           .create();

        // when
        CreateCredentialRequest request = mapper.map(dto);

        // then
        assertEquals("1", request.scal());
    }

    @Test
    void throwsOnInvalidCertificates() {
        // given
        CreateCredentialDto dto = Instancio.of(CreateCredentialDto.class)
                                           .set(field(CreateCredentialDto::certificates), "invalid_value")
                                           .create();

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Invalid parameter certificates.");
    }
}
