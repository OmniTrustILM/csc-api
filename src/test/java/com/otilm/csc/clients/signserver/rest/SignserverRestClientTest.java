package com.otilm.csc.clients.signserver.rest;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.otilm.csc.configuration.SignApiAuthorization;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

@WireMockTest
class SignserverRestClientTest {

    private static final String PROCESS_PATH = "/signserver/rest/v1/workers/TestSigner/process";

    /**
     * SignServer 7.9.0 and later reject a REST process request that lacks
     * {@code X-Keyfactor-Requested-With} with HTTP 403, as protection against cross-site request
     * forgery. Any non-empty value is accepted.
     */
    @Test
    void processSendsKeyfactorRequestedWithHeader(WireMockRuntimeInfo wireMock) {
        // given
        stubFor(post(urlEqualTo(PROCESS_PATH)).willReturn(okJson("{\"data\":\"c2lnbmF0dXJl\"}")));
        SignserverRestClient client = new SignserverRestClient(
                wireMock.getHttpBaseUrl() + "/signserver", SignApiAuthorization.CERTIFICATE, null, null,
                new HttpComponentsClientHttpRequestFactory());

        // when
        client.process("TestSigner", "dummyData1".getBytes(), Map.of(), SignserverProcessEncoding.NONE);

        // then
        verify(postRequestedFor(urlEqualTo(PROCESS_PATH))
                       .withHeader("X-Keyfactor-Requested-With", matching(".+")));
    }
}
