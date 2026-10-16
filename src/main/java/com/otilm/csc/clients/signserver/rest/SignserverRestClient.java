package com.otilm.csc.clients.signserver.rest;

import com.otilm.csc.common.errorhandling.ErrorResultRetryException;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.common.result.TextErrorWithRetryIndication;
import com.otilm.csc.configuration.SignApiAuthorization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Retryable(
        retryFor = {ErrorResultRetryException.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 1000, multiplier = 2),
        listeners = {"resultRetryListener"})
public class SignserverRestClient {

    public static final Logger logger = LoggerFactory.getLogger(SignserverRestClient.class);

    public static final String WORKERS_REST_API_PATH = "/rest/v1/";
    public static final String WORKER_PROCESS_REST_API_PATH = WORKERS_REST_API_PATH + "workers/{workerName}/process";

    private final RestClient restClient;
    private final String basicAuthHeader;


    public SignserverRestClient(
            @Value("${signingProvider.signserver.url}") String signserverUrl,
            @Value("${signingProvider.signserver.client.authType}") SignApiAuthorization authzType,
            @Value("${signingProvider.signserver.client.basic.username}") String basicAuthUsername,
            @Value("${signingProvider.signserver.client.basic.password}") String basicAuthPassword,
            @Qualifier("signserverRequestFactory") HttpComponentsClientHttpRequestFactory requestFactory
    ) {
        logger.debug("Creating SignserverRestClient with base URL: {}", signserverUrl);
        restClient = RestClient.builder().requestFactory(requestFactory).baseUrl(signserverUrl).build();
        if (authzType == SignApiAuthorization.BASIC) {
            basicAuthHeader = "Basic " + Base64.getEncoder().encodeToString(
                    (basicAuthUsername + ":" + basicAuthPassword).getBytes());
        } else {
            basicAuthHeader = null;
        }
    }

    public Result<byte[], TextError> process(String workerName, byte[] data, Map<String, String> metadata,
                                             SignserverProcessEncoding encoding
    ) {
        logger.debug("Calling Signserver process API. WorkerName: {}, Encoding: {}, metadata: [{}]",
                     workerName, encoding,
                     metadata.entrySet().stream()
                             .map(e -> e.getKey() + "=" + e.getValue())
                             .collect(Collectors.joining(", "))
        );
        final String requestData;
        requestData = new String(data);

        WorkerProcessRequest workerProcessRequest = new WorkerProcessRequest(requestData, metadata, encoding);
        try {
            WorkerProcessResponse response = restClient.post().uri(WORKER_PROCESS_REST_API_PATH, workerName)
                                                       .body(workerProcessRequest)
                                                       .contentType(MediaType.APPLICATION_JSON)
                                                       .header("Authorization", basicAuthHeader)
                                                       .header("X-Keyfactor-Requested-With", "csc-api")
                                                       .accept(MediaType.APPLICATION_JSON).retrieve()
                                                       .body(WorkerProcessResponse.class);

            if (response == null) {
                logger.error("Processing failed on worker {}. The response object is null.", workerName);
                return Result.error(
                        TextErrorWithRetryIndication.doNotRetry("Processing failed on worker " + workerName));
            }
            return Result.success(response.data().getBytes());
        } catch (ResourceAccessException e) {
            logger.error("Processing failed on worker {}", workerName, e);
            return Result.error(TextErrorWithRetryIndication.doRetry("Processing failed on worker " + workerName));
        } catch (Exception e) {
            logger.error("Processing has failed on worker {}", workerName, e);
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Processing failed on worker " + workerName));
        }
    }
}