package com.otilm.csc.utils.db;

import com.azure.spring.cloud.autoconfigure.implementation.context.AzureGlobalPropertiesAutoConfiguration;
import com.azure.spring.cloud.autoconfigure.implementation.jdbc.AzureJdbcAutoConfiguration;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Produces the JDBC connection options the Spring Cloud Azure starter appends when passwordless
 * authentication is enabled, so a test consumes the starter's own output instead of restating it.
 * A {@code BeanPostProcessor} on {@code DataSourceProperties} does the enhancing, so an
 * {@link ApplicationContextRunner} drives {@link AzureJdbcAutoConfiguration} with no database, and
 * {@link AzureGlobalPropertiesAutoConfiguration} comes too because that post processor looks up
 * its bean unconditionally.
 */
public final class PasswordlessJdbcUrl {

    /** Base URL for {@link #enhancedUrl()}, shared so a test need not restate the literal. */
    public static final String DATASOURCE_URL =
            "jdbc:postgresql://example.postgres.database.azure.com:5432/cscdb";

    private PasswordlessJdbcUrl() {
    }

    /**
     * Returns the enhanced URL's query parameters as connection properties, the form the driver
     * reduces a URL to before handing it to an authentication plugin.
     */
    public static Properties enhancedConnectionProperties() {
        return queryParameters(enhancedUrl());
    }

    /** Returns the enhanced JDBC URL, for assertions against the URL rather than its properties. */
    public static String enhancedUrl() {
        AtomicReference<String> url = new AtomicReference<>();
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AzureGlobalPropertiesAutoConfiguration.class,
                        AzureJdbcAutoConfiguration.class,
                        DataSourceAutoConfiguration.class))
                .withPropertyValues(
                        "spring.datasource.url=" + DATASOURCE_URL,
                        "spring.datasource.username=csc-api-identity",
                        "spring.datasource.driver-class-name=org.postgresql.Driver",
                        "spring.datasource.azure.passwordless-enabled=true")
                .run(context -> url.set(context.getBean(HikariDataSource.class).getJdbcUrl()));
        return url.get();
    }

    private static Properties queryParameters(String url) {
        int query = url.indexOf('?');
        if (query < 0) {
            throw new IllegalStateException("The starter added no connection options to " + url);
        }
        Properties properties = new Properties();
        for (String parameter : url.substring(query + 1).split("&")) {
            int separator = parameter.indexOf('=');
            if (separator < 0) {
                throw new IllegalStateException("Connection option without a value: " + parameter);
            }
            properties.setProperty(decode(parameter.substring(0, separator)),
                    decode(parameter.substring(separator + 1)));
        }
        return properties;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
