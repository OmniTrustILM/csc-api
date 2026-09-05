package com.otilm.csc.configuration;

import com.azure.spring.cloud.autoconfigure.implementation.context.AzureGlobalPropertiesAutoConfiguration;
import com.azure.spring.cloud.autoconfigure.implementation.jdbc.AzureJdbcAutoConfiguration;
import com.otilm.csc.utils.db.PasswordlessJdbcUrl;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards against the Azure SDK issue class in which {@code passwordless-enabled: true} still
 * required a password. {@link ApplicationContextRunner} drives the starter's URL enhancement with
 * no database, arranged as {@link com.otilm.csc.utils.db.PasswordlessJdbcUrl} describes.
 *
 * <p>The managed identity flag and the scope are asserted as well, because
 * {@link PasswordlessConnectionTest} substitutes a workload identity credential for the one
 * {@code DefaultTokenCredentialProvider} would build, which only holds while the starter emits
 * {@code azure.managedIdentityEnabled=false}.
 */
class PasswordlessDataSourceConfigurationTest {

    private static final String PLUGIN_CLASS =
            "com.azure.identity.extensions.jdbc.postgresql.AzurePostgresqlAuthenticationPlugin";
    private static final String SCOPE = "https://ossrdbms-aad.database.windows.net/.default";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    AzureGlobalPropertiesAutoConfiguration.class,
                    AzureJdbcAutoConfiguration.class,
                    DataSourceAutoConfiguration.class))
            .withPropertyValues(
                    "spring.datasource.url=" + PasswordlessJdbcUrl.DATASOURCE_URL,
                    "spring.datasource.username=csc-api-identity",
                    "spring.datasource.driver-class-name=org.postgresql.Driver");

    @Test
    void startsWithoutPasswordAndAddsAuthenticationPlugin() {
        String jdbcUrl = PasswordlessJdbcUrl.enhancedUrl();
        assertThat(jdbcUrl)
                .contains("authenticationPluginClassName=" + PLUGIN_CLASS)
                // The starter's own default for a URL that names no sslmode, pinned so that a
                // change to it is noticed. It is not the mode to deploy with: `require` encrypts
                // without authenticating the server, so the configuration documents `verify-full`,
                // which needs a certificate authority only the operator can supply.
                .contains("sslmode=require")
                .contains("azure.managedIdentityEnabled=false")
                .contains("azure.scopes=" + SCOPE);
    }

    @Test
    void leavesConnectionUrlUntouchedWhenDisabled() {
        runner.withPropertyValues("spring.datasource.azure.passwordless-enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    HikariDataSource dataSource = context.getBean(HikariDataSource.class);
                    assertThat(dataSource.getJdbcUrl()).isEqualTo(PasswordlessJdbcUrl.DATASOURCE_URL);
                });
    }

    @Test
    void preservesAnExplicitSslModeInTheConnectionUrl() {
        runner.withPropertyValues(
                        "spring.datasource.url=jdbc:postgresql://example.postgres.database.azure.com:5432/cscdb?sslmode=verify-full",
                        "spring.datasource.azure.passwordless-enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    HikariDataSource dataSource = context.getBean(HikariDataSource.class);
                    assertThat(dataSource.getJdbcUrl()).contains("sslmode=verify-full");
                    assertThat(dataSource.getJdbcUrl()).doesNotContain("sslmode=require");
                    assertThat(dataSource.getJdbcUrl()).contains("authenticationPluginClassName=" + PLUGIN_CLASS);
                });
    }

    @Test
    void leavesPasswordAuthenticationInPlaceWhenAPasswordIsConfigured() {
        runner.withPropertyValues(
                        "spring.datasource.azure.passwordless-enabled=true",
                        "spring.datasource.password=your-strong-password")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    HikariDataSource dataSource = context.getBean(HikariDataSource.class);
                    assertThat(dataSource.getJdbcUrl()).isEqualTo(PasswordlessJdbcUrl.DATASOURCE_URL);
                });
    }
}
