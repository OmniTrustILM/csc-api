# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ILM CSC API - a Spring Boot 4 REST API implementing the [Cloud Signature Consortium (CSC)](https://cloudsignatureconsortium.org) standard for remote digital signature operations. It integrates with **SignServer** for signature creation, **EJBCA** for certificate authority operations, and an **Identity Provider** (Keycloak) for OAuth2/OIDC authentication.

## Build & Test Commands

```bash
mvn clean package              # Full build with tests and JaCoCo coverage report
mvn test                       # Run unit tests only
mvn test -Dtest=ClassName      # Run a single test class
mvn test -Dtest=ClassName#methodName  # Run a single test method
```

Tests require **Docker** running (TestContainers spins up PostgreSQL, MySQL, Keycloak, Toxiproxy).

Test output is redirected to files (maven-surefire `redirectTestOutputToFile=true`).

**`package` is the gate, not `verify`.** `mvn verify` does not run on a developer
machine: the `spring-boot:start` goal bound to `pre-integration-test` boots the real
application, which needs a deployed `/opt/cscapi` tree (`workers.yml`, `profiles/`,
keystores) plus reachable EJBCA and SignServer endpoints. `sample-config/` does not
supply these. CI (`check_pr.yml`) runs `mvn -B -U package` for the same reason. The
OpenAPI spec under `openapi/` is only produced by `verify` and is not tracked in git.

## Development Environment

```bash
docker-compose -f development/docker-compose.yml up   # Start dev services (PostgreSQL, MySQL, Keycloak, MariaDB)
```

The `dev` Spring profile uses `src/main/resources/application-dev.yml`. In containers, config goes to `/opt/cscapi/application.yml`.

## Architecture

### API Layers

**CSC v2 API** (`csc/v2/`) - Standard CSC endpoints, secured with OAuth2 JWT:
- `POST csc/v2/info` - Service metadata (public)
- `POST csc/v2/credentials/list` and `credentials/info` - Credential queries
- `POST csc/v2/signatures/signHash` - Raw hash signing (plain signatures)
- `POST csc/v2/signatures/signDoc` - Document/digest signing (AdES signatures)

**Management API** (`management/v1/`) - Non-CSC credential lifecycle, secured with mTLS and/or OAuth2:
- `POST management/v1/credentials/{create,remove,disable,enable,rekey}`

### Signing Flow

`SignatureFacade` routes requests to the appropriate signing pipeline:

- **DocumentContentSigning** - Full document signing via SignServer
- **DocumentHashSigning** - Pre-computed digest signing
- **PlainHashSigning** - Raw hash signing (LongTermToken only)

Each pipeline uses a **SignatureProcessTemplate** that orchestrates: Authorization -> Token Provision -> Signing -> Response Mapping.

**Token types** determine key sourcing:
- **LongTermToken** - Persistent credentials stored in database
- **OneTimeToken** - Single-use keys from pre-generated pool
- **SessionToken** - Session-scoped temporary credentials

### External Service Clients

- **SignserverClient** - REST + SOAP/WS. Handles signing, key generation, CSR generation, certificate import
- **EjbcaClient** - SOAP/WS. Handles end entity creation, CSR signing, certificate revocation
- **IdpClient** - REST. Fetches user info, downloads JWKS for JWT validation (retry with exponential backoff)

### Authentication

- **OAuth2 JWT**: `CscJwtAuthenticationConverter` extracts claims including Signature Activation Data (SAD) into `CscAuthenticationToken`
- **mTLS**: Chain of filters (`MtlsClientCertificateFilter` -> `MtlsAuthorizationFilter` -> `MtlsAuthenticationFilter`) validates client certificates against trust anchors, issuer/subject DN allowlists, and fingerprint pinning
- Management auth type is configurable: `oauth2`, `certificate`, or `certificate_oauth2`

### Configuration

YAML-driven configuration at multiple levels:
- `application.yml` - Main Spring Boot config (DB, TLS, IDP, HTTP client settings)
- `workers.yml` (path in `csc.workerConfigurationFile`) - SignServer worker definitions with crypto tokens and capabilities
- `profiles/` directory (path in `csc.profilesConfigurationDirectory`) - Credential profiles and signature qualifier profiles per CA provider
- `key-pool-profiles.yml` - Pre-generated key pool sizes and replenishment schedules

### Database

- **Flyway** migrations in `src/main/resources/db/specific/{postgresql,mysql}/`
- Schema: `csc`, history table: `csc_schema_history`
- Supports PostgreSQL and MySQL
- Database retry: max 3 attempts with exponential backoff for transient SQL errors

### Scheduled Tasks

Background jobs (cron-configurable via `csc.*` properties):
- Pre-generate session keys, one-time keys, and long-term keys
- Clean up expired sessions and used keys
- Concurrency controlled via `csc.concurrency.maxKeyGeneration` / `maxKeyDeletion`

### Key Design Patterns

- **Result monad** (`Result<T, E>`) for functional error handling with `flatMap`/`map`/`mapError`
- **Template Method** in `SignatureProcessTemplate` for signing orchestration
- **Strategy** pattern for signers, authorizers, token providers, and key selectors
- **Repository pattern** for both DB entities and YAML-based config (WorkerRepository, CredentialProfileRepository)

## Package Structure

```
com.otilm.csc
├── api/auth/          # Authentication (JWT converter, mTLS filters, token validation)
├── clients/           # External service clients (signserver/, ejbca/, idp/)
├── common/            # Shared utilities (Result monad, etc.)
├── components/        # Spring components (scheduled tasks, key pool management)
├── configuration/     # Configuration properties and Spring config classes
├── controllers/       # REST controllers (v2/ for CSC, noncsc/v1/ for management)
├── crypto/            # Cryptographic utilities (algorithm mapping, OID handling)
├── model/             # DTOs, request/response objects, domain models
├── providers/         # Certificate authority provider abstraction
├── repository/        # JPA repositories and YAML-based config repositories
├── service/           # Business logic services
└── signing/           # Signing orchestration (facade, pipelines, token providers)
```

## Dependency Management

Renovate (`renovate.json`, `config:recommended`) opens update PRs. These rules keep the
`pom.xml` sane:

- **Do not pin what the Spring Boot BOM manages, unless you mean to move ahead of it.** `flyway`,
  `snakeyaml`, `commons-lang3`, `httpclient5`, `httpcore5`, `logback`, `jackson` and `postgresql`
  carry no `<version>` and move with the parent. A forward-pin silently becomes a *downgrade* once
  the BOM catches up — `<tomcat.version>` was pinned to 11.0.22 ahead of the BOM and was removed
  when Spring Boot 4.1.0 began managing that exact version, and `version.postgresql` was dropped
  when 4.1.1 reached the 42.7.13 it had been holding.
- **Deliberate forward overrides of BOM-managed versions.** Spring Boot 4.1.1 manages `tomcat`
  11.0.24 and `mysql` 9.7.0; `tomcat.version` and `version.mysql` move ahead of both to pick up
  fixes the BOM has not reached. `tomcat.version` is at 11.0.25 because CVE-2026-65905,
  CVE-2026-65182 and CVE-2026-68525 are fixed there and the GitHub Advisory Database scores all
  three critical from their CVSS vectors — Apache itself rates them Low, Important and Low, so the
  pin exists to satisfy the scanners that gate CI, not because Apache calls them critical. Drop an
  override the moment the BOM meets or passes it, or it turns into the downgrade above.
- **`version.testcontainers*` are not overrides.** They pin 2.0.5, exactly what the
  `testcontainers-bom` imported by Spring Boot 4.1.1 already manages. They are held explicitly
  because `testcontainers-keycloak` is coupled to the TestContainers 2.0.x major (see below), so a
  BOM move to 3.x should break the build visibly here rather than at runtime in a test.
- **Not BOM-managed at all**, so the `version.*` property is the only source: BouncyCastle, jjwt,
  commons-text, springdoc, spring-retry, Instancio, testcontainers-keycloak, WireMock, the JaCoCo
  plugin, the Spring Cloud Azure starter, and its JDK HTTP transport.

Notes on specific dependencies:

- **`com.sun.istack:istack-commons-runtime`** is declared explicitly on purpose. `jaxb-runtime`
  (pulled by `spring-boot-starter-web-services` via `spring-ws-core`) uses `FinalArrayList`
  from it but no longer shades it, and the artifact does not reach the *runtime* classpath
  transitively — it resolves at `test` scope only. Without the explicit declaration, SOAP
  marshalling fails at runtime with `NoClassDefFoundError`. Verify with
  `mvn dependency:build-classpath -DincludeScope=runtime` before removing it.
- **TestContainers 2.x renamed every module coordinate** to a `testcontainers-*` prefix
  (`org.testcontainers:postgresql` → `org.testcontainers:testcontainers-postgresql`, and the
  same for `mysql`, `toxiproxy`, `junit-jupiter`). Renovate cannot rename coordinates, so its
  PRs bump only the core `testcontainers` artifact — applying one as-is leaves the modules on
  1.x and breaks resolution. 2.x also stopped shading commons-lang3, so
  `org.testcontainers.shaded.*` imports no longer resolve.
- **`com.mysql:mysql-connector-j` uses calendar versioning** from `26.7.0` onward (it follows
  `9.7.0`). A jump from 9.x to 26.x is expected, not a hijacked coordinate.
- **`com.github.dasniko:testcontainers-keycloak`** hard-couples to a TestContainers major
  version (4.3.x requires 2.0.x), so the two move together.
- **`org.wiremock:wiremock-standalone`** is test-scoped and stands in for the Microsoft Entra ID
  token endpoint; it shades its own Jetty, so it cannot collide with the servlet container.
- **`MockEntraTokenIssuer` is shaped by three Azure library constraints.** `IdentityClientOptions`
  rejects a non-`https` authority host, so the stub mints a `localhost` certificate and serves TLS;
  MSAL resolves an unknown authority against the real `login.microsoftonline.com`, so the
  connection test names its own `azure.tokenCredentialProviderClassName` and disables instance
  discovery; and azure-core caches every environment lookup process-wide, misses included, so the
  federated token reaches `WorkloadIdentityCredentialBuilder.tokenFilePath` rather than
  `AZURE_FEDERATED_TOKEN_FILE`, which one earlier read in the single Surefire JVM would pin empty
  for good. It and `PasswordlessDataSourceConfigurationTest` name classes from non-public
  `com.azure.*.implementation` packages, so a bump that relocates one breaks the build loudly.
- **Outbound HTTP defaults are pinned explicitly**, not inherited. In `ServerConfiguration`,
  `getHttpClient` states `HostnameVerificationPolicy.CLIENT` with
  `HttpsSupport.getDefaultHostnameVerifier()`, and `setSoKeepAlive(false)`. httpclient5 5.6 changed
  the single-argument `DefaultClientTlsStrategy` constructor to select
  `HostnameVerificationPolicy.BUILTIN` (JSSE endpoint identification, which rejects certificates
  with no `subjectAltName`), and httpcore5 5.4 changed the `SocketConfig` default for `soKeepAlive`
  to `true`. Both are stated explicitly so a BOM bump cannot silently change how the service
  authenticates EJBCA, SignServer, and IDP endpoints. Deployments using internal CN-only
  certificates depend on this.
- **httpcore5 5.4.3 caps incoming HTTP/1 responses** at 100 headers and an 8192-byte header
  line by default, and no `Http1Config` is set anywhere, so the clients inherit those limits.
  This cap *is* the fix for CVE-2026-54399, so raising it would reopen the advisory. An EJBCA,
  SignServer or IDP response that legitimately exceeded either limit would now be rejected —
  worth knowing before reaching for a network explanation.
- **httpclient5 5.6.3 counts the scheme in the redirect same-authority check.** A redirect from
  `https` to `http` on the same host and port is no longer same-authority, so `Authorization`
  is stripped instead of forwarded. `IdpClient.downloadUserInfo` sets a bearer header per
  request, so a downgrade-redirecting IDP loses it rather than leaking it over cleartext.
- **`com.azure.spring:spring-cloud-azure-starter-jdbc-postgresql`** pins its own
  `version.spring-cloud-azure`, and the Spring Cloud Azure BOM is deliberately **not** imported:
  Microsoft maps `spring-cloud-azure-dependencies` 7.4.0 to Spring Boot 4.0.x with no 4.1.x
  mapping, and an imported BOM outranks the parent for everything it manages. Its
  `azure-core-http-netty` transport is excluded in favour of `azure-core-http-jdk-httpclient`,
  because Netty's `netty-tcnative-boringssl-static` and `netty-transport-native-epoll` are
  glibc-linked and the runtime image is Alpine. Do not exclude the unused AMQP and management
  subtrees it drags in: without `azure-core-management`, `AzureGlobalPropertiesAutoConfiguration`
  has no `@ConditionalOnClass` guard and fails startup with `NoClassDefFoundError`; without
  `azure-core-amqp`, startup is clean but reflection over the bound configuration properties throws
  (actuator `configprops`, AOT, metadata tooling), latent only because that endpoint is not
  exposed. No test here boots a fully auto-configured context, so `mvn package` catches neither.
- **`version.azure-core-http-jdk-httpclient` and JNA hit the same nearest-wins hazard.** The
  property sits at dependency depth 1, so its `azure-core:1.59.1` beats the `1.58.1` the starter
  and `azure-identity` would resolve, governing the whole Azure stack. Separately,
  `net.java.dev.jna:jna:5.18.1` reaches the *runtime* classpath through `testcontainers` →
  `docker-java-transport-zerodep`, nearer than `azure-identity`'s own `jna:5.17.0` — a test-only
  dependency choosing the JNA shipped in the production image, dormant only because JNA loads for
  msal4j's persistent token cache, which neither credential path enables. Re-check with
  `mvn dependency:tree -Dverbose` and `mvn dependency:list -DincludeScope=runtime` when either
  moves.

Keycloak's `admin-cli` client enables lightweight access tokens by default, and the userinfo
endpoint rejects them. `IdpClientTest` turns that flag off during setup so it receives a full
access token, as a real IDP client would.

## Container Base Images

All three `Dockerfile` stages contribute to the published image, but they carry very different
vulnerability weight:

- **`build`** (`maven:3.9.x-eclipse-temurin-21`) produces the jar, and the final stage also
  copies the `docker/` tree out of it. Nothing from the Maven image's own filesystem or packages
  reaches the published image, so this tag moves on convenience, not urgency.
- **`optimize`** (`eclipse-temurin:21.0.x_y-jdk-alpine`) is the one that matters most. Its
  `jlink` output *is* the JRE in the final image, so a stale tag here puts known JDK
  vulnerabilities into production even though no JDK package is visible to a scanner. Keep it
  on the newest `21.0.x_y-jdk-alpine` tag.
- **`alpine:latest`** is deliberately left floating rather than pinned. Together with the
  `apk upgrade --no-cache` in the same stage, a floating tag rebuilds against current OS
  packages, which is what keeps the nightly Trivy probe green. Pinning it would trade that for
  reproducibility and start failing as the pin ages.

## Test Coverage & Sonar

Line coverage is **44.54%** (2726/6121) and instruction coverage 43.17%. This is pre-existing
test debt, concentrated in the signing pipelines, external service clients, and services.
SonarCloud gates on **new-code** coverage, so the ≥80% standard applies to new and changed
code; a change that adds no production lines satisfies it trivially. Raising the overall
figure is separate, deliberate work — do not bundle it into an unrelated change, because it
destroys the "tests unchanged and still green" signal that regression-free refactors rely on.
SonarCloud must report **no issues** on the change, not merely a passing quality gate, and
duplication must stay under 3%.

## Working Documents

Design specs and implementation plans under `docs/superpowers/` are gitignored local working
documents; code, comments, commit messages and PR descriptions must never reference them.

## Quality Gate Before Pushing

Run locally before opening a PR (GitHub Actions then run the authoritative SonarCloud and
CodeQL checks):

- `mvn clean package` — 574 tests, 0 failures. A changed test count means something was
  silently skipped, unless the change deliberately added tests.
- `./scripts/sonar-local.sh` — ephemeral SonarQube smoke check reporting the quality gate,
  duplication, and issues on changed files. An ephemeral server has no new-code baseline, so
  SonarCloud on the PR is authoritative.
- `copilot --allow-all-tools --model gpt-5.6-sol --effort max -p "..."` — an independent
  review pass on the diff. Every change goes through this.

The code itself must satisfy: no `TODO` or `FIXME` markers; no sensitive information such as
credentials, tokens, internal hostnames or customer names; comments that are accurate and minimal,
with no speculative notes or unrelated context; and small units with one clear purpose.

Container vulnerability scanning is **not** run locally. The shared reusable workflows in
`OmniTrustILM/.github` (`containers-test.yml`, `containers-build-and-push.yml`) enforce the
org-default Trivy policy. They read a repo-local Trivy config only when
`allow-trivy-config-override: true` is passed, and no csc-api workflow passes it.

## Commits & PRs

Write a plain description of what changed, formatted as markdown, and nothing else: **no**
co-author or attribution trailers and no mention of AI assistance, **no** validation or
quality-status lines (test counts, "BUILD SUCCESS", coverage numbers), and **no** follow-up work,
task lists, test plans or implementation plans. A PR description may link the issue it resolves.
Squash the branch into a single commit before the **first** push; keep later changes as separate
commits, so a reviewer can see what moved in response to their comments.

Do not push or open a PR without maintainer approval.
