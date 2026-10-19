#!/usr/bin/env bash
# Local SonarQube analysis for csc-api (Java/Maven).
# Spins up an ephemeral SonarQube Community container, runs mvn package with
# JaCoCo coverage, then mvn sonar:sonar against the local instance, and
# prints the quality gate + open issues.
# Usage: ./scripts/sonar-local.sh
#
# Requires Docker (the build itself uses TestContainers for PostgreSQL, MySQL,
# Keycloak and Toxiproxy).
#
# IMPORTANT — Limitation of ephemeral SonarQube:
# The SonarQube container is freshly started on every run, so it has no
# previous analysis to use as a "new code" baseline. The Quality Gate's
# new-code conditions therefore evaluate trivially OK and do NOT match the
# behaviour you'll see on SonarCloud (where a real baseline exists). To
# approximate PR-style focus locally, this script intersects the Sonar
# issue list with `git diff --name-only main...HEAD` and reports only
# issues on changed files. Use it as a smoke-check; treat SonarCloud on
# the actual PR as authoritative.
set -euo pipefail

CONTAINER_NAME="ilm-csc-api-sonarqube"
SONAR_PORT="${SONAR_PORT:-9000}"
PROJECT_KEY="csc-api"
SONAR_URL="http://localhost:${SONAR_PORT}"
MAX_DUPLICATION="${MAX_DUPLICATION:-3}"
SONAR_PLUGIN_VERSION="${SONAR_PLUGIN_VERSION:-5.8.0.7211}"
# Pinned so the analyser version cannot change under the script without a diff. Override with
# SONAR_IMAGE to try a different release.
SONAR_IMAGE="${SONAR_IMAGE:-sonarqube:26.9.0.129388-community}"

cleanup() {
    echo "Stopping SonarQube..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "Starting ${SONAR_IMAGE} on port ${SONAR_PORT}..."
# Bound to the loopback interface only: this instance uses a well-known throwaway admin password
# (see below) and holds the analysed source, so it must not be reachable from the network.
docker run -d --name "${CONTAINER_NAME}" -p "127.0.0.1:${SONAR_PORT}:9000" "${SONAR_IMAGE}" >/dev/null

echo "Waiting for SonarQube to be ready (up to 2 minutes)..."
for i in $(seq 1 120); do
    if curl -sf "${SONAR_URL}/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
        echo "SonarQube is ready."
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "ERROR: SonarQube failed to start within 2 minutes."
        exit 1
    fi
    sleep 1
done

echo "Configuring SonarQube..."
# SonarQube ships with `admin/admin` as the factory default; the server forces
# this password to be changed on first login. We rotate it to `Admin12345678!`
# (a value that satisfies SonarQube's password policy) so the rest of the script
# can authenticate. Both credentials are scoped to this ephemeral container only —
# the container is removed by the EXIT trap, so neither value is persisted.
curl -s -o /dev/null -u admin:admin -X POST \
    "${SONAR_URL}/api/users/change_password?login=admin&previousPassword=admin&password=Admin12345678!" 2>/dev/null || true

if curl -sf -u admin:Admin12345678! "${SONAR_URL}/api/system/status" >/dev/null 2>&1; then
    SONAR_CREDS="admin:Admin12345678!"
elif curl -sf -u admin:admin "${SONAR_URL}/api/system/status" >/dev/null 2>&1; then
    SONAR_CREDS="admin:admin"
else
    echo "ERROR: Cannot authenticate to SonarQube."
    exit 1
fi

TOKEN_NAME="ci-$(date +%s)"
TOKEN=$(curl -sf -u "${SONAR_CREDS}" -X POST \
    "${SONAR_URL}/api/user_tokens/generate?name=${TOKEN_NAME}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "${TOKEN}" ]; then
    echo "ERROR: Failed to generate SonarQube token."
    exit 1
fi

# `package` — not `verify` — is the gate here: the `verify` phase starts the real
# application via spring-boot:start, which needs a deployed /opt/cscapi config
# tree plus live EJBCA and SignServer endpoints. CI (check_pr.yml) runs `package`
# for the same reason.
echo "Running mvn package with JaCoCo..."
mvn -B -U package

# The `sonar` plugin prefix does not resolve without an extra pluginGroup in settings.xml, so the
# goal is fully qualified exactly as `.github/workflows/sonar.yml` invokes it. The version is pinned
# here so a local run is reproducible.
echo "Running sonar analysis..."
mvn -B "org.sonarsource.scanner.maven:sonar-maven-plugin:${SONAR_PLUGIN_VERSION}:sonar" \
    -Dsonar.projectKey="${PROJECT_KEY}" \
    -Dsonar.host.url="${SONAR_URL}" \
    -Dsonar.token="${TOKEN}" \
    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
    -Dsonar.cpd.minimumTokens=100

echo ""
echo "=== SonarQube Results ==="
echo "Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"

# Sonar processes the analysis report asynchronously after upload. Poll until
# the projectStatus payload is available, then report.
# Any condition that cannot be positively verified fails the run — a gate that exits 0 when it
# could not measure anything is worse than no gate at all.
GATE_FAILED=0

# Sonar ingests the uploaded report asynchronously on its compute engine. Wait for that task to
# finish before reading anything: the quality gate and the measures API both answer with empty or
# NONE values while a report is still queued, which would otherwise look like a clean result.
echo ""
echo "Waiting for Sonar to process the analysis..."
PROCESSED=0
for i in $(seq 1 90); do
    CE_STATUS=$(curl -s -u "${SONAR_CREDS}" \
        "${SONAR_URL}/api/ce/component?component=${PROJECT_KEY}" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print('UNREADABLE'); raise SystemExit
if d.get('queue'):
    print('PENDING')
else:
    print((d.get('current') or {}).get('status', 'ABSENT'))
" 2>/dev/null || echo UNREADABLE)
    if [ "${CE_STATUS}" = "SUCCESS" ]; then
        PROCESSED=1
        break
    fi
    if [ "${CE_STATUS}" = "FAILED" ] || [ "${CE_STATUS}" = "CANCELED" ]; then
        echo "ERROR: Sonar compute-engine task ended as ${CE_STATUS}."
        break
    fi
    sleep 2
done
if [ "${PROCESSED}" -eq 0 ]; then
    echo "ERROR: Sonar did not finish processing the analysis; results could not be verified."
    GATE_FAILED=1
fi

PROBE=$(curl -s -u "${SONAR_CREDS}" \
    "${SONAR_URL}/api/qualitygates/project_status?projectKey=${PROJECT_KEY}" 2>/dev/null || true)

# Ephemeral SonarQube has no previous analysis to act as a "new code" baseline, so PR-style focus is
# approximated from the git diff. The intersection is done per *line*, not per file: filtering by
# file alone reports every pre-existing issue in any file the branch happens to touch, which
# SonarCloud would not raise because it gates on new code.
BASE_BRANCH="${BASE_BRANCH:-main}"
CHANGED=$(git diff --name-only "${BASE_BRANCH}...HEAD" 2>/dev/null || true)
CHANGED_LINES=$(git diff --unified=0 "${BASE_BRANCH}...HEAD" 2>/dev/null | python3 -c "
import sys, json, re
added, path = {}, None
for raw in sys.stdin:
    if raw.startswith('+++ '):
        target = raw[4:].strip()
        path = None if target == '/dev/null' else re.sub(r'^b/', '', target)
    elif raw.startswith('@@') and path:
        m = re.match(r'@@ -\S+ \+(\d+)(?:,(\d+))? @@', raw)
        if m:
            start = int(m.group(1))
            count = 1 if m.group(2) is None else int(m.group(2))
            added.setdefault(path, []).extend(range(start, start + count))
print(json.dumps(added))
" 2>/dev/null || echo '{}')
if [ -z "${CHANGED}" ]; then
    echo ""
    echo "(No changes vs ${BASE_BRANCH}; reporting the whole project for information.)"
    echo "Pre-existing project issues do not fail this run — there is nothing new to attribute."
    SCOPE_DESC="all project files, informational"
    FAIL_ON_ISSUES=0
else
    echo ""
    echo "Files changed vs ${BASE_BRANCH}:"
    echo "${CHANGED}" | sed 's/^/  /'
    SCOPE_DESC="added/changed lines only"
    FAIL_ON_ISSUES=1
fi

echo ""
echo "================================================================================"
echo "EPHEMERAL SONARQUBE — LIMITATION"
echo "================================================================================"
echo "  This run uses a freshly-started SonarQube container with no previous"
echo "  analysis to act as a 'new code' baseline. The Quality Gate evaluates"
echo "  trivially OK and does NOT match SonarCloud, where a real baseline exists."
echo "  Treat this as a smoke check; SonarCloud on the actual PR is authoritative."
echo "================================================================================"

echo ""
echo "Quality Gate (whole project; new-code conditions trivially OK without baseline):"
if ! echo "${PROBE}" | python3 -c "
import sys, json
d = json.load(sys.stdin)['projectStatus']
print(f'  Status: {d[\"status\"]}')
for c in d.get('conditions', []):
    print(f'  {c[\"metricKey\"]}: {c[\"actualValue\"]} (threshold: {c[\"errorThreshold\"]}) - {c[\"status\"]}')
sys.exit(1 if d['status'] == 'ERROR' else 0)
"; then
    echo "  -> Quality gate reported ERROR (or could not be read)."
    GATE_FAILED=1
fi

echo ""
echo "Duplication and coverage (whole project); duplication must stay under ${MAX_DUPLICATION}%:"
if ! curl -sf -u "${SONAR_CREDS}" \
    "${SONAR_URL}/api/measures/component?component=${PROJECT_KEY}&metricKeys=duplicated_lines_density,coverage,line_coverage,ncloc" \
    | MAX_DUPLICATION="${MAX_DUPLICATION}" python3 -c "
import sys, json, os
limit = float(os.environ['MAX_DUPLICATION'])
measures = {m['metric']: m['value'] for m in json.load(sys.stdin)['component']['measures']}
for metric, value in sorted(measures.items()):
    print(f'  {metric}: {value}')
density = measures.get('duplicated_lines_density')
if density is None:
    print('  ERROR: duplicated_lines_density not reported.')
    sys.exit(1)
if float(density) >= limit:
    print(f'  ERROR: duplication {density}% is at or above the {limit}% limit.')
    sys.exit(1)
"; then
    GATE_FAILED=1
fi

echo ""
echo "Issues — ${SCOPE_DESC} (derived from the git diff vs ${BASE_BRANCH}; not a full project view):"
# `curl -f` so an HTTP error is a gate failure, and the payload must actually carry an `issues`
# field — an error response such as {"errors":[...]} must never be read as "zero issues".
if ! curl -sf -u "${SONAR_CREDS}" \
    "${SONAR_URL}/api/issues/search?projectKeys=${PROJECT_KEY}&statuses=OPEN&ps=500" \
    | CHANGED_LINES="${CHANGED_LINES}" FAIL_ON_ISSUES="${FAIL_ON_ISSUES}" python3 -c "
import sys, json, os
added = json.loads(os.environ.get('CHANGED_LINES') or '{}')
fail_on_issues = os.environ.get('FAIL_ON_ISSUES') == '1'
payload = json.load(sys.stdin)
if 'issues' not in payload:
    print(f'  ERROR: unexpected response from the issues API: {payload}')
    sys.exit(1)


def touched(issue):
    # Sonar components look like '<projectKey>:<repo-relative path>'.
    path = issue.get('component', '').split(':', 1)[-1]
    lines = added.get(path)
    if lines is None:
        return False
    line = issue.get('line')
    # File-level issues carry no line; attribute them to a file the branch touched.
    return True if line is None else line in set(lines)


issues = payload['issues']
in_scope = [i for i in issues if touched(i)] if added else issues
print(f'  Total in scope: {len(in_scope)}')
for i in in_scope[:50]:
    comp = i['component'].split(':')[-1]
    print(f'  [{i[\"severity\"]}] {comp}:{i.get(\"line\", \"-\")} - {i[\"message\"]}')
# 'total' is the project-wide count; len(issues) is capped by the ps= page size, so report 'total'
# rather than a page count that would understate the project's pre-existing debt.
elsewhere = payload.get('total', len(issues)) - len(in_scope)
if elsewhere > 0:
    print(f'  ({elsewhere} pre-existing issue(s) elsewhere in the project, not attributed to this branch.)')
sys.exit(1 if in_scope and fail_on_issues else 0)
"; then
    echo "  -> Open issues attributable to this branch (or the issue list could not be read)."
    GATE_FAILED=1
fi

echo ""
echo "(Set BASE_BRANCH=<other> to compare against a different base; default: main.)"
if [ "${GATE_FAILED}" -ne 0 ]; then
    echo "RESULT: FAILED — see the conditions marked ERROR above."
    exit 1
fi
echo "RESULT: PASSED"
