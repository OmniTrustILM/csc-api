#!/bin/sh
# Verifies that the runtime image can load the Azure passwordless authentication classes. The
# image runs a jlink-trimmed JRE, so a dropped module would otherwise surface only in a deployed
# cluster. The container is given no network, so the attempt must end on the connection, never on
# a missing class.
#
# Usage: ./scripts/verify-passwordless-image.sh [image]
#
# A probe rather than an application start, because the application stops on the first missing
# file of a deployed /opt/cscapi tree long before it builds a data source, and would report a
# clean run of code it never reached.
set -eu

IMAGE="${1:-csc-api:passwordless-check}"

repository=$(cd "$(dirname "$0")/.." && pwd)

# Compile with the JDK the image's own runtime is linked from, so the probe cannot carry a class
# file version that runtime refuses to read.
compiler=$(awk '$1 == "FROM" && $NF == "optimize" { print $2 }' "$repository/Dockerfile")
if [ -z "$compiler" ]; then
    echo "FAIL: no optimize stage in $repository/Dockerfile to take a compiler from."
    exit 1
fi

probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
# The image runs as an unprivileged user and has to read the compiled probe out of the mount.
chmod 755 "$probe"

cat > "$probe/PasswordlessProbe.java" <<'JAVA'
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;

/**
 * Drives the authentication chain a passwordless connection drives, naming every class
 * reflectively so that this file compiles against the JDK alone while the classes it names are
 * loaded from the nested libraries of the application jar.
 */
public final class PasswordlessProbe {

    public static void main(String[] args) throws Exception {
        Class<?> httpClient = Class.forName("com.azure.core.http.HttpClient");
        Object transport = httpClient.getMethod("createDefault").invoke(null);
        System.out.println("PROBE transport=" + transport.getClass().getName());

        // Managed identity off is what sends the plugin down the DefaultAzureCredential chain.
        Properties options = new Properties();
        options.setProperty("azure.managedIdentityEnabled", "false");
        options.setProperty("azure.scopes", "https://ossrdbms-aad.database.windows.net/.default");
        Class<?> plugin = Class.forName(
                "com.azure.identity.extensions.jdbc.postgresql.AzurePostgresqlAuthenticationPlugin");
        Object instance = plugin.getConstructor(Properties.class).newInstance(options);
        System.out.println("PROBE plugin=" + instance.getClass().getName());

        Class<?> requestType = Class.forName("org.postgresql.plugin.AuthenticationRequestType");
        Method getPassword = plugin.getMethod("getPassword", requestType);
        try {
            getPassword.invoke(instance, requestType.getField("CLEARTEXT_PASSWORD").get(null));
            System.out.println("PROBE credential=token issued");
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof LinkageError) {
                // A resolution failure inside the credential chain is the one thing this probe
                // exists to catch, so it aborts the run rather than being reported as an outcome
                // of it, and the completion line below is never reached.
                throw (LinkageError) cause;
            }
            cause.printStackTrace(System.out);
            System.out.println("PROBE credential=" + cause.getClass().getName());
        }

        // Printed only once every step above has returned.
        System.out.println("PROBE complete");
    }
}
JAVA

# The compiler runs as root and writes into the mount, so the mode is set there rather than left
# to whatever umask the daemon happens to have.
if ! docker run --rm -v "$probe":/probe "$compiler" \
    sh -c 'javac -d /probe /probe/PasswordlessProbe.java && chmod 644 /probe/PasswordlessProbe.class'; then
    echo "FAIL: could not compile the probe with the compiler from the Dockerfile's optimize stage."
    exit 1
fi

# The federated-assertion path below is what production uses on AKS. WorkloadIdentityCredential
# only attempts it when a client id, tenant id, and federated token file are all present --
# unset, it reports itself unconfigured and DefaultAzureCredential moves on without ever
# reaching msal4j. The ids are placeholders: nothing reads them until a request reaches Entra
# ID, which --network none guarantees never happens. The token file is created inside the
# container because the /probe mount is read-only.
#
# AZURE_REQUEST_RETRY_COUNT=0 disables azure-core's exponential-backoff retries around the
# doomed connection attempt. It changes only how many times that attempt repeats, not which
# classes load or where it ultimately fails, and cuts the run from roughly 25 seconds to
# roughly 6.
output=$(docker run --rm --network none -v "$probe":/probe:ro \
    -e AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
    -e AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000 \
    -e AZURE_FEDERATED_TOKEN_FILE=/tmp/passwordless-probe-token \
    -e AZURE_REQUEST_RETRY_COUNT=0 \
    --entrypoint sh "$IMAGE" -c \
    'echo throwaway-token > "$AZURE_FEDERATED_TOKEN_FILE" && exec java \
        -cp /opt/cscapi/app.jar \
        -Dloader.main=PasswordlessProbe \
        -Dloader.path=/probe \
        org.springframework.boot.loader.launch.PropertiesLauncher' 2>&1 || true)

case "$output" in
    *NoClassDefFoundError*|*ClassNotFoundException*|*"module not found"*|*NoSuchMethodError*)
        echo "FAIL: the runtime image cannot load the Azure authentication classes."
        echo "$output" | grep -E 'NoClassDefFoundError|ClassNotFoundException|module not found|NoSuchMethodError' | head -5
        exit 1
        ;;
esac

for step in transport plugin credential; do
    case "$output" in
        *"PROBE $step="*)
            ;;
        *)
            echo "FAIL: the runtime image did not reach the $step step of the Azure authentication chain."
            echo "$output" | tail -20
            exit 1
            ;;
    esac
done

# The patterns above enumerate known failures, so a run passes only on the completion line the
# probe prints last, never on the absence of those strings.
case "$output" in
    *"PROBE complete"*)
        ;;
    *)
        echo "FAIL: the probe did not run to completion in the runtime image."
        echo "$output" | tail -20
        exit 1
        ;;
esac

echo "$output" | grep '^PROBE '
echo "PASS: no class or module resolution failure in the runtime image."
