package net.hugmesh.userbff;

import org.junit.jupiter.api.Test;
import net.hugmesh.userbff.ShippedConfigDefaults.ValueDecl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static net.hugmesh.userbff.ShippedConfigDefaults.applicationYmlDefaults;
import static net.hugmesh.userbff.ShippedConfigDefaults.filesUnder;
import static net.hugmesh.userbff.ShippedConfigDefaults.inlineValueDeclarations;
import static net.hugmesh.userbff.ShippedConfigDefaults.literalFallback;

/**
 * THE CASDOOR HANDSHAKE CONTRACT — the values on THIS side of {@code POST /bff/login}
 * that must byte-match what the cluster's {@code casdoor-init} Job registers on the
 * OTHER side. Plain JUnit: reads {@code application.yml}, the {@code @Value} fallbacks
 * and the repo's own k8s manifests off disk. No Spring context, no Casdoor, no cluster.
 *
 * <h2>Why this exists (and why the rebrand lint was not enough)</h2>
 * The first real kind run of the GitOps payload could not log anybody in.
 * {@link ConfigDefaultsContractTest} was added for the first half of that — defaults
 * still naming {@code *.snapdragon-*} services, which NXDOMAIN. It is a SHAPE lint: it
 * asks "does this look pre-rebrand?" and "do the copies agree with each other?".
 * <p>{@code app.bff.oidc.client-id: user-bff} passed all of that — no banned identifier,
 * one single copy — and {@code POST /bff/login} still returned
 * <b>401 "Invalid client_id"</b>, because {@code casdoor-init} registers the Casdoor
 * Application's {@code clientId} FIELD as {@code app-user-bff}:
 * <pre>
 *   # hugmesh-generator specs/cluster/manifests/casdoor/init-job.yaml, reconcile_app()
 *   appname = f"app-{name}"                    # name == "user-bff" (the APPS map key)
 *   app = { ..., "clientId": appname, ... }
 * </pre>
 * The generator's user-bff Deployment injects only the OIDC client SECRET — it never
 * sets {@code APP_BFF_OIDC_CLIENT_ID} — so the {@code application.yml} default IS what a
 * fresh cluster presents to Casdoor. A wrong default here is a production outage that
 * no test in this repo could see, because these values are only ever exercised when the
 * deployment does NOT override them.
 *
 * <h2>What is pinned</h2>
 * {@link #PINNED} is the whole login chain, not just the one broken key: the client
 * identity, the two Casdoor base URLs, both endpoint paths, the organization, and the
 * PKCE-matched redirect URI (Casdoor rejects the token exchange unless the
 * {@code redirect_uri} byte-matches a registered one — and it is sent on BOTH legs).
 * {@link #everyCasdoorNamespacedDefaultIsClassified()} then makes the list CLOSED: a
 * newly-added {@code app.bff.oidc.*} / {@code casdoor.*} default must be pinned or
 * explicitly recorded in {@link #NOT_REGISTERED_BY_CASDOOR_INIT}, so the guard cannot
 * quietly stop covering the chain it was written for.
 *
 * <h2>Both sides</h2>
 * <ul>
 *   <li>THIS side always: {@code application.yml}, every {@code @Value} fallback in
 *       {@code src/main}, and any env var this repo's own manifests set
 *       ({@code deploy/} is a Forgejo-cutover copy that used to hard-set the WRONG
 *       {@code APP_BFF_OIDC_CLIENT_ID}, which would have overridden the fix).</li>
 *   <li>THE CASDOOR side, opt-in: {@link #pinsAgreeWithTheGeneratorCasdoorInit()}
 *       re-derives the expected values from the generator's real
 *       {@code manifests/casdoor/init-job.yaml} when that checkout is pointed at with
 *       {@code -Dhugmesh.generator.dir=…} (or {@code HUGMESH_GENERATOR_DIR}). It is a
 *       hard failure when the directory is given and the derivation disagrees or the
 *       anchors it reads have moved; it does not run when no directory is given,
 *       because the CI image for this repo has no generator checkout. That gap is
 *       DELIBERATE and stated rather than papered over: the always-on half above is
 *       what protects the branch, and it is the half that failed live.</li>
 * </ul>
 */
class CasdoorRegistrationContractTest {

    /** The Casdoor Application key this BFF is registered under (the APPS map key). */
    private static final String CASDOOR_APP_KEY = "user-bff";

    /** {@code reconcile_app()}: {@code appname = f"app-{name}"} — both name AND clientId. */
    private static final String REGISTERED_APP = "app-" + CASDOOR_APP_KEY;

    /** {@code casdoor-init} Job env {@code CASDOOR_URL} — the in-cluster Casdoor. */
    private static final String CASDOOR_INTERNAL_BASE = "http://casdoor.hugmesh-pki.svc.cluster.local:8000";

    /** {@code casdoor-init} Job env {@code CASDOOR_ORG}, and the seeded organization name. */
    private static final String CASDOOR_ORG = "hugmesh";

    /** {@code reconcile_app()}'s user-bff override: {@code app["redirectUris"] = [...]}. */
    private static final String REGISTERED_REDIRECT_URI = "https://hugmesh.net/login/callback";

    /**
     * Every shipped default that has to agree with the Casdoor side, and the literal a
     * fresh cluster must resolve it to. Provenance for each is in the value comment.
     */
    private static final Map<String, String> PINNED = new LinkedHashMap<>();

    static {
        // ── client identity ──────────────────────────────────────────────────
        // reconcile_app(): "clientId": appname, appname = "app-user-bff". This is the
        // key whose `user-bff` default produced the live 401 "Invalid client_id":
        // CasdoorLoginClient sends it as the ?clientId= query param on /api/login, and
        // auth-core's OidcExchangeClient sends it again on the token exchange.
        PINNED.put("app.bff.oidc.client-id", REGISTERED_APP);
        // reconcile_app(): "name": appname. The /api/login BODY field "application".
        PINNED.put("app.bff.oidc.application", REGISTERED_APP);
        // Casdoor authenticates its REST API with HTTP Basic <clientId>:<clientSecret>
        // of an APPLICATION, so the account surface presents the SAME registered
        // clientId — not the bare app key.
        PINNED.put("casdoor.account.client-id", REGISTERED_APP);

        // ── organization ─────────────────────────────────────────────────────
        // init-job.yaml env CASDOOR_ORG=hugmesh; init_data.json seeds organization
        // "hugmesh". Sent in the /api/login body and used by the account client.
        PINNED.put("app.bff.oidc.organization", CASDOOR_ORG);
        PINNED.put("casdoor.organization", CASDOOR_ORG);

        // ── where Casdoor actually is ────────────────────────────────────────
        // init-job.yaml env CASDOOR_URL. login-base carries the plaintext password to
        // /api/login; `issuer` is NOT the JWT `iss` validator (that is
        // spring.security.oauth2.resourceserver.jwt.issuer-uri) but the base auth-core
        // POSTs `token-path` against, so it is the same internal Casdoor. It must NOT be
        // casdoor.gateway-base: the pki-gateway route table declares a LITERAL
        // `Path=/api/login` predicate, which never matches /api/login/oauth/access_token.
        PINNED.put("app.bff.oidc.login-base", CASDOOR_INTERNAL_BASE);
        PINNED.put("app.bff.oidc.issuer", CASDOOR_INTERNAL_BASE);
        PINNED.put("casdoor.account.base-url", CASDOOR_INTERNAL_BASE);

        // ── Casdoor's own endpoint paths ─────────────────────────────────────
        // Fixed by Casdoor itself, not by the seed (docs: the code->token exchange is
        // POST https://<host>/api/login/oauth/access_token).
        PINNED.put("app.bff.oidc.login-path", "/api/login");
        PINNED.put("app.bff.oidc.token-path", "/api/login/oauth/access_token");

        // ── the PKCE-matched redirect ────────────────────────────────────────
        // reconcile_app()'s user-bff override registers exactly ONE redirectUri. It is a
        // pure internal PKCE-match string (no browser ever dereferences it) and Casdoor
        // rejects the exchange unless it byte-matches, so drift here breaks login even
        // though nothing is ever redirected.
        PINNED.put("app.bff.oidc.redirect-uri", REGISTERED_REDIRECT_URI);
    }

    /**
     * The remaining {@code app.bff.oidc.*} / {@code casdoor.*} defaults, each with why it
     * is NOT part of the handshake. Keeping this explicit is what makes {@link #PINNED}
     * a closed set instead of a sample.
     */
    private static final Map<String, String> NOT_REGISTERED_BY_CASDOOR_INIT = Map.of(
            "app.bff.oidc.enabled",
            "local feature gate (ships dark); Casdoor has no matching notion.",
            "app.bff.oidc.client-secret",
            "SECRET — empty default is the fail-closed posture; the real value is ESO/Vault-sourced "
                    + "into APP_BFF_OIDC_CLIENT_SECRET and must never be a literal in git.",
            "app.bff.oidc.default-expiry-seconds",
            "local fallback TTL used only when Casdoor returns no expires_in; not a registered value.",
            "app.bff.oidc.scope",
            "OIDC scopes requested per call. The seeded Application object carries no scope "
                    + "allow-list, so there is nothing on the Casdoor side to agree with.",
            "casdoor.account.enabled",
            "local feature gate (account writes ship stubbed); Casdoor has no matching notion.",
            "casdoor.account.client-secret",
            "SECRET — see app.bff.oidc.client-secret.",
            "casdoor.gateway-base",
            "the hugmesh-pki-gateway front door, NOT Casdoor itself. It is deliberately absent from "
                    + "the login chain: its route table has no predicate matching the token endpoint.");

    /** Env var → property key, for the manifest scan. Same contract, spelled the k8s way. */
    private static final Map<String, String> ENV_TO_KEY = Map.of(
            "APP_BFF_OIDC_CLIENT_ID", "app.bff.oidc.client-id",
            "APP_BFF_OIDC_APPLICATION", "app.bff.oidc.application",
            "APP_BFF_OIDC_ORGANIZATION", "app.bff.oidc.organization",
            "APP_BFF_OIDC_REDIRECT_URI", "app.bff.oidc.redirect-uri",
            "APP_BFF_OIDC_LOGIN_BASE", "app.bff.oidc.login-base",
            "APP_BFF_OIDC_LOGIN_PATH", "app.bff.oidc.login-path",
            "APP_BFF_OIDC_TOKEN_PATH", "app.bff.oidc.token-path",
            "APP_BFF_OIDC_ISSUER", "app.bff.oidc.issuer",
            "CASDOOR_ACCOUNT_CLIENT_ID", "casdoor.account.client-id",
            "CASDOOR_ORG", "casdoor.organization");

    private static final String[] CASDOOR_PREFIXES = {"app.bff.oidc.", "casdoor."};

    // ── 1. application.yml ───────────────────────────────────────────────────

    @Test
    void applicationYmlResolvesEveryPinnedDefaultToTheRegisteredValue() throws IOException {
        Map<String, String> yml = applicationYmlDefaults();
        List<String> problems = new ArrayList<>();
        PINNED.forEach((key, expected) -> {
            String raw = yml.get(key);
            if (raw == null) {
                // Dropping the key is NOT harmless: auth-core's own OidcExchangeConfig
                // carries the pre-fix inline fallback @Value("${app.bff.oidc.client-id:user-bff}"),
                // so an absent key silently reinstates the exact live bug from the library.
                problems.add(key + "\n    MISSING from application.yml (expected " + expected + ")");
                return;
            }
            String actual = literalFallback(raw);
            if (!expected.equals(actual)) {
                problems.add(key + "\n    application.yml -> " + actual + "\n    casdoor-init    -> " + expected);
            }
        });
        assertThat(problems)
                .as("shipped defaults that do NOT match what casdoor-init registers — on a fresh "
                        + "cluster (which overrides none of these) POST /bff/login fails against Casdoor")
                .isEmpty();
    }

    // ── 2. the inline @Value fallbacks ───────────────────────────────────────

    @Test
    void everyInlineValueFallbackForAPinnedKeyResolvesToTheRegisteredValue() throws IOException {
        List<String> problems = new ArrayList<>();
        for (ValueDecl decl : inlineValueDeclarations()) {
            String expected = PINNED.get(decl.key());
            if (expected == null || decl.defaultExpr() == null) {
                continue;
            }
            String actual = literalFallback(decl.defaultExpr());
            if (!expected.equals(actual)) {
                problems.add(decl.key() + "\n    " + decl.where() + " -> " + actual
                        + "\n    casdoor-init -> " + expected);
            }
        }
        assertThat(problems)
                .as("an inline @Value fallback disagrees with what casdoor-init registers; it takes "
                        + "effect in any context without the packaged application.yml")
                .isEmpty();
    }

    // ── 3. the pin list stays CLOSED ─────────────────────────────────────────

    @Test
    void everyCasdoorNamespacedDefaultIsClassified() throws IOException {
        List<String> unclassified = new ArrayList<>();
        for (String key : new TreeMap<>(applicationYmlDefaults()).keySet()) {
            boolean casdoorNamespaced = false;
            for (String prefix : CASDOOR_PREFIXES) {
                casdoorNamespaced |= key.startsWith(prefix);
            }
            if (casdoorNamespaced
                    && !PINNED.containsKey(key)
                    && !NOT_REGISTERED_BY_CASDOOR_INIT.containsKey(key)) {
                unclassified.add(key);
            }
        }
        assertThat(unclassified)
                .as("a Casdoor-namespaced default is neither PINNED to what casdoor-init registers "
                        + "nor recorded in NOT_REGISTERED_BY_CASDOOR_INIT with a reason — decide which, "
                        + "so this contract keeps covering the whole login chain")
                .isEmpty();
    }

    // ── 4. this repo's own manifests must not contradict the pins ────────────

    @Test
    void repoManifestsNeverContradictThePinnedContract() throws IOException {
        List<String> problems = new ArrayList<>();
        for (Path file : repoManifests()) {
            for (EnvAssignment env : envAssignments(file)) {
                String key = ENV_TO_KEY.get(env.name());
                if (key == null) {
                    continue;
                }
                String expected = PINNED.get(key);
                if (expected != null && !expected.equals(env.value())) {
                    problems.add(env.where() + ": " + env.name() + "=" + env.value()
                            + "\n    overrides " + key + ", which casdoor-init registers as " + expected);
                }
            }
        }
        assertThat(problems)
                .as("a manifest in THIS repo hard-sets a Casdoor handshake env var to something other "
                        + "than what casdoor-init registers — an env var WINS over the application.yml "
                        + "default, so this silently re-breaks login no matter how correct the default is")
                .isEmpty();
    }

    // ── 5. the other side, when it is available ──────────────────────────────

    /**
     * Re-derive the expected values from the generator's real casdoor-init and compare
     * with {@link #PINNED}. Point it at a checkout with
     * {@code -Dhugmesh.generator.dir=/path/to/hugmesh-generator} or the
     * {@code HUGMESH_GENERATOR_DIR} env var; with neither set there is nothing to read
     * and the check does not run (this repo's CI image has no generator checkout — see
     * the class javadoc). When a directory IS given, every failure mode is a hard
     * failure: a missing file, a moved anchor, or a derived value that disagrees.
     */
    @Test
    void pinsAgreeWithTheGeneratorCasdoorInit() throws IOException {
        Optional<Path> generator = generatorDir();
        if (generator.isEmpty()) {
            return;
        }
        Path initJob = generator.get().resolve("specs/cluster/manifests/casdoor/init-job.yaml");
        assertThat(initJob)
                .as("hugmesh.generator.dir was given but does not contain the casdoor init Job")
                .exists();
        String text = Files.readString(initJob);
        List<String> problems = new ArrayList<>();

        // The clientId is DERIVED, not written: reconcile_app() builds `app-<key>` and
        // assigns it to BOTH "name" and "clientId". Assert those two structural anchors
        // still hold, then derive — so a change to either shape fails here loudly.
        requireAnchor(text, "appname = f\"app-{name}\"", initJob, problems);
        requireAnchor(text, "\"clientId\": appname", initJob, problems);
        requireAnchor(text, "\"" + CASDOOR_APP_KEY + "\": \"ROLE_API\"", initJob, problems);
        requireAnchor(text, "if name == \"" + CASDOOR_APP_KEY + "\":", initJob, problems);

        compare("clientId / application", REGISTERED_APP, "app-" + CASDOOR_APP_KEY, problems);
        compare("app.bff.oidc.redirect-uri",
                PINNED.get("app.bff.oidc.redirect-uri"),
                singleQuotedListValue(text, "app[\"redirectUris\"] = [", initJob, problems),
                problems);
        compare("CASDOOR_URL",
                CASDOOR_INTERNAL_BASE,
                envDefaultFromPython(text, "CASDOOR_URL", initJob, problems),
                problems);
        compare("CASDOOR_ORG",
                CASDOOR_ORG,
                envDefaultFromPython(text, "CASDOOR_ORG", initJob, problems),
                problems);

        // The Job's own container env must agree with the script's fallbacks, or the
        // reconcile writes to a different Casdoor than the one we pinned against.
        Map<String, String> jobEnv = new LinkedHashMap<>();
        for (EnvAssignment env : envAssignments(initJob)) {
            jobEnv.put(env.name(), env.value());
        }
        compare("init-job container env CASDOOR_URL", CASDOOR_INTERNAL_BASE, jobEnv.get("CASDOOR_URL"), problems);
        compare("init-job container env CASDOOR_ORG", CASDOOR_ORG, jobEnv.get("CASDOOR_ORG"), problems);

        assertThat(problems)
                .as("the pinned contract no longer matches the generator's casdoor-init at " + initJob
                        + " — the two sides drifted; fix whichever side is wrong")
                .isEmpty();
    }

    // ── anti-vacuum ──────────────────────────────────────────────────────────

    /** A silently-empty scan would make every property above pass by seeing nothing. */
    @Test
    void theScanActuallySeesTheSources() throws IOException {
        assertThat(PINNED).as("pinned handshake values").hasSizeGreaterThanOrEqualTo(11);
        assertThat(applicationYmlDefaults().keySet())
                .as("application.yml must declare the key whose wrong default broke login live")
                .contains("app.bff.oidc.client-id");
        assertThat(repoManifests()).as("repo manifests scanned").isNotEmpty();
        List<EnvAssignment> deployEnv = envAssignments(Path.of("deploy", "deployment.yaml"));
        assertThat(deployEnv)
                .as("the env scanner parsed nothing out of deploy/deployment.yaml — property 4 "
                        + "would be vacuous")
                .hasSizeGreaterThan(10);
        assertThat(deployEnv).extracting(EnvAssignment::name)
                .as("the env scanner must see the very var that used to carry the broken client id")
                .contains("APP_BFF_OIDC_CLIENT_ID");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** One literal {@code name:}/{@code value:} env entry in a k8s manifest. */
    private record EnvAssignment(Path file, int line, String name, String value) {
        String where() {
            return file + ":" + line;
        }
    }

    /** {@code - { name: FOO, value: "bar" }} — the flow-mapping form. */
    private static final Pattern ENV_FLOW = Pattern.compile(
            "\\{\\s*name:\\s*([A-Z][A-Z0-9_]*)\\s*,\\s*value:\\s*(\"[^\"]*\"|'[^']*'|[^,}]*?)\\s*\\}");

    /** {@code - name: FOO} on its own line — the block form; the value follows. */
    private static final Pattern ENV_BLOCK_NAME = Pattern.compile("^\\s*-?\\s*name:\\s*([A-Z][A-Z0-9_]*)\\s*$");

    private static final Pattern ENV_BLOCK_VALUE = Pattern.compile("^\\s*value:\\s*(\\S.*?)\\s*$");

    private static List<EnvAssignment> envAssignments(Path file) throws IOException {
        List<EnvAssignment> out = new ArrayList<>();
        if (!Files.isRegularFile(file)) {
            return out;
        }
        List<String> lines = Files.readAllLines(file);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.stripLeading().startsWith("#")) {
                continue;
            }
            Matcher flow = ENV_FLOW.matcher(line);
            while (flow.find()) {
                out.add(new EnvAssignment(file, i + 1, flow.group(1), unquote(flow.group(2))));
            }
            Matcher name = ENV_BLOCK_NAME.matcher(line);
            if (!name.matches()) {
                continue;
            }
            // Take the FIRST value: that belongs to this entry; stop at valueFrom: (a
            // secretKeyRef, no literal to check) or at the next list item.
            for (int j = i + 1; j < Math.min(i + 7, lines.size()); j++) {
                String next = lines.get(j);
                String stripped = next.strip();
                if (stripped.startsWith("#")) {
                    continue;
                }
                if (stripped.startsWith("valueFrom:") || stripped.startsWith("- ")) {
                    break;
                }
                Matcher value = ENV_BLOCK_VALUE.matcher(next);
                if (value.matches()) {
                    out.add(new EnvAssignment(file, j + 1, name.group(1), unquote(value.group(1))));
                    break;
                }
            }
        }
        return out;
    }

    /**
     * Every YAML in the repo EXCEPT the java sources and build output — i.e. the k8s /
     * kustomize / CI files, which are the OTHER place a handshake value can be written.
     */
    private static List<Path> repoManifests() throws IOException {
        List<Path> out = new ArrayList<>();
        try (java.util.stream.Stream<Path> walk = Files.walk(Path.of("."))) {
            walk.filter(p -> {
                String rel = p.normalize().toString();
                return !rel.startsWith("target") && !rel.startsWith("src") && !rel.startsWith(".git");
            }).filter(Files::isRegularFile).forEach(p -> {
                String rel = p.normalize().toString();
                if (rel.endsWith(".yaml") || rel.endsWith(".yml")) {
                    out.add(p.normalize());
                }
            });
        }
        out.sort(Path::compareTo);
        return out;
    }

    private static String unquote(String raw) {
        String s = raw.strip();
        if (s.length() >= 2
                && ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'")))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    private static Optional<Path> generatorDir() {
        String dir = System.getProperty("hugmesh.generator.dir", System.getenv("HUGMESH_GENERATOR_DIR"));
        return (dir == null || dir.isBlank()) ? Optional.empty() : Optional.of(Path.of(dir));
    }

    private static void requireAnchor(String text, String anchor, Path file, List<String> problems) {
        if (!text.contains(anchor)) {
            problems.add("anchor no longer present in " + file + ": " + anchor
                    + "\n    the casdoor-init shape this contract derives from has changed — re-derive it");
        }
    }

    /** Pull {@code "literal"} out of {@code <marker>"literal"…}. */
    private static String singleQuotedListValue(String text, String marker, Path file, List<String> problems) {
        int at = text.indexOf(marker);
        if (at < 0) {
            problems.add("marker not found in " + file + ": " + marker);
            return null;
        }
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(text.substring(at + marker.length()));
        if (!m.find()) {
            problems.add("no quoted value after marker in " + file + ": " + marker);
            return null;
        }
        return m.group(1);
    }

    /** Pull the default out of {@code os.environ.get("NAME", "default")}. */
    private static String envDefaultFromPython(String text, String name, Path file, List<String> problems) {
        Matcher m = Pattern.compile("os\\.environ\\.get\\(\"" + Pattern.quote(name) + "\",\\s*\"([^\"]*)\"\\)")
                .matcher(text);
        if (!m.find()) {
            problems.add("os.environ.get(\"" + name + "\", …) not found in " + file);
            return null;
        }
        return m.group(1);
    }

    private static void compare(String what, String expected, String derived, List<String> problems) {
        if (!expected.equals(derived)) {
            problems.add(what + "\n    pinned here    -> " + expected + "\n    casdoor-init   -> " + derived);
        }
    }
}
