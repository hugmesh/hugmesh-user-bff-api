package net.hugmesh.userbff;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import net.hugmesh.userbff.ShippedConfigDefaults.ValueDecl;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static net.hugmesh.userbff.ShippedConfigDefaults.MAIN;
import static net.hugmesh.userbff.ShippedConfigDefaults.applicationYmlDefaults;
import static net.hugmesh.userbff.ShippedConfigDefaults.filesUnder;
import static net.hugmesh.userbff.ShippedConfigDefaults.inlineValueDeclarations;
import static net.hugmesh.userbff.ShippedConfigDefaults.literalFallback;
import static net.hugmesh.userbff.ShippedConfigDefaults.readLines;

/**
 * REPO-LEVEL CONTRACT over this service's SHIPPED CONFIG DEFAULTS. Plain JUnit — no
 * Spring context, no database, no network: it reads {@code src/main} off disk (cwd =
 * module root, same convention as {@code OpenApiSpecDumpTest}).
 *
 * <p>It exists because of a LIVE fresh-cluster outage: on the first real kind run of
 * the GitOps payload, {@code POST /bff/login} failed because this BFF's own defaults
 * still named PRE-REBRAND services — it resolved {@code casdoor.exampleorg-pki…} and
 * {@code exampleorg-admin-bff-api.exampleorg-backend…} (the old brand is written as the
 * placeholder {@code exampleorg} throughout this file) and got NXDOMAIN. Nothing in
 * the build could notice: the values are only ever exercised when the deployment does
 * NOT override them, which is exactly the case nobody tests.
 *
 * <p>Three properties are pinned, each closing one half of that failure:
 * <ol>
 *   <li>{@link #noPreRebrandIdentifiersInMainSources()} — no pre-rebrand identifier may
 *       reappear anywhere under {@code src/main} (defaults, javadoc, resources).</li>
 *   <li>{@link #inlineValueDefaultsAgreeWithApplicationYml()} — a default that is written
 *       BOTH in {@code application.yml} and inline in a {@code @Value} fallback must be
 *       the same value on both sides. Several keys carry the string in three places, so
 *       "fix one, miss the others" is the natural failure mode.</li>
 *   <li>{@link #duplicatedInlineValueDefaultsAgree()} — the same property key declared in
 *       more than one Java file must carry a byte-identical inline default.</li>
 * </ol>
 *
 * <p><b>SHAPE ONLY.</b> This class checks that no default LOOKS pre-rebrand and that the
 * copies agree WITH EACH OTHER. It cannot tell whether a correctly-shaped
 * {@code hugmesh-*} value is the RIGHT value: {@code app.bff.oidc.client-id: user-bff}
 * carries no banned identifier and had one single copy, so all three properties above
 * passed while POST {@code /bff/login} still 401'd with "Invalid client_id" against a
 * Casdoor that registers clientId {@code app-user-bff}. Agreement with the OTHER SIDE —
 * what casdoor-init actually registers — is {@link CasdoorRegistrationContractTest}.
 *
 * <p><b>Where the banned list comes from.</b> The old brand name is deliberately NOT
 * written anywhere in this repository, not even in this lint, so the list of banned
 * identifiers is supplied from OUTSIDE the repo at run time:
 * <ul>
 *   <li>{@value #TOKENS_ENV}: comma-separated identifiers, and/or</li>
 *   <li>{@value #TOKENS_FILE_ENV}: path to a file holding one identifier per line
 *       ({@code #} starts a comment). A set-but-unreadable file FAILS the test rather
 *       than silently checking nothing.</li>
 * </ul>
 * Each identifier is matched as a literal substring, case-insensitively. The placeholder
 * {@value #PLACEHOLDER_TOKEN} is always in the list, so the scan is never empty. When
 * neither variable is set the scan still runs, but it only proves the mechanism works
 * (see {@link #theLintFlagsAPlantedIdentifier()}); the real old-brand check needs the
 * variable exported on the machine that runs the gate.
 *
 * <p><b>Scope: {@code src/main} only.</b> The rebrand has been applied repo-wide and
 * {@link #ALLOWLIST} stays empty. Two notes on what the
 * rest of the repo actually is:
 * <ul>
 *   <li>The GitLab/GitHub group ({@code .gitlab-ci.yml}, {@code settings.xml}) is
 *       {@code hugmesh}, and the in-cluster image registry is Harbor at
 *       {@code registry.hugmesh.net}. The k8s node-label domain is
 *       {@code hugmesh.net/<tier>}.</li>
 *   <li>{@code deploy/} and {@code hugmesh-deploy.yaml} are a Forgejo-cutover PILOT
 *       that ships dark (the live GitHub-rooted ArgoCD ignores them and the Forgejo
 *       catalog is unseeded) and are a DRIFTED copy of the authoritative central
 *       manifest in hugmesh-generator {@code specs/cluster/manifests/user-bff-api/};
 *       they should be re-synced from that central copy rather than hand-maintained.
 *       The narrow slice of them that can silently re-break login IS guarded — see
 *       {@code CasdoorRegistrationContractTest#repoManifestsNeverContradictThePinnedContract()}.</li>
 * </ul>
 * A future genuine exception INSIDE {@code src/main} goes in {@link #ALLOWLIST}, one
 * path per line, with its reason.
 */
class ConfigDefaultsContractTest {

    /** Env var: comma-separated banned identifiers, supplied from outside the repo. */
    static final String TOKENS_ENV = "HUGMESH_FORBIDDEN_TOKENS";

    /** Env var: path to a file of banned identifiers (one per line, {@code #} comments). */
    static final String TOKENS_FILE_ENV = "HUGMESH_FORBIDDEN_TOKENS_FILE";

    /** Always banned, so the list is never empty. A placeholder, not a real old name. */
    static final String PLACEHOLDER_TOKEN = "exampleorg-legacy";

    /**
     * Pre-rebrand identifiers, case-insensitive literal matches, so one entry also
     * catches its {@code Exampleorg-Systems}, {@code exampleorg_gateway} and
     * {@code EXAMPLEORG_*} env-name forms, not just the DNS form.
     */
    private static final List<Pattern> BANNED =
            bannedPatterns(System.getenv(TOKENS_ENV), System.getenv(TOKENS_FILE_ENV));

    static List<Pattern> bannedPatterns(String tokensCsv, String tokensFile) {
        Set<String> tokens = new LinkedHashSet<>();
        tokens.add(PLACEHOLDER_TOKEN);
        if (tokensCsv != null) {
            for (String t : tokensCsv.split(",")) {
                addToken(tokens, t);
            }
        }
        if (tokensFile != null && !tokensFile.isBlank()) {
            try {
                for (String line : Files.readAllLines(Path.of(tokensFile.strip()))) {
                    addToken(tokens, line.replaceFirst("#.*", ""));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(TOKENS_FILE_ENV + " is set but unreadable", e);
            }
        }
        List<Pattern> out = new ArrayList<>();
        for (String t : tokens) {
            out.add(Pattern.compile(Pattern.quote(t), Pattern.CASE_INSENSITIVE));
        }
        return out;
    }

    private static void addToken(Set<String> tokens, String raw) {
        String t = raw.strip();
        if (!t.isEmpty()) {
            tokens.add(t);
        }
    }

    /**
     * Repo-relative paths under {@code src/main} exempt from {@link #BANNED}. EMPTY on
     * purpose — see the class javadoc. Adding an entry requires a one-line reason here.
     */
    private static final Set<String> ALLOWLIST = Set.of();

    /**
     * Property keys whose inline {@code @Value} fallback DELIBERATELY differs from the
     * {@code application.yml} default, with the reason. Every other divergence is a bug.
     */
    private static final Map<String, String> INTENTIONAL_DIVERGENCE = Map.of(
            "app.hs-token.enabled",
            "application.yml ships the homeserver proxy LIVE (true); the injection points keep a "
                    + "fail-closed inline `false` so a context WITHOUT the packaged application.yml "
                    + "(slice tests, a stripped config) cannot silently turn the surface on.");

    // ── 1. the rebrand lint ──────────────────────────────────────────────────

    @Test
    void noPreRebrandIdentifiersInMainSources() throws IOException {
        assertThat(bannedHits(MAIN, BANNED, ALLOWLIST))
                .as("pre-rebrand identifiers under src/main — these are SHIPPED defaults and docs; "
                        + "every one of them resolves to NXDOMAIN in a real cluster")
                .isEmpty();
    }

    /**
     * Proves the lint is live even when no real identifier is configured: a planted
     * identifier in a scratch tree must be reported, in every case form, and a token
     * containing regex metacharacters must match literally.
     */
    @Test
    void theLintFlagsAPlantedIdentifier(@TempDir Path tmp) throws IOException {
        Path tree = Files.createDirectory(tmp.resolve("tree"));
        Path cfg = tree.resolve("application.yml");
        Files.writeString(cfg, "url: http://ZZPLANTED-x.backend\nother: axb\nhost: a.b\n");
        Path list = tmp.resolve("tokens.txt");
        Files.writeString(list, "# comment line\nzzplanted # trailing comment\n\n");

        assertThat(bannedHits(tree, bannedPatterns(null, list.toString()), Set.of()))
                .containsExactly(cfg + ":1: url: http://ZZPLANTED-x.backend");
        assertThat(bannedHits(tree, bannedPatterns(" zzplanted , ", null), Set.of()))
                .hasSize(1);
        assertThat(bannedHits(tree, bannedPatterns("a.b", null), Set.of()))
                .as("'.' must be literal, not 'any character'")
                .containsExactly(cfg + ":3: host: a.b");
        assertThat(bannedHits(tree, bannedPatterns(null, null), Set.of()))
                .as("placeholder only: nothing planted matches it")
                .isEmpty();
        assertThat(bannedHits(tree, bannedPatterns("zzplanted", null), Set.of(cfg.toString())))
                .as("an allowlisted path is skipped")
                .isEmpty();
    }

    @Test
    void anUnreadableTokenFileFailsLoudly(@TempDir Path tmp) {
        String missing = tmp.resolve("absent.txt").toString();
        assertThatThrownBy(() -> bannedPatterns(null, missing))
                .isInstanceOf(UncheckedIOException.class)
                .hasMessageContaining(TOKENS_FILE_ENV);
    }

    static List<String> bannedHits(Path root, List<Pattern> banned, Set<String> allowlist)
            throws IOException {
        List<String> hits = new ArrayList<>();
        for (Path file : filesUnder(root)) {
            String rel = file.toString();
            if (allowlist.contains(rel)) {
                continue;
            }
            List<String> lines = readLines(file);
            for (int i = 0; i < lines.size(); i++) {
                for (Pattern p : banned) {
                    if (p.matcher(lines.get(i)).find()) {
                        hits.add(rel + ":" + (i + 1) + ": " + lines.get(i).strip());
                        break;
                    }
                }
            }
        }
        return hits;
    }

    // ── 2. application.yml vs. the inline @Value fallbacks ───────────────────

    @Test
    void inlineValueDefaultsAgreeWithApplicationYml() throws IOException {
        Map<String, String> yml = applicationYmlDefaults();
        List<String> mismatches = new ArrayList<>();
        for (ValueDecl decl : inlineValueDeclarations()) {
            if (decl.defaultExpr() == null || !yml.containsKey(decl.key())) {
                continue;
            }
            if (INTENTIONAL_DIVERGENCE.containsKey(decl.key())) {
                continue;
            }
            String fromYml = literalFallback(yml.get(decl.key()));
            String fromJava = literalFallback(decl.defaultExpr());
            if (!fromYml.equals(fromJava)) {
                mismatches.add(decl.key() + "\n    application.yml -> " + fromYml
                        + "\n    " + decl.where() + " -> " + fromJava);
            }
        }
        assertThat(mismatches)
                .as("the SAME property default is written twice and the copies drifted; "
                        + "fix both sides or record the divergence in INTENTIONAL_DIVERGENCE")
                .isEmpty();
    }

    // ── 3. the same key declared in several Java files ───────────────────────

    @Test
    void duplicatedInlineValueDefaultsAgree() throws IOException {
        Map<String, Map<String, List<String>>> byKey = new TreeMap<>();
        for (ValueDecl decl : inlineValueDeclarations()) {
            if (decl.defaultExpr() == null) {
                continue;
            }
            byKey.computeIfAbsent(decl.key(), k -> new LinkedHashMap<>())
                    .computeIfAbsent(decl.defaultExpr(), d -> new ArrayList<>())
                    .add(decl.where());
        }
        List<String> conflicts = new ArrayList<>();
        byKey.forEach((key, defaults) -> {
            if (defaults.size() > 1) {
                StringBuilder sb = new StringBuilder(key);
                defaults.forEach((def, sites) -> sb.append("\n    ").append(def).append("  @ ").append(sites));
                conflicts.add(sb.toString());
            }
        });
        assertThat(conflicts)
                .as("one property key, several inline @Value defaults — the copies must stay identical")
                .isEmpty();
    }

    // ── anti-vacuum ──────────────────────────────────────────────────────────

    /** Guards against a silently-empty scan (a vacuous lint is worse than none). */
    @Test
    void theScanActuallySeesTheSources() throws IOException {
        assertThat(filesUnder(MAIN)).as("src/main files scanned").hasSizeGreaterThan(50);
        assertThat(inlineValueDeclarations()).as("@Value declarations parsed").hasSizeGreaterThan(20);
        assertThat(applicationYmlDefaults())
                .as("application.yml parsed to no properties — the contract would be vacuous")
                .isNotEmpty();
    }
}
