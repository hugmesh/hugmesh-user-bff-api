package systems.hugmesh.userbff;

import org.junit.jupiter.api.Test;
import systems.hugmesh.userbff.ShippedConfigDefaults.ValueDecl;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static systems.hugmesh.userbff.ShippedConfigDefaults.MAIN;
import static systems.hugmesh.userbff.ShippedConfigDefaults.applicationYmlDefaults;
import static systems.hugmesh.userbff.ShippedConfigDefaults.filesUnder;
import static systems.hugmesh.userbff.ShippedConfigDefaults.inlineValueDeclarations;
import static systems.hugmesh.userbff.ShippedConfigDefaults.literalFallback;
import static systems.hugmesh.userbff.ShippedConfigDefaults.readLines;

/**
 * REPO-LEVEL CONTRACT over this service's SHIPPED CONFIG DEFAULTS. Plain JUnit — no
 * Spring context, no database, no network: it reads {@code src/main} off disk (cwd =
 * module root, same convention as {@code OpenApiSpecDumpTest}).
 *
 * <p>It exists because of a LIVE fresh-cluster outage: on the first real kind run of
 * the GitOps payload, {@code POST /bff/login} failed because this BFF's own defaults
 * still named PRE-REBRAND services — it resolved {@code casdoor.snapdragon-pki…} and
 * {@code snapdragon-admin-bff-api.snapdragon-backend…} and got NXDOMAIN. Nothing in
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
 * <p><b>Scope: {@code src/main} only.</b> {@code snapdragon} identifiers OUTSIDE
 * {@code src/main} are a MIX and are not all current, so this lint does not reach there
 * and {@link #ALLOWLIST} stays empty:
 * <ul>
 *   <li>GENUINELY CURRENT — the {@code Snapdragon-Systems} GitLab/GitHub group
 *       ({@code .gitlab-ci.yml}, {@code settings.xml}), the live k8s node-label domain
 *       {@code snapdragon.systems/<tier>} and the {@code registry.snapdragon.systems}
 *       image host ({@code deploy/}). Migrating those live identifiers is a separate,
 *       not-yet-executed plan.</li>
 *   <li>GENUINELY STALE, NOT FIXED HERE — {@code deploy/} and
 *       {@code snapdragon-deploy.yaml} are a Forgejo-cutover PILOT that ships dark
 *       (the live GitHub-rooted ArgoCD ignores them and the Forgejo catalog is
 *       unseeded) and are a DRIFTED copy of the authoritative central manifest in
 *       hugmesh-generator {@code specs/cluster/manifests/user-bff-api/}: they still
 *       carry {@code snapdragon-user-bff-api}, {@code snapdragon-backend} and
 *       pre-rebrand service hostnames. Re-syncing that copy is a separate change; the
 *       narrow slice of it that can silently re-break login IS guarded — see
 *       {@code CasdoorRegistrationContractTest#repoManifestsNeverContradictThePinnedContract()}.</li>
 * </ul>
 * A future genuine exception INSIDE {@code src/main} goes in {@link #ALLOWLIST}, one
 * path per line, with its reason.
 */
class ConfigDefaultsContractTest {

    /**
     * Pre-rebrand identifiers. Case-insensitive so it also catches {@code Snapdragon-Systems},
     * {@code snapdragon_gateway} and {@code SNAPDRAGON_*} env names, not just the DNS forms.
     */
    private static final List<Pattern> BANNED = List.of(
            Pattern.compile("snapdragon", Pattern.CASE_INSENSITIVE));

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
        List<String> hits = new ArrayList<>();
        for (Path file : filesUnder(MAIN)) {
            String rel = file.toString();
            if (ALLOWLIST.contains(rel)) {
                continue;
            }
            List<String> lines = readLines(file);
            for (int i = 0; i < lines.size(); i++) {
                for (Pattern banned : BANNED) {
                    if (banned.matcher(lines.get(i)).find()) {
                        hits.add(rel + ":" + (i + 1) + ": " + lines.get(i).strip());
                        break;
                    }
                }
            }
        }
        assertThat(hits)
                .as("pre-rebrand identifiers under src/main — these are SHIPPED defaults and docs; "
                        + "every one of them resolves to NXDOMAIN in a real cluster")
                .isEmpty();
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
