package net.hugmesh.userbff.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the TWO Maven-registry contracts of this service's image build, so that adding the
 * GitHub one can never silently remove the GitLab one.
 *
 * <ul>
 *   <li><b>GitLab / local lane (historical, must not change).</b> The repo-root
 *       {@code settings.xml} points at {@code ${env.CI_API_V4_URL}/groups/${env.GITLAB_GROUP_ID}}
 *       with a {@code Job-Token} header, and the Dockerfile mounts the BuildKit secret
 *       {@code ci_job_token} and runs {@code ./mvnw -B -s settings.xml package}. The GitLab
 *       pipeline and hugmesh-generator's local compose / kind lane depend on exactly that:
 *       {@code scripts/patch-stack-src.sh} greps {@code settings.xml} for
 *       {@code CI_API_V4_URL}, and {@code scripts/kind-load-images.sh} refuses a Dockerfile
 *       that does not thread {@code -s settings.xml}. Both fail by wedging a long image
 *       build, not by saying so.</li>
 *   <li><b>GitHub release workflow (additive).</b> When the BuildKit secret
 *       {@code packages_read_token} is mounted the Dockerfile uses
 *       {@code .github/maven-ci-settings.xml} against GitHub Packages. That file must stay
 *       mirrors-free, carry no committed credential, and declare every upstream of the chain
 *       as both a repository and a plugin repository (the analyser rulesets are resolved
 *       from plugin repositories).</li>
 *   <li><b>No xtrace in the build step.</b> With a real token present, {@code sh -x} prints
 *       {@code export UPSTREAM_PACKAGES_TOKEN=<value>} into the BuildKit log, and
 *       build-push-action v6 uploads a build-record artifact holding raw BuildKit logs,
 *       which runner-side masking does not cover.</li>
 *   <li><b>Beta release scheme (2026-10-21).</b> The workflow publishes from {@code main}
 *       ({@code :main}, {@code :sha-<12>}) and from {@code v<version>} tags
 *       ({@code :<version>}, {@code :beta}, {@code :sha-<12>}, a prerelease GitHub Release that
 *       is not latest), never {@code :latest}; it has no pull-request trigger; every job runs on
 *       {@code RUNS_ON_PUBLISH} only for main and v* refs and on hosted runners otherwise; and
 *       the pom version is a {@code MAJOR.MINOR.PATCH-beta.N}.</li>
 * </ul>
 *
 * <p>Reads the repository files directly (surefire runs with the project basedir as the
 * working directory). Comments are stripped before an ABSENCE is asserted, so a sentence
 * explaining why something is gone cannot satisfy or defeat a check.
 */
class ReleaseImageGuardTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final List<String> UPSTREAMS = List.of(
            "hugmesh-build-config", "hugmesh-parent", "hugmesh-commons", "hugmesh-auth-core");

    @Test
    @DisplayName("Dockerfile keeps the GitLab contract: ci_job_token mount, the ARG pair, literal -s settings.xml")
    void dockerfileKeepsGitLabContract() throws IOException {
        String dockerfile = code(read("Dockerfile"), "#");
        assertThat(dockerfile)
                .contains("--mount=type=secret,id=ci_job_token")
                .contains("ARG CI_API_V4_URL")
                .contains("ARG GITLAB_GROUP_ID");
        // The literal spelling: kind-load-images.sh greps for -s[[:space:]]+settings\.xml.
        assertThat(Pattern.compile("-s\\s+settings\\.xml\\s+package").matcher(dockerfile).find())
                .as("Dockerfile must still run `-s settings.xml package` verbatim in the no-secret branch")
                .isTrue();
    }

    @Test
    @DisplayName("Dockerfile adds the GitHub contract and does not xtrace the token")
    void dockerfileAddsGitHubContractWithoutXtrace() throws IOException {
        String dockerfile = code(read("Dockerfile"), "#");
        assertThat(dockerfile)
                .contains("--mount=type=secret,id=packages_read_token")
                .contains("ARG UPSTREAM_PACKAGES_ACTOR")
                .contains("-s .github/maven-ci-settings.xml");
        // `sh -euxc` (any flag cluster carrying x) or an explicit `set -x` would echo the token.
        assertThat(Pattern.compile("\\bsh\\s+-[a-z]*x[a-z]*\\b|\\bset\\s+-[a-z]*x").matcher(dockerfile).find())
                .as("the build RUN must not enable xtrace")
                .isFalse();
    }

    @Test
    @DisplayName("Repo-root settings.xml is still the GitLab registry and never names GitHub Packages")
    void rootSettingsStaysGitLab() throws IOException {
        String settings = read("settings.xml");
        assertThat(settings).contains("CI_API_V4_URL").contains("GITLAB_GROUP_ID").contains("Job-Token");
        assertThat(settings).doesNotContain("maven.pkg.github.com");
    }

    @Test
    @DisplayName(".github/maven-ci-settings.xml: no mirror, no committed secret, all upstreams as repo + plugin repo")
    void ciSettingsShape() throws Exception {
        Document doc = parse(read(".github/maven-ci-settings.xml"));
        assertThat(doc.getElementsByTagName("mirror").getLength()).as("mirrors-free").isZero();

        List<String> serverIds = new ArrayList<>();
        NodeList servers = doc.getElementsByTagName("server");
        for (int i = 0; i < servers.getLength(); i++) {
            Element server = (Element) servers.item(i);
            serverIds.add(text(server, "id"));
            assertThat(text(server, "password")).as("password of %s", text(server, "id"))
                    .isEqualTo("${env.UPSTREAM_PACKAGES_TOKEN}");
            assertThat(text(server, "username")).isEqualTo("${env.UPSTREAM_PACKAGES_ACTOR}");
        }
        List<String> expectedIds = UPSTREAMS.stream().map(u -> "github-" + u).toList();
        assertThat(serverIds).as("a consumer has read servers only; no `github` deploy server")
                .containsExactlyInAnyOrderElementsOf(expectedIds);

        for (String tag : Set.of("repository", "pluginRepository")) {
            NodeList repos = doc.getElementsByTagName(tag);
            List<String> found = new ArrayList<>();
            for (int i = 0; i < repos.getLength(); i++) {
                Element repo = (Element) repos.item(i);
                String id = text(repo, "id");
                found.add(id);
                assertThat(text(repo, "url")).isEqualTo(
                        "https://maven.pkg.github.com/hugmesh/" + id.substring("github-".length()));
            }
            assertThat(found).as("<%s> ids", tag).containsExactlyInAnyOrderElementsOf(expectedIds);
        }
    }

    @Test
    @DisplayName("release.yml feeds the GitHub contract, has no GITHUB_TOKEN fall-back and no dead GitLab inputs")
    void releaseWorkflowUsesGitHubContract() throws IOException {
        // No Assumptions.assumeTrue here: a deleted workflow must fail this test, not skip it.
        String yaml = code(read(".github/workflows/release.yml"), "#");
        assertThat(yaml)
                .contains("packages_read_token=${{ secrets.PACKAGES_READ_TOKEN }}")
                .contains("UPSTREAM_PACKAGES_ACTOR=${{ secrets.PACKAGES_READ_ACTOR || github.actor }}")
                .contains("DOCKER_BUILD_RECORD_UPLOAD: false")
                .contains("Preflight, cross-repo package read")
                .contains("workflow_dispatch");
        // GITHUB_TOKEN cannot read another repository's package; falling back to it only
        // turns a missing secret into a confusing later failure. It is still right for GHCR login.
        assertThat(yaml).as("no fall-back from PACKAGES_READ_TOKEN to GITHUB_TOKEN")
                .doesNotContain("PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN")
                .doesNotContain("PACKAGES_READ_TOKEN || github.token");
        assertThat(yaml).as("the GitLab inputs these names replaced must not come back")
                .doesNotContain("ci_job_token=")
                .doesNotContain("CI_API_V4_URL=")
                .doesNotContain("GITLAB_GROUP_ID=");
        for (String upstream : UPSTREAMS) {
            assertThat(yaml).as("the preflight must probe %s", upstream).contains(upstream);
        }
        assertThat(jobs(yaml).get("build-and-push"))
                .as("the image build must wait for the version guard AND the preflight")
                .contains("needs: [version, preflight]");
        assertThat(yaml.indexOf("Preflight, cross-repo package read"))
                .as("the preflight must precede the image build")
                .isGreaterThan(-1)
                .isLessThan(yaml.indexOf("docker/build-push-action"));
    }

    // ---------------------------------------------------------------------------------------
    // Beta release scheme (2026-10-21): what publishes, from where, under which tags.
    // ---------------------------------------------------------------------------------------

    /** The exact runs-on line every publish job carries (org beta scheme, section 3.1). */
    static final String PUBLISH_RUNS_ON = "${{ fromJSON(github.event_name != 'pull_request'"
            + " && github.event_name != 'pull_request_target'"
            + " && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
            + " || startsWith(github.ref, 'refs/tags/studio-v'))"
            + " && vars.RUNS_ON_PUBLISH || '\"ubuntu-latest\"') }}";

    @Test
    @DisplayName("release.yml triggers: push to main, v* tags and manual dispatch; never a PR, schedule or other event")
    void releaseTriggersAreMainTagsAndDispatchOnly() throws IOException {
        List<String> on = onBlock(code(read(".github/workflows/release.yml"), "#"));
        List<String> events = on.stream().filter(l -> l.matches("  \\S.*")).map(String::strip).toList();
        assertThat(events).as("the trigger events").containsExactly("push:", "workflow_dispatch: {}");
        List<String> push = on.stream().filter(l -> l.startsWith("    ")).map(String::strip).toList();
        assertThat(push).as("push publishes from main and v* tags only")
                .containsExactly("branches: [main]", "tags: ['v*']");
    }

    @Test
    @DisplayName("release jobs run on RUNS_ON_PUBLISH only for main / v* tags, hosted otherwise; the signed jobs always hosted; nothing reads RUNS_ON")
    void everyReleaseJobUsesThePublishRunnerLine() throws IOException {
        String yaml = code(read(".github/workflows/release.yml"), "#");
        Map<String, String> jobs = jobs(yaml);
        assertThat(jobs.keySet())
                .containsExactly("version", "preflight", "build-and-push", "github-release", "notify-site");
        // The signed publish job and notify-site never run on the self-hosted runner
        // (ReleaseSignedImageGuardTest pins the signing itself).
        Set<String> hosted = Set.of("build-and-push", "notify-site");
        for (Map.Entry<String, String> job : jobs.entrySet()) {
            List<String> runsOn = job.getValue().lines()
                    .filter(l -> l.startsWith("    runs-on:")).toList();
            assertThat(runsOn).as("runs-on of job %s", job.getKey())
                    .containsExactly("    runs-on: "
                            + (hosted.contains(job.getKey()) ? "ubuntu-latest" : PUBLISH_RUNS_ON));
        }
        assertThat(Pattern.compile("vars\\.RUNS_ON\\b(?!_PUBLISH)").matcher(yaml).find())
                .as("the PR-reachable RUNS_ON variable must not steer a publish job")
                .isFalse();
    }

    @Test
    @DisplayName("release.yml never pushes :latest; tag runs push :<version>, :sha-<12>, :beta and a prerelease that is not latest")
    void releaseNeverPushesLatest() throws IOException {
        String yaml = code(read(".github/workflows/release.yml"), "#");
        assertThat(yaml).as("no :latest image tag, in any spelling")
                .doesNotContain(":latest")
                .doesNotContain("latest=true")
                .doesNotContain("format('{0}:latest'");
        String image = jobs(yaml).get("build-and-push");
        assertThat(image)
                .contains("tags: ${{ steps.tags.outputs.list }}")
                .contains("tags=\"${IMAGE}:${VERSION}\"$'\\n'\"${IMAGE}:sha-${SHA12}\"")
                .contains("*-*) tags=\"${tags}\"$'\\n'\"${IMAGE}:beta\" ;;")
                .contains("tags=\"${IMAGE}:main\"$'\\n'\"${IMAGE}:sha-${SHA12}\"")
                .contains("org.opencontainers.image.source=https://github.com/${{ github.repository }}");
        String release = jobs(yaml).get("github-release");
        assertThat(release)
                .contains("if: needs.version.outputs.kind == 'release'")
                .contains("contents: write")
                .contains("flags=(--verify-tag)")
                .contains("*-*) flags+=(--prerelease --latest=false) ;;");
    }

    @Test
    @DisplayName("the version guard ties a v* tag to the pom version, refuses SNAPSHOT and other refs, and never overwrites a published version")
    void versionGuardIsWired() throws IOException {
        String yaml = code(read(".github/workflows/release.yml"), "#");
        String version = jobs(yaml).get("version");
        assertThat(version)
                .contains("E.parse(\"pom.xml\").getroot().find(n+\"version\")")
                .contains("*-SNAPSHOT)")
                .contains("semver='^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?$'")
                .contains("if ! [[ \"${version}\" =~ ${semver} ]]; then")
                .contains("if [ \"${GITHUB_REF_NAME#v}\" != \"${version}\" ]; then")
                .contains("\n            refs/heads/main)\n              kind=main\n")
                .contains("\n            refs/tags/v*)\n")
                .contains("\n            *)\n              echo \"::error::refusing to publish from ${GITHUB_REF}");
        assertThat(jobs(yaml).get("build-and-push"))
                .contains("if docker buildx imagetools inspect \"${IMAGE}:${VERSION}\" >/dev/null 2>&1; then");
    }

    @Test
    @DisplayName("pom.xml carries a beta version (MAJOR.MINOR.PATCH-beta.N) and no SNAPSHOT anywhere")
    void pomVersionIsABeta() throws Exception {
        Document pom = parse(read("pom.xml"));
        Element project = pom.getDocumentElement();
        assertThat(directChild(project, "version"))
                .as("project version").matches("\\d+\\.\\d+\\.\\d+-beta\\.[1-9]\\d*");
        assertThat(directChild(directChildElement(project, "parent"), "version"))
                .as("parent version").doesNotContain("SNAPSHOT");
        assertThat(read("pom.xml")).as("no SNAPSHOT coordinate").doesNotContain("-SNAPSHOT</version>");
    }

    /** The lines of the top-level {@code on:} block (its indented children). */
    private static List<String> onBlock(String yaml) {
        List<String> out = new ArrayList<>();
        boolean inside = false;
        for (String line : yaml.split("\n", -1)) {
            if (line.equals("on:")) {
                inside = true;
            } else if (inside && !line.isBlank() && !line.startsWith(" ")) {
                break;
            } else if (inside && !line.isBlank()) {
                out.add(line);
            }
        }
        assertThat(out).as("release.yml must have a top-level on: block").isNotEmpty();
        return out;
    }

    /** Job name -> the job's text, for every job under the top-level {@code jobs:} key. */
    private static Map<String, String> jobs(String yaml) {
        Map<String, String> out = new LinkedHashMap<>();
        Pattern header = Pattern.compile("^  ([A-Za-z0-9_-]+):\\s*$");
        boolean inside = false;
        String current = null;
        StringBuilder body = new StringBuilder();
        for (String line : yaml.split("\n", -1)) {
            if (line.equals("jobs:")) {
                inside = true;
                continue;
            }
            if (!inside) {
                continue;
            }
            if (!line.isBlank() && !line.startsWith(" ")) {
                break;
            }
            Matcher m = header.matcher(line);
            if (m.matches()) {
                if (current != null) {
                    out.put(current, body.toString());
                }
                current = m.group(1);
                body = new StringBuilder();
            } else if (current != null) {
                body.append(line).append('\n');
            }
        }
        if (current != null) {
            out.put(current, body.toString());
        }
        assertThat(out).as("release.yml must declare jobs").isNotEmpty();
        return out;
    }

    private static Element directChildElement(Element parent, String name) {
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i) instanceof Element e && e.getTagName().equals(name)) {
                return e;
            }
        }
        throw new AssertionError("<" + name + "> missing under <" + parent.getTagName() + ">");
    }

    private static String directChild(Element parent, String name) {
        return directChildElement(parent, name).getTextContent().trim();
    }

    @Test
    @DisplayName("Dockerfile refuses a mounted-but-empty packages_read_token instead of falling back to GitLab")
    void dockerfileRejectsEmptyToken() throws IOException {
        String dockerfile = code(read("Dockerfile"), "#");
        assertThat(dockerfile).contains("[ ! -s /run/secrets/packages_read_token ]");
    }

    private static String read(String relative) throws IOException {
        Path p = ROOT.resolve(relative);
        assertThat(p).as("%s must exist", relative).exists();
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** Drops whole-line comments so prose cannot satisfy or defeat a check. */
    private static String code(String text, String commentPrefix) {
        StringBuilder out = new StringBuilder();
        for (String line : text.split("\n", -1)) {
            if (!line.stripLeading().startsWith(commentPrefix)) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static String text(Element parent, String child) {
        NodeList nodes = parent.getElementsByTagName(child);
        assertThat(nodes.getLength()).as("<%s> in <%s>", child, parent.getTagName()).isGreaterThan(0);
        return nodes.item(0).getTextContent().trim();
    }
}
