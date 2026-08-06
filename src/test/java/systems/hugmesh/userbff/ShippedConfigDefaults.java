package systems.hugmesh.userbff;

import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.origin.OriginTrackedValue;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.MalformedInputException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Test-support: reads this module's SHIPPED CONFIG DEFAULTS off disk the way a
 * deployment resolves them. Plain file IO — no Spring context, no database, no
 * network; cwd is the module root (same convention as {@code OpenApiSpecDumpTest}).
 *
 * <p>Shared by {@link ConfigDefaultsContractTest} (does any default still name a
 * pre-rebrand service, and do the duplicated copies agree?) and
 * {@link CasdoorRegistrationContractTest} (does every default that has to line up
 * with what casdoor-init registers actually line up?). Both need the same three
 * primitives — walk {@code src/main}, flatten {@code application.yml}, and peel a
 * {@code ${a:${B:literal}}} placeholder down to the literal a fresh cluster gets —
 * so they live here once rather than drifting in two copies.
 */
final class ShippedConfigDefaults {

    static final Path MAIN = Path.of("src", "main");
    static final Path MAIN_JAVA = MAIN.resolve("java");
    static final Path APPLICATION_YML = MAIN.resolve("resources").resolve("application.yml");

    private ShippedConfigDefaults() {
    }

    /** One {@code @Value("${key:default}")} occurrence. {@code defaultExpr} is null when absent. */
    record ValueDecl(Path file, int line, String key, String defaultExpr) {
        String where() {
            return file + ":" + line;
        }
    }

    /** {@code @Value(} then a single Java string literal (no escapes occur in these). */
    private static final Pattern VALUE_ANNOTATION = Pattern.compile("@Value\\(\\s*\"([^\"]*)\"");

    static List<ValueDecl> inlineValueDeclarations() throws IOException {
        List<ValueDecl> out = new ArrayList<>();
        for (Path file : filesUnder(MAIN_JAVA)) {
            if (!file.toString().endsWith(".java")) {
                continue;
            }
            String text = Files.readString(file);
            Matcher m = VALUE_ANNOTATION.matcher(text);
            while (m.find()) {
                String[] kv = splitKeyAndDefault(m.group(1));
                if (kv == null) {
                    continue; // SpEL (#{...}) or a composite expression — not a plain placeholder
                }
                out.add(new ValueDecl(file, lineOf(text, m.start()), kv[0], kv[1]));
            }
        }
        return out;
    }

    /** Flattened {@code application.yml}, loaded the way Spring Boot itself loads it. */
    static Map<String, String> applicationYmlDefaults() throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        List<PropertySource<?>> sources =
                new YamlPropertySourceLoader().load("application.yml", new FileSystemResource(APPLICATION_YML));
        for (PropertySource<?> source : sources) {
            if (!(source instanceof EnumerablePropertySource<?> enumerable)) {
                continue;
            }
            for (String name : enumerable.getPropertyNames()) {
                Object raw = enumerable.getProperty(name);
                if (raw instanceof OriginTrackedValue tracked) {
                    raw = tracked.getValue();
                }
                if (raw != null) {
                    out.put(name, String.valueOf(raw));
                }
            }
        }
        return out;
    }

    /**
     * Split {@code ${key:default}} at the FIRST top-level {@code :}. The default may itself
     * be a placeholder ({@code ${a:${B:lit}}}), so brace depth is tracked. Returns
     * {@code null} when the expression is not one single placeholder; {@code [1]} is
     * {@code null} when the placeholder has no default.
     */
    static String[] splitKeyAndDefault(String expression) {
        if (!expression.startsWith("${") || !expression.endsWith("}")) {
            return null;
        }
        String inner = expression.substring(2, expression.length() - 1);
        int depth = 0;
        int split = -1;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '$' && i + 1 < inner.length() && inner.charAt(i + 1) == '{') {
                depth++;
                i++;
            } else if (c == '}') {
                if (depth == 0) {
                    return null; // the opening ${ closed before the end: not a single placeholder
                }
                depth--;
            } else if (c == ':' && depth == 0 && split < 0) {
                split = i;
            }
        }
        if (depth != 0) {
            return null;
        }
        return split < 0
                ? new String[]{inner, null}
                : new String[]{inner.substring(0, split), inner.substring(split + 1)};
    }

    /**
     * Peel nested placeholder fallbacks down to the literal a deployment gets when NO env
     * var and NO other property is set — the value a fresh cluster actually resolves.
     */
    static String literalFallback(String expression) {
        String current = expression;
        while (true) {
            String[] kv = splitKeyAndDefault(current);
            if (kv == null || kv[1] == null) {
                return current;
            }
            current = kv[1];
        }
    }

    static List<Path> filesUnder(Path root) throws IOException {
        try (Stream<Path> walk = Files.walk(root)) {
            return walk.filter(Files::isRegularFile).sorted().toList();
        }
    }

    /** Text lines, or none for a binary/undecodable file (nothing to lint there). */
    static List<String> readLines(Path file) {
        try {
            return Files.readAllLines(file);
        } catch (MalformedInputException e) {
            return List.of();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
}
