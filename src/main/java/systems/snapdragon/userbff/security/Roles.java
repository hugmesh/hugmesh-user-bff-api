package systems.snapdragon.userbff.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * JWT role extraction utility — COPIED VERBATIM (logic) from snapdragon-gateway's
 * {@code systems.snapdragon.gateway.security.Roles} so the BFF answers the same
 * "does this principal have role X / which domain is it" questions identically.
 *
 * <p>Casdoor's token template can emit the {@code roles} claim in two shapes:
 * <ol>
 *   <li>List of strings:  {@code "roles": ["admin", "player"]}</li>
 *   <li>List of role objects (default):
 *       {@code "roles": [{"name": "admin", ...}, {"name": "player", ...}]}</li>
 * </ol>
 * Both shapes are handled. Empty / blank entries are skipped silently so a
 * partially-populated role object doesn't introduce a phantom {@code ROLE_}
 * authority.
 */
public final class Roles {

    private Roles() {}

    /** Returns every role name carried by the JWT, upper-cased and trimmed. Empty
     *  list if the claim is missing. */
    public static List<String> fromJwt(Jwt jwt) {
        List<String> out = new ArrayList<>();
        if (jwt == null) return out;
        Object claim = jwt.getClaim("roles");
        if (claim instanceof Collection<?> list) {
            for (Object item : list) {
                String name = roleNameOf(item);
                if (!name.isBlank()) out.add(name.toUpperCase());
            }
        }
        return out;
    }

    /** True iff {@code roleName} (case-insensitive) is present in the JWT's roles claim. */
    public static boolean has(Jwt jwt, String roleName) {
        if (jwt == null || roleName == null) return false;
        String want = roleName.trim().toUpperCase();
        for (String r : fromJwt(jwt)) if (r.equals(want)) return true;
        return false;
    }

    public static boolean isAdmin(Jwt jwt) {
        if (jwt == null) return false;
        if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) return true;
        return has(jwt, "ADMIN");
    }

    /** True iff the principal carries the infra super-role {@code SUPERADMIN}.
     *  The ONLY role exempt from per-domain scoping — SUPERADMIN reaches every
     *  surface in every brand (the infra control plane). Both hyphen and underscore
     *  spellings of the Casdoor role name match. */
    public static boolean isSuperadmin(Jwt jwt) {
        return has(jwt, "SUPERADMIN") || has(jwt, "SUPER-ADMIN") || has(jwt, "SUPER_ADMIN");
    }

    /** True iff the principal may build mesh-WORKLOAD images. Granted to trusted
     *  per-domain admins as a separate capability (NOT an admin default); SUPERADMIN
     *  reaches the build surface via the cross-domain bypass. Both hyphen and
     *  underscore spellings match (the converter upper-cases the raw Casdoor role
     *  name without stripping its separator). */
    public static boolean isImageBuilder(Jwt jwt) {
        return has(jwt, "IMAGE-BUILDER") || has(jwt, "IMAGE_BUILDER");
    }

    /** True iff the principal carries the {@code SUPERADMIN} super-role, read from
     *  the already-converted Spring authorities ({@code ROLE_SUPERADMIN}) — the form
     *  a caller holding only authorities (no {@link Jwt}) can read. SUPERADMIN sees
     *  ALL domains (no domain predicate applied). */
    public static boolean isSuperadmin(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) return false;
        for (GrantedAuthority a : authorities) {
            String s = a.getAuthority();
            if ("ROLE_SUPERADMIN".equals(s) || "ROLE_SUPER-ADMIN".equals(s)
                    || "ROLE_SUPER_ADMIN".equals(s)) {
                return true;
            }
        }
        return false;
    }

    /** The brand/domain this principal is scoped to, derived from the token ISSUER
     *  (per-brand Casdoor =&gt; distinct {@code iss}) through the SAME registry the
     *  converter uses. Returns {@code "default"} for the single-issuer fallback so
     *  single-issuer clusters keep one domain, and (defensively) when {@code jwt}/
     *  {@code registry} is null. A {@code null} from the registry (unknown issuer in
     *  multi-brand mode) is surfaced as-is so the caller can fail closed. */
    public static String domainOf(Jwt jwt, DomainRegistry registry) {
        if (jwt == null || registry == null) return DomainRegistry.DEFAULT_DOMAIN;
        return registry.domainOf(jwt.getIssuer() == null ? null : jwt.getIssuer().toString());
    }

    /** Domain carried on the already-converted authorities ({@code DOMAIN_<x>}) —
     *  the form a caller holding only Spring authorities (no registry) can read.
     *
     *  <p>FAIL-CLOSED on an ambiguous authority set: the canonical converter
     *  ({@code CasdoorAuthorities}) stamps EXACTLY ONE issuer-derived
     *  {@code DOMAIN_<x>}, so any other count is anomalous —
     *  <ul>
     *    <li>ZERO {@code DOMAIN_} authorities (a hand-built / pre-converter token) —
     *        we can't prove a tenant, so return {@code null}.</li>
     *    <li>MORE THAN ONE {@code DOMAIN_} authority — an INJECTION signature (e.g.
     *        a forged {@code permissions:["DOMAIN_brandy"]} alongside the genuine
     *        issuer {@code DOMAIN_brandx}); never pick the first, return
     *        {@code null}.</li>
     *  </ul>
     *  The converter's reserved-prefix guard already prevents an injected
     *  {@code DOMAIN_} from ever appearing; this overload simply refuses to be a
     *  spoofable side channel. Prefer {@link #domainOf(Jwt, DomainRegistry)}
     *  (issuer-keyed) where a {@link Jwt} is in hand. */
    public static String domainOf(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) return null;                       // fail-closed
        String found = null;
        for (GrantedAuthority a : authorities) {
            String s = a.getAuthority();
            if (s != null && s.startsWith("DOMAIN_")) {
                if (found != null) return null;                     // >1 DOMAIN_ -> injection, fail-closed
                found = s.substring("DOMAIN_".length());
            }
        }
        return found;                                               // null when ZERO DOMAIN_ -> fail-closed
    }

    private static String roleNameOf(Object item) {
        if (item == null) return "";
        if (item instanceof String s) return s.trim();
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s.trim();
        }
        return "";
    }
}
