package systems.snapdragon.userbff.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Single source of truth for the BFF's Casdoor JWT -&gt; Spring authorities mapping,
 * so the single-issuer ({@code SecurityConfig}) and the optional multi-issuer
 * ({@code TenancyResourceServerConfig}) decoder paths emit BYTE-IDENTICAL
 * authorities. COPIED VERBATIM (logic) from the adversarially-verified-safe
 * snapdragon-gateway {@code systems.snapdragon.gateway.config.CasdoorAuthorities}
 * (package adjusted). Keeping one converter avoids the half-migration pitfall where
 * one path silently drops the {@code DOMAIN_<x>} authority.
 *
 * <p>Three claim sources, in precedence:
 * <ol>
 *   <li>{@code roles} array (strings OR objects with a {@code name} field —
 *       Casdoor's default token shape) -&gt; {@code ROLE_<UPPER>}.</li>
 *   <li>{@code permissions} array -&gt; verbatim (non-prefixed) authorities, EXCEPT
 *       any entry whose value starts with a RESERVED prefix ({@code ROLE_} /
 *       {@code DOMAIN_}) is dropped — those authorities come ONLY from controlled
 *       logic, never from a user-influenced permission string (authority-injection
 *       defense; see {@code RESERVED_PREFIXES}).</li>
 *   <li>{@code isAdmin} boolean (legacy) -&gt; {@code ROLE_ADMIN}.</li>
 * </ol>
 * Every authenticated principal floors to {@code ROLE_USER} and is stamped with
 * exactly one issuer-derived {@code DOMAIN_<x>} authority.
 */
public final class CasdoorAuthorities {

    private CasdoorAuthorities() {}

    /**
     * Authority prefixes RESERVED for the converter's own controlled logic and
     * therefore NEVER allowed to originate from a user-influenced claim string:
     * <ul>
     *   <li>{@code ROLE_} — emitted ONLY from the {@code roles} claim (each role name
     *       upper-cased and prefixed here) and the legacy {@code isAdmin} boolean. A
     *       verbatim {@code permissions} entry must never become a {@code ROLE_*}
     *       authority.</li>
     *   <li>{@code DOMAIN_} — emitted ONLY from the cryptographically-validated
     *       issuer (exactly one, added last). A verbatim {@code permissions} entry
     *       must never forge a {@code DOMAIN_*} tenant scope, and a {@code roles}
     *       entry cannot either (it always gains the {@code ROLE_} prefix first, so
     *       {@code "DOMAIN_x" -> "ROLE_DOMAIN_X"}, which is an inert non-tenant
     *       authority).</li>
     * </ul>
     * SECURITY: without this filter a brand-X token carrying
     * {@code permissions:["DOMAIN_brandy"]} or {@code permissions:["ROLE_SUPERADMIN"]}
     * would inject a forged tenant scope / super-role and escalate cross-domain.
     */
    private static final String[] RESERVED_PREFIXES = {"ROLE_", "DOMAIN_"};

    private static boolean isReserved(String authority) {
        String upper = authority.trim().toUpperCase();
        for (String prefix : RESERVED_PREFIXES) {
            if (upper.startsWith(prefix)) return true;
        }
        return false;
    }

    /** Build the converter bound to the given {@link DomainRegistry} (used to resolve
     *  the issuer -&gt; {@code DOMAIN_<x>} authority). */
    public static Converter<Jwt, Flux<GrantedAuthority>> converter(DomainRegistry domainRegistry) {
        return jwt -> Flux.fromIterable(authorities(jwt, domainRegistry));
    }

    /** Compute the authority list for a token (the pure mapping, exposed for reuse +
     *  unit testing). */
    public static List<GrantedAuthority> authorities(Jwt jwt, DomainRegistry domainRegistry) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // floor — UNCHANGED

        Object rolesClaim = jwt.getClaim("roles");
        if (rolesClaim instanceof Collection<?> list) {
            for (Object r : list) {
                String name = roleNameOf(r);
                if (!name.isBlank()) {
                    // Always ROLE_-prefixed, so a roles entry can NEVER inject a
                    // DOMAIN_ authority: "DOMAIN_x" -> "ROLE_DOMAIN_X" (inert,
                    // non-tenant). See RESERVED_PREFIXES.
                    authorities.add(new SimpleGrantedAuthority(
                            "ROLE_" + name.trim().toUpperCase()));
                }
            }
        }

        Object permsClaim = jwt.getClaim("permissions");
        if (permsClaim instanceof Collection<?> list) {
            for (Object p : list) {
                if (p == null) continue;
                String perm = p.toString().trim();
                if (perm.isEmpty()) continue;
                // RESERVED-PREFIX GUARD (authority-injection defense). A verbatim
                // permission string MUST NOT carry the ROLE_ or DOMAIN_ prefix —
                // those authorities come ONLY from the converter's controlled logic
                // (roles-claim -> ROLE_<UPPER>; validated issuer -> DOMAIN_<x>).
                // Skipping such entries stops a brand-X token carrying
                // permissions:["DOMAIN_brandy"] (forged tenant scope) or
                // permissions:["ROLE_SUPERADMIN"] (forged super-role) from
                // escalating cross-domain. See RESERVED_PREFIXES.
                if (isReserved(perm)) continue;
                authorities.add(new SimpleGrantedAuthority(perm));
            }
        }

        if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        // Domain authority — keyed on the cryptographically-validated ISSUER
        // (per-brand Casdoor => distinct iss). NEVER a user-settable claim.
        // DOMAIN_<x> is a NON-role authority (no ROLE_ prefix) so it can never
        // satisfy a hasRole()/route-access role check by accident. A null from the
        // registry (unknown issuer) defensively maps to "default" rather than
        // emitting "DOMAIN_null".
        String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
        String domain = domainRegistry.domainOf(issuer);
        if (domain == null) domain = DomainRegistry.DEFAULT_DOMAIN;
        authorities.add(new SimpleGrantedAuthority("DOMAIN_" + domain));

        return authorities;
    }

    private static String roleNameOf(Object item) {
        if (item instanceof String s) return s;
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s;
        }
        return "";
    }
}
