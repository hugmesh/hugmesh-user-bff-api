package net.hugmesh.userbff.security;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.Roles;
import net.hugmesh.commons.tenancy.DomainScope;

/**
 * Resolves the EFFECTIVE domain-scope for a request principal — the single place a
 * controller turns a validated {@link Jwt} into the {@code domain} string the
 * service/repo layer scopes on.
 *
 * <p>Two outcomes:
 * <ul>
 *   <li>SUPERADMIN (the cross-domain infra super-role, read from the validated
 *       {@code roles} claim) ⇒ {@code null} — the {@link DomainScope} bypass: the
 *       service applies NO domain predicate, so SUPERADMIN sees/mutates every brand's
 *       rows;</li>
 *   <li>any other principal ⇒ the concrete {@code DOMAIN_<x>} derived from the
 *       token's cryptographically-validated ISSUER (per-brand Casdoor → distinct
 *       {@code iss}) through the SAME {@link DomainRegistry} the converter used. A
 *       single-issuer cluster resolves {@code "default"} for everyone, so behaviour
 *       is unchanged.</li>
 * </ul>
 *
 * <p>The domain is NEVER read from a request field — it comes only from the issuer,
 * so a caller cannot forge a cross-tenant scope. This sits ABOVE owner-enforcement
 * (owner == JWT subject), which the services apply independently; a non-SUPERADMIN
 * principal must satisfy BOTH.
 */
@Component
public class PrincipalDomain {

    private final DomainRegistry registry;

    public PrincipalDomain(DomainRegistry registry) {
        this.registry = registry;
    }

    /**
     * The domain to scope this principal's queries to: {@code null} for SUPERADMIN
     * (cross-domain bypass), else the issuer-derived {@code DOMAIN_<x>}.
     *
     * <p>FAIL-CLOSED for a non-SUPERADMIN whose issuer the registry can't resolve
     * (unknown issuer in multi-brand mode → {@code null} from the registry): we
     * substitute a sentinel that can match NO row ({@code __deny__}) rather than the
     * {@code null} bypass, so an unresolved issuer denies rather than escalates. In
     * single-issuer mode the registry always resolves {@code "default"}, so this
     * sentinel never fires there.
     */
    public String forScope(Jwt jwt) {
        if (Roles.isSuperadmin(jwt)) {
            return null;                       // SUPERADMIN cross-domain bypass
        }
        String domain = Roles.domainOf(jwt, registry);
        // A non-SUPERADMIN with an unresolved issuer must FAIL CLOSED, never inherit
        // the null (=bypass) sentinel. A non-matchable domain denies all rows.
        return domain == null ? "__deny__" : domain;
    }
}
