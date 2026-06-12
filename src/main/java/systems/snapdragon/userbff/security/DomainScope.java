package systems.snapdragon.userbff.security;

import org.springframework.r2dbc.core.DatabaseClient;

/**
 * The optional {@code domain = :domain} predicate every owner-keyed repository
 * appends to scope a read/mutation to the caller's tenant — the data-layer half of
 * the multi-brand isolation boundary.
 *
 * <p><b>Convention.</b> The service layer resolves the principal's domain from the
 * validated token issuer ({@link Roles#domainOf(org.springframework.security.oauth2.jwt.Jwt,
 * DomainRegistry)}) and passes it down:
 * <ul>
 *   <li>a NON-null {@code domain} ⇒ the SQL gains {@code AND domain = :domain} and
 *       binds it, so the caller only ever touches rows in their OWN brand;</li>
 *   <li>a {@code null} {@code domain} ⇒ NO predicate is added — this is the SUPERADMIN
 *       (cross-domain infra super-role) bypass: SUPERADMIN sees/mutates every brand's
 *       rows. The service decides this (it passes {@code null} only for a SUPERADMIN
 *       principal); a non-SUPERADMIN caller is ALWAYS passed its concrete domain.</li>
 * </ul>
 *
 * <p>Domain is ALWAYS an ADDITIONAL predicate alongside the existing
 * {@code owner = :uid} one — it never replaces or weakens owner-enforcement
 * (owner == JWT subject). A non-SUPERADMIN principal must satisfy BOTH owner AND
 * domain.
 */
public final class DomainScope {

    private DomainScope() {}

    /** The named bind parameter for the domain predicate. */
    public static final String PARAM = "domain";

    /**
     * The SQL fragment to splice into a WHERE clause for the given domain:
     * {@code " AND domain = :domain"} when {@code domain} is non-null/blank, else the
     * empty string (SUPERADMIN cross-domain bypass — no predicate).
     */
    public static String andPredicate(String domain) {
        return isUnscoped(domain) ? "" : " AND domain = :" + PARAM;
    }

    /** Bind the domain parameter onto a spec IFF a domain predicate was added (i.e.
     *  {@code domain} is non-null/blank). A no-op for the SUPERADMIN bypass so the
     *  bound-parameter set always matches the SQL exactly (an unbound {@code :domain}
     *  in non-bypass SQL, or a bound-but-unused param in bypass SQL, both throw). */
    public static DatabaseClient.GenericExecuteSpec bind(
            DatabaseClient.GenericExecuteSpec spec, String domain) {
        return isUnscoped(domain) ? spec : spec.bind(PARAM, domain);
    }

    /** True iff the domain represents the SUPERADMIN cross-domain bypass (null/blank
     *  ⇒ no predicate). */
    public static boolean isUnscoped(String domain) {
        return domain == null || domain.isBlank();
    }
}
