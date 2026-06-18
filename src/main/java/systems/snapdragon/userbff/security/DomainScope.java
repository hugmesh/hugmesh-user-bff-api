package systems.snapdragon.userbff.security;

/**
 * The multi-brand scoping decision every owner-keyed repository applies: whether a
 * read/mutation gains the {@code domain = :domain} tenant predicate or runs unscoped
 * (the SUPERADMIN cross-domain bypass) — the data-layer half of the multi-brand
 * isolation boundary.
 *
 * <p>Since the data access moved to Spring Data R2DBC repositories, the scoping is
 * expressed as a CHOICE between a domain-scoped derived/{@code @Query} finder and an
 * unscoped one (mirroring federation's {@code findBySlug} / {@code findBySlugAndDomain}
 * pair); each repository facade calls {@link #isUnscoped(String)} to pick the variant.
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

    /** True iff the domain represents the SUPERADMIN cross-domain bypass (null/blank
     *  ⇒ no predicate). */
    public static boolean isUnscoped(String domain) {
        return domain == null || domain.isBlank();
    }
}
