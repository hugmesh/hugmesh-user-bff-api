package systems.snapdragon.userbff.web;

/**
 * Shared regex / size constants for jakarta Bean Validation across the user-BFF
 * controllers + request DTOs. Centralised so the API-level validation stays in
 * lock-step with the DB column types / CHECK vocabularies (the security-hardening
 * API&lt;-&gt;DB parity audit):
 *
 * <ul>
 *   <li>{@link #VISIBILITY} — {@code public|internal}; mirrors the 005
 *       {@code user_profile.visibility} CHECK.</li>
 *   <li>{@link #PLATFORM} — {@code matrix|mastodon|internal}; mirrors the 005
 *       {@code user_block.platform} CHECK + {@code UserBlock.validPlatform}.</li>
 *   <li>{@link #SLUG} — DNS-label-style card slug (matches the federation-api
 *       {@code user_modules.slug} the BFF proxies to).</li>
 *   <li>{@link #BLOCK_ID} — the app-generated UUID a {@code user_block} row is
 *       keyed by (the {@code DELETE /blocks/{id}} path variable).</li>
 *   <li>{@link #PREF_KEY_SEGMENT} — a guide name (the {@code guide} request param);
 *       a safe key segment, no separators that could break the composite pref key.</li>
 * </ul>
 */
public final class ValidationPatterns {

    private ValidationPatterns() {}

    /** user_profile.visibility — mirrors the 005 CHECK. */
    public static final String VISIBILITY = "^(public|internal)$";

    /** user_block.platform — mirrors the 005 CHECK + UserBlock.validPlatform. */
    public static final String PLATFORM = "^(matrix|mastodon|internal)$";

    /** DNS-label-style card slug: lower-alnum + internal hyphens, 1-128 chars. */
    public static final String SLUG = "^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$";

    /** A user_block UUID (app-generated, varchar(64) PK). */
    public static final String BLOCK_ID =
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    /** A guide name / pref-key segment: alnum + hyphen, 1-64 chars (no ':' so it
     *  can't smuggle a second key segment into the composite preference key). */
    public static final String PREF_KEY_SEGMENT = "^[A-Za-z0-9][A-Za-z0-9-]{0,63}$";
}
