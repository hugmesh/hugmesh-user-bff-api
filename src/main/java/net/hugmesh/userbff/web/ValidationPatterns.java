package net.hugmesh.userbff.web;

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

    /** A durable preferences-store key (the {@code user_preferences_store.pref_key}):
     *  dotted/alnum/hyphen segments, e.g. {@code media.poison.default}. Bounded to
     *  the varchar(128) column; starts/ends with an alnum so it can't be blank or a
     *  bare separator, and carries no whitespace/quotes so it stays a safe key. */
    public static final String PREF_STORE_KEY = "^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$";

    /** A Meshtastic LoRa radio node id as CLAIMED (pre-normalization): exactly 8 hex
     *  digits with an OPTIONAL {@code !} prefix, ANY case ({@code a1b2c3d4} /
     *  {@code !A1B2C3D4} both accepted). The service canonicalizes to
     *  {@code "!" + lowercase} BEFORE storage; the 019
     *  {@code ck_mesh_device_node_id} CHECK ({@code ^![0-9a-f]{8}$}) is the DB parity
     *  for the CANONICAL stored form, so this API pattern is deliberately the
     *  looser accept-then-normalize shape. */
    public static final String MESH_NODE_ID = "^!?[0-9a-fA-F]{8}$";

    /** mesh_device.visibility — mirrors the 019 CHECK + MeshDevice.validVisibility. */
    public static final String MESH_VISIBILITY = "^(private|friends|channels)$";

    /** mesh_device.state — mirrors the 019 CHECK + MeshDevice.validState. The
     *  moderation console's {@code ?state=} filter validates against it (an OMITTED
     *  filter means "both states", so the empty string is deliberately accepted). */
    public static final String MESH_STATE = "^(active|revoked)?$";
}
