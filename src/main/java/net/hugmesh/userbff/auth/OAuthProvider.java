package net.hugmesh.userbff.auth;

import java.util.Locale;
import java.util.Optional;

/**
 * The third-party sign-in providers user-bff can run (hugmesh-generator#1107): Google and
 * Discord. Each names its public OAuth endpoints, the scope it asks for, the name of the
 * matching Casdoor provider (seeded by the generator's casdoor init-job), and the Casdoor
 * {@code User} field that links an account to the provider's immutable id
 * ({@code user.google} = Google {@code sub}, {@code user.discord} = Discord user id).
 *
 * <p>The endpoints are the providers' own, documented ones; they are constants, never read
 * from a request, so a caller cannot point the exchange anywhere else.
 */
public enum OAuthProvider {

    GOOGLE("google", "google", "google",
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
            "openid email profile"),

    DISCORD("discord", "discord", "discord",
            "https://discord.com/oauth2/authorize",
            "https://discord.com/api/oauth2/token",
            "https://discord.com/api/users/@me",
            "identify email");

    /** The path segment and the sign-in method name ({@code /bff/oauth/google/...}). */
    private final String id;
    /** The Casdoor provider's {@code name} (the init-job seeds {@code google}/{@code discord}). */
    private final String casdoorProvider;
    /** The Casdoor {@code User} JSON field that holds the provider's id for a linked account. */
    private final String casdoorUserField;
    private final String authorizeUrl;
    private final String tokenUrl;
    private final String userinfoUrl;
    private final String scope;

    OAuthProvider(String id, String casdoorProvider, String casdoorUserField, String authorizeUrl,
                  String tokenUrl, String userinfoUrl, String scope) {
        this.id = id;
        this.casdoorProvider = casdoorProvider;
        this.casdoorUserField = casdoorUserField;
        this.authorizeUrl = authorizeUrl;
        this.tokenUrl = tokenUrl;
        this.userinfoUrl = userinfoUrl;
        this.scope = scope;
    }

    public String id() {
        return id;
    }

    public String casdoorProvider() {
        return casdoorProvider;
    }

    public String casdoorUserField() {
        return casdoorUserField;
    }

    public String authorizeUrl() {
        return authorizeUrl;
    }

    public String tokenUrl() {
        return tokenUrl;
    }

    public String userinfoUrl() {
        return userinfoUrl;
    }

    public String scope() {
        return scope;
    }

    /** The provider named by a path segment, or empty for anything else. */
    public static Optional<OAuthProvider> byId(String id) {
        if (id == null) {
            return Optional.empty();
        }
        String want = id.trim().toLowerCase(Locale.ROOT);
        for (OAuthProvider p : values()) {
            if (p.id.equals(want)) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }
}
