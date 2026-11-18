package net.hugmesh.userbff.auth;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import net.hugmesh.authcore.casdoor.BffCustodyCipher;

/**
 * Binds a Google/Discord round trip to the browser that started it (hugmesh-generator#1107).
 *
 * <p>The provider redirects back with {@code ?code&state}. Casdoor's own state check only
 * compares the text before {@code -org-} with the application name, which is no CSRF
 * protection, so user-bff keeps the real binding: {@code /start} puts the state, the provider,
 * the phase, the host and an expiry into a short-lived HttpOnly cookie, sealed with the same
 * AES-256-GCM key as token custody (a tampered or foreign cookie does not decrypt). The
 * callback accepts the provider's {@code state} only when it equals the one sealed in the
 * cookie for the same provider and host, before the expiry.
 *
 * <p>The sealed text carries a purpose prefix, so a custody blob (an encrypted access token)
 * can never be replayed as a state cookie or the other way round.
 */
public class OAuthStateCodec {

    /** The cookie that carries the sealed state. Path-scoped to the OAuth routes. */
    public static final String COOKIE = "bff_oauth";
    public static final String COOKIE_PATH = "/bff/oauth";

    private static final String PURPOSE = "oauth-state/v1";
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Which leg a round trip is: sign in through Casdoor, or the invite check before it. */
    public enum Phase { SIGNIN, SIGNUP }

    /** One round trip. {@code state} also satisfies Casdoor's application-name prefix check. */
    public record State(OAuthProvider provider, Phase phase, String state, String host,
                        long expiresAtEpochSecond) {}

    private final BffCustodyCipher cipher;
    private final Clock clock;

    public OAuthStateCodec(BffCustodyCipher cipher, Clock clock) {
        this.cipher = cipher;
        this.clock = clock;
    }

    public boolean available() {
        return cipher != null && cipher.isAvailable();
    }

    /**
     * A fresh random state, prefixed so Casdoor's check
     * ({@code state.split("-org-")[0] == application}) passes for {@code application}.
     */
    public static String newState(String application) {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return application + "-org-" + Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public State issue(OAuthProvider provider, Phase phase, String application, String host,
                       java.time.Duration ttl) {
        return new State(provider, phase, newState(application), host,
                Instant.now(clock).plus(ttl).getEpochSecond());
    }

    /** The cookie value for {@code s} (URL-safe base64, no characters a cookie forbids). */
    public String seal(State s) {
        String plain = String.join("|", PURPOSE, s.provider().id(), s.phase().name(), s.state(),
                s.host(), Long.toString(s.expiresAtEpochSecond()));
        String std = cipher.encrypt(plain);
        return std.replace('+', '-').replace('/', '_').replace("=", "");
    }

    /**
     * The state sealed in {@code cookie}, or empty when it does not decrypt, is not a state
     * cookie, is malformed, or has expired.
     */
    public Optional<State> open(String cookie) {
        if (cookie == null || cookie.isBlank() || !available()) {
            return Optional.empty();
        }
        String std = cookie.replace('-', '+').replace('_', '/');
        int pad = (4 - std.length() % 4) % 4;
        String plain = cipher.decrypt(std + "=".repeat(pad));
        if (plain == null) {
            return Optional.empty();
        }
        String[] f = plain.split("\\|", -1);
        if (f.length != 6 || !PURPOSE.equals(f[0])) {
            return Optional.empty();
        }
        Optional<OAuthProvider> provider = OAuthProvider.byId(f[1]);
        Phase phase;
        long exp;
        try {
            phase = Phase.valueOf(f[2]);
            exp = Long.parseLong(f[5]);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (provider.isEmpty() || f[3].isBlank() || Instant.now(clock).getEpochSecond() > exp) {
            return Optional.empty();
        }
        return Optional.of(new State(provider.get(), phase, f[3], f[4], exp));
    }
}
