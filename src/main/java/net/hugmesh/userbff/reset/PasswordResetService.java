package net.hugmesh.userbff.reset;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

/**
 * The POLICY layer of the anonymous forgot-password flow — everything that must be
 * decided BEFORE, and INDEPENDENTLY of, what Casdoor happens to answer.
 *
 * <p>{@link CasdoorPasswordResetClient} is a faithful transport: it reports refusals
 * exactly as Casdoor gives them. That faithfulness is what makes this class necessary,
 * because Casdoor's answers must NOT reach an anonymous browser verbatim.
 *
 * <h2>1. The request leg is an ENUMERATION ORACLE unless it is flattened</h2>
 *
 * <p>{@code POST /api/send-verification-code} refuses an unknown user and accepts a known
 * one. Passed through, that turns this permitAll endpoint into a membership oracle for
 * the whole mesh: anyone could confirm whether {@code alice} has an account by watching
 * the status code. {@link #request} therefore ALWAYS resolves successfully once the input
 * is well-formed, whatever Casdoor said — the caller ({@link PasswordResetController})
 * answers a fixed 202 with a fixed body, so a registered and an unregistered username are
 * byte-identical to the browser.
 *
 * <p>The refusal is not DISCARDED — the client already logged it at WARN, which is where
 * an operator can see it and an attacker cannot.
 *
 * <p><b>The DARK 503 is deliberately NOT flattened.</b> "This mesh has no password reset"
 * is a fact about the SERVICE, identical for every visitor, and reveals nothing about any
 * account; masking it would strand a locked-out user retrying a flow that can never
 * complete. So {@link ApiException#serviceUnavailable} propagates and nothing else does.
 *
 * <h2>2. The confirm leg must not distinguish WHY it failed</h2>
 *
 * <p>"No such user", "wrong code" and "expired code" are three different Casdoor messages
 * and ONE answer here. Passing them through would rebuild the oracle the request leg just
 * closed, and would additionally tell an attacker holding a stolen code whether the
 * username half of their guess was right.
 *
 * <p><b>Casdoor's message is never inspected to make that decision.</b> An earlier draft
 * of this class tried to let PASSWORD-POLICY refusals through by substring-matching
 * Casdoor's wording — which is unsound in both directions: the platform's own documented
 * wrong-code message is {@code "password or code is incorrect, you have N remaining
 * chances"} (see {@code CasdoorUserClient}'s javadoc), so matching on "password" would
 * have leaked exactly the code-refusal it was meant to hide. Instead, the only
 * password-quality rule stated to the user is one THIS service enforces itself
 * ({@link #minPasswordLength}) BEFORE any Casdoor call — actionable, and about the string
 * the user just typed rather than about any account. Everything Casdoor refuses collapses
 * to {@link #RESET_REFUSED}, whose wording names BOTH remaining possibilities so a user
 * hitting a stricter org policy is not told a lie about their code.
 */
@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    /**
     * The ONE answer every Casdoor-refused confirm gets. It names both surviving causes
     * (code, and org password policy) precisely because the service refuses to work out
     * which — an honest "one of these two" beats a confident wrong guess, and beats a
     * bare "invalid" that sends a user with a perfectly good code round the loop again.
     */
    private static final String RESET_REFUSED =
            "we could not complete that reset — the code may have expired or already been "
                    + "used, or the new password may not meet this mesh's password policy";

    private final CasdoorPasswordResetClient casdoor;

    /** The ONLY password-quality rule this service states to the user, enforced locally
     *  so the message can be specific without consulting (or leaking) Casdoor. Casdoor's
     *  org policy remains authoritative and may be stricter; that case is covered by the
     *  second clause of {@link #RESET_REFUSED}. */
    private final int minPasswordLength;

    public PasswordResetService(CasdoorPasswordResetClient casdoor,
                                @Value("${casdoor.password-reset.min-password-length:8}")
                                int minPasswordLength) {
        this.casdoor = casdoor;
        this.minPasswordLength = minPasswordLength;
    }

    /** Whether the live reset path is wired (vs. dark). */
    public boolean enabled() { return casdoor.enabled(); }

    /**
     * Leg 1 — ask Casdoor to mail a one-time code to whatever address it holds for
     * {@code username}. Resolves EMPTY for both "code sent" and "no such user"; see the
     * class javadoc for why that flattening is the security property, not a shortcut.
     * A 503 (dark) is the only outcome allowed through.
     */
    public Mono<Void> request(String username) {
        String name = requireUsername(username);
        return casdoor.sendResetCode(name)
                .onErrorResume(t -> isDark(t)
                        // Service-level fact, identical for everyone → tell the truth.
                        ? Mono.error(t)
                        // Account-level fact → swallow. Already WARN-logged by the client;
                        // this DEBUG line records that the swallow HAPPENED, so an operator
                        // reading logs sees a decision rather than a silence. The username
                        // is deliberately absent: it is attacker-supplied and unvalidated.
                        : Mono.<Void>fromRunnable(() -> log.debug(
                                "[password-reset] request refused by Casdoor — answering 202 "
                                        + "anyway (enumeration guard)")));
    }

    /**
     * Leg 2 — redeem the mailed code and set the new password. Casdoor verifies the code
     * itself, so this BFF never stores, compares, or is trusted with it.
     *
     * <p>Order matters: the LOCAL validations run first, so a caller who typed a too-short
     * password is told so without a Casdoor round-trip AND without burning their one-time
     * code on a request that was never going to succeed.
     */
    public Mono<Void> confirm(String username, String code, String newPassword) {
        String name = requireUsername(username);
        if (code == null || code.isBlank()) {
            return Mono.error(ApiException.badRequest("code required"));
        }
        if (newPassword == null || newPassword.isBlank()) {
            return Mono.error(ApiException.badRequest("newPassword required"));
        }
        if (newPassword.length() < minPasswordLength) {
            return Mono.error(ApiException.badRequest(
                    "newPassword must be at least " + minPasswordLength + " characters"));
        }
        return casdoor.resetPassword(name, code, newPassword)
                .onErrorMap(t -> !isDark(t), t -> ApiException.badRequest(RESET_REFUSED));
    }

    /** A dark-surface 503 — the one refusal that is about the service, not an account. */
    private static boolean isDark(Throwable t) {
        return t instanceof ApiException api && api.status() == HttpStatus.SERVICE_UNAVAILABLE;
    }

    /** The username is the ADDRESS of the IdP call — fail closed, never blank. */
    private static String requireUsername(String username) {
        String name = username == null ? "" : username.trim();
        if (name.isEmpty()) {
            throw ApiException.badRequest("username required");
        }
        return name;
    }
}
