package systems.hugmesh.userbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * User BFF — the ROLE_USER-floor backend paired with the future
 * {@code hugmesh-user-ui} (built later, NOT here). Every endpoint is
 * owner-scoped to the caller's Casdoor JWT subject — a user can only ever read /
 * write their OWN profile, preferences, cards (federation bundles), and
 * self-blocks. Surfaces:
 *
 * <ul>
 *   <li>PROFILE  — own R2DBC {@code user_profile}; password/email changes go to
 *       the Casdoor IdP via {@code CasdoorUserClient}.</li>
 *   <li>PREFERENCES — own R2DBC {@code user_preference}; per-guide home-guide
 *       dismissal so each role's getting-started guide shows only on first visit.</li>
 *   <li>CARDS    — CRUD over the caller's OWN federation bundles (reactive
 *       WebClient to hugmesh-federation-api, forwarding the caller JWT).</li>
 *   <li>SELF-BLOCK — own R2DBC {@code user_block} + reactive Matrix/Mastodon
 *       clients to push the external mute/block (external call STUBBED).</li>
 *   <li>RECOMMEND-INSTANCE-BLOCK — POST federation-api /moderation kind=
 *       instance-block (status set to recommended server-side) — the chain start
 *       of USER -&gt; MOD -&gt; ADMIN instance blocking.</li>
 *   <li>SELF-SILENCE — own R2DBC {@code self_silence}: a self-service visibility
 *       hide (profile 404 + homeserver discovery hide) that is DISTINCT from a ban
 *       (no role/suspension/revocation write); a {@code @Scheduled} wake auto-clears
 *       it at {@code expires_at}.</li>
 * </ul>
 *
 * <p>{@code @EnableScheduling} powers the {@code SelfSilenceExpiryAction} wake.
 */
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@SpringBootApplication
@EnableScheduling
public class UserBffApplication {
    public static void main(String[] args) { SpringApplication.run(UserBffApplication.class, args); }
}
