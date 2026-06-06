package systems.snapdragon.userbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * User BFF — the ROLE_USER-floor "Best Friends Forever" backend paired with the
 * future {@code snapdragon-user-ui} (built later, NOT here). Every endpoint is
 * owner-scoped to the caller's Casdoor JWT subject — a user can only ever read /
 * write their OWN profile, preferences, cards (federation bundles), and
 * self-blocks. Surfaces:
 *
 * <ul>
 *   <li>PROFILE  — own R2DBC {@code user_profile}; password/email changes go to
 *       the Casdoor IdP via {@code CasdoorUserClient}.</li>
 *   <li>PREFERENCES — own R2DBC {@code user_preference}; per-role home-guide
 *       dismissal so each role's getting-started guide shows only on first visit.</li>
 *   <li>CARDS    — CRUD over the caller's OWN federation bundles (reactive
 *       WebClient to snapdragon-federation-api, forwarding the caller JWT).</li>
 *   <li>SELF-BLOCK — own R2DBC {@code user_block} + reactive Matrix/Mastodon
 *       clients to push the external mute/block (external call STUBBED).</li>
 *   <li>RECOMMEND-INSTANCE-BLOCK — POST federation-api /moderation kind=
 *       instance-block (status set to recommended server-side) — the chain start
 *       of USER -> MOD -> ADMIN instance blocking.</li>
 * </ul>
 *
 * <p>(Eureka client auto-activates from spring-cloud-starter-netflix-eureka-client
 * on the classpath but is off by default — opt-in via the {@code eureka} profile.)
 */
@SpringBootApplication
public class UserBffApplication {
    public static void main(String[] args) { SpringApplication.run(UserBffApplication.class, args); }
}
