package net.hugmesh.userbff.auth;

import java.time.Clock;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;

import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the Google/Discord sign-in (hugmesh-generator#1107). SHIPS DARK: with
 * {@code app.bff.oauth.enabled=false} (the default) {@link OAuthSettings} offers no provider
 * on any host, so {@code /bff/oauth/providers} answers an empty list and {@code /start}
 * refuses. Going live needs, in addition: the OIDC surface on ({@code app.bff.oidc.enabled}),
 * the custody key (it seals the state cookie), each provider's client id and secret (the same
 * OAuth client the Casdoor provider of that name uses), the per-domain method list written by
 * provisioning, and {@code casdoor.account.enabled} (the invite leg creates the account).
 */
@Configuration
public class OAuthConfig {

    private static final Logger log = LoggerFactory.getLogger(OAuthConfig.class);

    @Bean
    public OAuthSettings oauthSettings(
            @Value("${app.bff.oauth.enabled:false}") boolean enabled,
            @Value("${app.bff.oauth.state-ttl:PT10M}") Duration stateTtl,
            @Value("${app.bff.oauth.google.client-id:}") String googleId,
            @Value("${app.bff.oauth.google.client-secret:}") String googleSecret,
            @Value("${app.bff.oauth.discord.client-id:}") String discordId,
            @Value("${app.bff.oauth.discord.client-secret:}") String discordSecret,
            @Value("${app.bff.oauth.domain-methods:}") String domainMethods) {
        Map<OAuthProvider, OAuthSettings.Client> clients = new EnumMap<>(OAuthProvider.class);
        clients.put(OAuthProvider.GOOGLE, new OAuthSettings.Client(googleId, googleSecret));
        clients.put(OAuthProvider.DISCORD, new OAuthSettings.Client(discordId, discordSecret));
        OAuthSettings s = new OAuthSettings(enabled, stateTtl, clients, domainMethods);
        log.info("[oauth] Google/Discord sign-in {} (google configured={}, discord configured={})",
                enabled ? "ENABLED" : "dark (app.bff.oauth.enabled=false)",
                s.client(OAuthProvider.GOOGLE).isPresent(), s.client(OAuthProvider.DISCORD).isPresent());
        return s;
    }

    @Bean
    public OAuthStateCodec oauthStateCodec(BffCustodyCipher cipher) {
        return new OAuthStateCodec(cipher, Clock.systemUTC());
    }

    @Bean
    public OAuthIdentityClient oauthIdentityClient() {
        return new OAuthIdentityClient(WebClient.builder().build());
    }
}
