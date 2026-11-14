package net.hugmesh.userbff.auth;

import java.util.Locale;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * user-bff's OWN exchange with Google or Discord, used ONLY on the sign-up leg of
 * hugmesh-generator#1107: before any account exists, user-bff must learn who the person is
 * (the provider's immutable id and a VERIFIED email) to check the invite. Sign-in never uses
 * it: Casdoor does that exchange itself, so MFA and the account link stay Casdoor's.
 *
 * <p>The provider's tokens are used for one userinfo call and dropped; they are never stored,
 * logged or returned.
 */
public class OAuthIdentityClient {

    /**
     * Who the provider says this is. {@code id} is immutable (Google {@code sub}, Discord user
     * id); {@code email} is lowercased and present only when the provider marks it verified;
     * {@code username} is Discord's current username (empty for Google).
     */
    public record Identity(String id, String email, String username) {
        public boolean hasVerifiedEmail() {
            return email != null && !email.isBlank();
        }
    }

    private static final ParameterizedTypeReference<Map<String, Object>> JSON =
            new ParameterizedTypeReference<>() {};

    private final WebClient http;

    public OAuthIdentityClient(WebClient http) {
        this.http = http;
    }

    /** Exchange {@code code} (issued for {@code redirectUri}) and read the identity. */
    public Mono<Identity> identify(OAuthProvider provider, OAuthSettings.Client client,
                                   String code, String redirectUri) {
        return http.post().uri(provider.tokenUrl())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                        .with("code", code)
                        .with("redirect_uri", redirectUri)
                        .with("client_id", client.clientId())
                        .with("client_secret", client.clientSecret()))
                .retrieve()
                .bodyToMono(JSON)
                .flatMap(token -> {
                    Object access = token.get("access_token");
                    if (access == null || access.toString().isBlank()) {
                        return Mono.error(new IllegalStateException(
                                provider.id() + " returned no access token"));
                    }
                    return http.get().uri(provider.userinfoUrl())
                            .headers(h -> h.setBearerAuth(access.toString()))
                            .accept(MediaType.APPLICATION_JSON)
                            .retrieve()
                            .bodyToMono(JSON);
                })
                .map(info -> parse(provider, info));
    }

    /** The provider's userinfo body -> an {@link Identity}; unverified emails are dropped. */
    static Identity parse(OAuthProvider provider, Map<String, Object> info) {
        String email = str(info.get("email")).toLowerCase(Locale.ROOT);
        return switch (provider) {
            case GOOGLE -> new Identity(str(info.get("sub")),
                    truthy(info.get("email_verified")) ? email : "", "");
            case DISCORD -> new Identity(str(info.get("id")),
                    truthy(info.get("verified")) ? email : "",
                    str(info.get("username")).toLowerCase(Locale.ROOT));
        };
    }

    private static boolean truthy(Object o) {
        return Boolean.TRUE.equals(o) || "true".equalsIgnoreCase(String.valueOf(o));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}
