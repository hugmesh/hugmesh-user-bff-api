package systems.hugmesh.userbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The SERVER-SIDE Casdoor {@code /api/login} client — the heart of native login. The
 * browser posts only {@code {username, password}} to {@code POST /bff/login}; THIS client
 * verifies those credentials against Casdoor over the INTERNAL, in-cluster base
 * ({@code app.bff.oidc.login-base}, e.g. {@code http://casdoor:8000}) so Casdoor is NEVER
 * browser-exposed. It drives Casdoor's OIDC {@code type:"code"} login: the caller supplies
 * a server-generated PKCE {@code code_challenge} + {@code state}; on success Casdoor returns
 * a one-time authorization {@code code} which the caller then exchanges for tokens with the
 * matching {@code code_verifier}.
 *
 * <p><b>Response shapes handled</b> (Casdoor's {@code controllers.Response} envelope):
 * <ul>
 *   <li><b>success</b> — {@code {status:"ok", data:"<code>"}} ⇒ {@link CasdoorLoginResult#code};</li>
 *   <li><b>MFA required</b> — {@code {status:"ok", data:"NextMfa", data2:[{mfaType:..}, ..]}}
 *       ⇒ {@link CasdoorLoginResult#mfaRequired} carrying the enabled MFA types;</li>
 *   <li><b>error</b> — {@code {status:"error", msg:"<message>"}} (bad password, disabled user,
 *       wrong MFA passcode, …) ⇒ {@link CasdoorLoginResult#error} carrying Casdoor's message.</li>
 * </ul>
 *
 * <p>SHIPS DARK / fail-closed: when the OIDC surface is disabled
 * ({@code app.bff.oidc.enabled=false}) the {@link WebClient} is {@code null} and every call
 * errors — a disabled surface can never verify a credential or mint a session. The password
 * is sent ONLY to Casdoor over the internal base and is NEVER logged; the returned
 * authorization {@code code} is a one-time server-side secret and never reaches the browser.
 */
public class CasdoorLoginClient {

    private static final Logger log = LoggerFactory.getLogger(CasdoorLoginClient.class);

    /** Casdoor's sentinel {@code data} value signalling a second-factor challenge. */
    private static final String NEXT_MFA = "NextMfa";

    /** The outcome of a Casdoor {@code /api/login} call. Exactly one shape is populated. */
    public record CasdoorLoginResult(Kind kind, String code, List<String> mfaTypes, String message) {
        public enum Kind { CODE, MFA_REQUIRED, ERROR }

        // Copy on the way IN. The static factories below already pass an immutable list,
        // but the canonical constructor is public — so an arbitrary caller can hand in a
        // mutable one. Null is preserved; the accessor maps it to an empty list.
        public CasdoorLoginResult {
            mfaTypes = mfaTypes == null ? null : List.copyOf(mfaTypes);
        }

        /** Return a defensive copy so callers cannot mutate the internal list. */
        @Override
        public List<String> mfaTypes() {
            return mfaTypes == null ? List.of() : List.copyOf(mfaTypes);
        }

        static CasdoorLoginResult code(String code) {
            return new CasdoorLoginResult(Kind.CODE, code, List.of(), null);
        }

        static CasdoorLoginResult mfaRequired(List<String> mfaTypes) {
            return new CasdoorLoginResult(Kind.MFA_REQUIRED, null, List.copyOf(mfaTypes), null);
        }

        static CasdoorLoginResult error(String message) {
            return new CasdoorLoginResult(Kind.ERROR, null, List.of(), message);
        }
    }

    /** Null unless app.bff.oidc.enabled=true — when null every call is a fail-closed stub. */
    private final WebClient http;
    private final String loginPath;
    private final String clientId;
    private final String application;
    private final String organization;
    private final String scope;

    public CasdoorLoginClient(WebClient http, String loginPath, String clientId,
                              String application, String organization, String scope) {
        this.http = http;
        this.loginPath = loginPath;
        this.clientId = clientId;
        this.application = application;
        this.organization = organization;
        this.scope = scope;
    }

    /** Whether the live Casdoor login client is wired (vs. the fail-closed stub). */
    public boolean enabled() {
        return http != null;
    }

    /**
     * Verify {@code (username, password)} against Casdoor and drive the OIDC {@code code}
     * login. {@code state} + {@code codeChallenge} are the server-generated PKCE/anti-CSRF
     * values (S256); {@code redirectUri} MUST match the one used at token-exchange time.
     * When {@code mfaPasscode} is non-blank the Casdoor MFA verification fields are added so
     * the same call completes a second-factor challenge.
     */
    public Mono<CasdoorLoginResult> login(String username, String password, String state,
                                          String codeChallenge, String redirectUri,
                                          String mfaPasscode, String mfaType) {
        if (http == null) {
            // SHIPS-DARK: no live client → fail closed, never verify a credential.
            return Mono.error(new IllegalStateException(
                    "Casdoor login client disabled (app.bff.oidc.enabled=false)"));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("application", application);
        body.put("organization", organization);
        body.put("username", username);
        body.put("password", password);
        body.put("autoSignin", true);
        body.put("type", "code");
        body.put("signinMethod", "Password");
        if (mfaPasscode != null && !mfaPasscode.isBlank()) {
            // Casdoor's second-factor verification fields, verified in the SAME /api/login call.
            body.put("passcode", mfaPasscode);
            body.put("mfaType", (mfaType == null || mfaType.isBlank()) ? "totp" : mfaType);
        }

        return http.post()
                .uri(b -> b.path(loginPath)
                        .queryParam("clientId", clientId)
                        .queryParam("responseType", "code")
                        .queryParam("redirectUri", redirectUri)
                        .queryParam("scope", scope)
                        .queryParam("state", state)
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256")
                        .build())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .map(CasdoorLoginClient::parse);
    }

    /** Map Casdoor's {@code Response} envelope onto one of the three outcomes. */
    private static CasdoorLoginResult parse(Map<?, ?> resp) {
        Object status = resp.get("status");
        Object data = resp.get("data");

        // Not "ok" → an authentication error (bad password, disabled user, wrong passcode…).
        if (!"ok".equals(str(status))) {
            String msg = str(resp.get("msg"));
            return CasdoorLoginResult.error(msg == null || msg.isBlank() ? "login failed" : msg);
        }
        // "ok" + data == "NextMfa" → a second factor is required (NO session yet).
        if (NEXT_MFA.equals(str(data))) {
            return CasdoorLoginResult.mfaRequired(extractMfaTypes(resp.get("data2")));
        }
        // "ok" + data == the one-time authorization code.
        String code = str(data);
        if (code == null || code.isBlank()) {
            // Defensive: an "ok" with no code is not something we can complete a login from.
            log.warn("[casdoor-login] status=ok but no authorization code in response — treating as error");
            return CasdoorLoginResult.error("login failed");
        }
        return CasdoorLoginResult.code(code);
    }

    /**
     * Pull the enabled MFA type names out of Casdoor's {@code data2}, which for a NextMfa
     * response is the list of the user's MFA props ({@code [{mfaType:"totp",..}, ..]}).
     * Tolerant of a list of maps, a single map, or a bare string.
     */
    private static List<String> extractMfaTypes(Object data2) {
        List<String> out = new ArrayList<>();
        if (data2 instanceof List<?> list) {
            for (Object o : list) {
                addMfaType(out, o);
            }
        } else {
            addMfaType(out, data2);
        }
        return out;
    }

    private static void addMfaType(List<String> out, Object o) {
        if (o instanceof Map<?, ?> m) {
            Object t = m.get("mfaType");
            if (t == null) {
                t = m.get("type");
            }
            if (t != null && !t.toString().isBlank()) {
                out.add(t.toString());
            }
        } else if (o != null && !o.toString().isBlank()) {
            out.add(o.toString());
        }
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }
}
