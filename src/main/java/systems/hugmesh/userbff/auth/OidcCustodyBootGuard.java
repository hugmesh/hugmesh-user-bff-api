package systems.hugmesh.userbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Boot-time guard for the two-flag SSO custody invariant: the OIDC login surface MUST
 * NOT be enabled while the at-rest custody key is blank, because then there is no key
 * to AES-256-GCM-encrypt the exchanged access/refresh tokens with and the only way to
 * complete a login would be to stamp a PLAINTEXT token at rest — which we never do.
 *
 * <p>So when {@code app.bff.oidc.enabled=true} AND {@code app.bff.custody-key} is blank
 * this FAILS FAST at startup (the auth-core {@code BffCustodyCipher} is independently
 * inert + fail-closed in that case, but failing the boot makes the misconfiguration
 * loud rather than letting the surface come up only to 503 every callback). Modeled on
 * auth-core's {@code InternalSurfaceBootGuard} ({@link SmartInitializingSingleton}),
 * which guards the analogous server-side mTLS invariant.
 *
 * <p>Ships dark: with {@code app.bff.oidc.enabled=false} (the default) this is a no-op,
 * so dev/test/CI and every existing deployment boot unchanged.
 */
@Component
public class OidcCustodyBootGuard implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(OidcCustodyBootGuard.class);

    private final boolean oidcEnabled;
    private final String custodyKey;

    public OidcCustodyBootGuard(@Value("${app.bff.oidc.enabled:false}") boolean oidcEnabled,
                                @Value("${app.bff.custody-key:}") String custodyKey) {
        this.oidcEnabled = oidcEnabled;
        this.custodyKey = custodyKey;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!oidcEnabled) {
            return;
        }
        if (custodyKey == null || custodyKey.isBlank()) {
            throw new IllegalStateException(
                    "app.bff.oidc.enabled=true but app.bff.custody-key is blank: refusing to start. "
                            + "The OIDC login surface would have no key to encrypt exchanged tokens at "
                            + "rest, and a plaintext token is NEVER stored. Provision the AES-256-GCM "
                            + "custody key (ESO/Vault → APP_BFF_CUSTODY_KEY) before enabling OIDC.");
        }
        log.info("[oidc-custody-guard] OIDC login enabled with a non-blank custody key — OK");
    }
}
