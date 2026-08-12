package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.Test;
import net.hugmesh.userbff.federation.FederationHttpClientSsl;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CasdoorLoginConfig} builds the password-bearing native-login WebClient through the
 * gated {@link FederationHttpClientSsl} mTLS connector (the same connector the federation and
 * admin-bff-internal legs use). These prove the bean is constructable with the mTLS param in
 * BOTH gate states, that the ships-dark {@code app.bff.oidc.enabled} gate is preserved, and
 * that a mis-mounted mTLS keystore degrades to the plain connector rather than crashing boot.
 */
class CasdoorLoginConfigTest {

    private final CasdoorLoginConfig config = new CasdoorLoginConfig();

    /** Default-constructed = gate off (enabled=false) — the local/dev/CI posture. */
    private static final FederationHttpClientSsl MTLS_OFF = new FederationHttpClientSsl();

    private CasdoorLoginClient build(FederationHttpClientSsl mtls, boolean oidcEnabled) {
        return config.casdoorLoginClient(
                mtls, oidcEnabled,
                "http://casdoor:8000", "/api/login", "app-user-bff",
                "app-user-bff", "hugmesh", "openid profile email");
    }

    @Test
    void oidcEnabled_buildsLiveClient_throughMtlsConnector() {
        // A live client is wired (http != null): the mTLS connector (a no-op with the gate off)
        // did not suppress the live native-login path.
        assertThat(build(MTLS_OFF, true).enabled()).isTrue();
    }

    @Test
    void oidcDisabled_shipsFailClosedStub() {
        // Ships-dark gate preserved: with the surface off the client is a fail-closed stub.
        assertThat(build(MTLS_OFF, false).enabled()).isFalse();
    }

    @Test
    void mtlsGateOn_butStoresAbsent_stillBuildsLiveClient() {
        // Gate ON yet no keystore mounted (shouldApply()==false): customize() degrades to the
        // plain connector instead of crashing, so the live client is still built.
        FederationHttpClientSsl mtlsOn = new FederationHttpClientSsl();
        mtlsOn.setEnabled(true);
        mtlsOn.setKeyStore("/nonexistent/keystore.p12");
        assertThat(build(mtlsOn, true).enabled()).isTrue();
    }
}
