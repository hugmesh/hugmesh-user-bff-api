package systems.hugmesh.userbff.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ClientKind} contract: the enum is a CODE-SIDE lens over the closed
 * {@code connected_client_audit.client_kind} vocabulary, byte-identical to the prior
 * {@code KIND_OAUTH_APP}/{@code KIND_DEVICE} string constants (mirroring federation #46
 * {@code ScopeKindTest}). Pins the hyphenated {@code oauth-app} token and that the
 * retained {@link ConnectedClient} constants + {@link ConnectedClient#validKind(String)}
 * guard (now delegating here) keep their exact values / verdict.
 */
class ClientKindTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken_includingHyphen() {
        assertThat(ClientKind.OAUTH_APP.value()).isEqualTo("oauth-app");
        assertThat(ClientKind.DEVICE.value()).isEqualTo("device");
    }

    @Test
    void retainedStringConstants_stayByteIdentical() {
        // The KIND_* constants are now sourced from the enum; pin they did not drift.
        assertThat(ConnectedClient.KIND_OAUTH_APP).isEqualTo("oauth-app");
        assertThat(ConnectedClient.KIND_DEVICE).isEqualTo("device");
        assertThat(ConnectedClient.KIND_OAUTH_APP).isEqualTo(ClientKind.OAUTH_APP.value());
        assertThat(ConnectedClient.KIND_DEVICE).isEqualTo(ClientKind.DEVICE.value());
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(ClientKind.values()).map(ClientKind::value).toList())
                .containsExactly("oauth-app", "device");
    }

    @Test
    void fromWire_roundTripsEveryToken_andIsNullTolerant() {
        for (ClientKind k : ClientKind.values()) {
            assertThat(ClientKind.fromWire(k.value())).isEqualTo(k);
        }
        assertThat(ClientKind.fromWire(null)).isNull();
        assertThat(ClientKind.fromWire("")).isNull();
        assertThat(ClientKind.fromWire("oauth_app")).isNull();   // underscore is not the token
        assertThat(ClientKind.fromWire("DEVICE")).isNull();
    }

    @Test
    void isValid_matchesLegacyValidKind_exactly() {
        for (String ok : new String[] {"oauth-app", "device"}) {
            assertThat(ClientKind.isValid(ok)).isTrue();
            assertThat(ConnectedClient.validKind(ok)).isTrue();
        }
        for (String bad : new String[] {"oauth_app", "DEVICE", "", null}) {
            assertThat(ClientKind.isValid(bad)).isFalse();
            assertThat(ConnectedClient.validKind(bad)).isFalse();
        }
    }

    @Test
    void json_roundTripsLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(ClientKind.OAUTH_APP)).isEqualTo("\"oauth-app\"");
        assertThat(MAPPER.readValue("\"device\"", ClientKind.class)).isEqualTo(ClientKind.DEVICE);
        assertThat(MAPPER.readValue("\"nope\"", ClientKind.class)).isNull();
    }
}
