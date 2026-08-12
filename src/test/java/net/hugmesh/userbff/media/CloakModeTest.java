package net.hugmesh.userbff.media;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CloakMode} contract: the enum is a CODE-SIDE lens over the closed
 * {@code media_poison_decision.mode} vocabulary, byte-identical to the prior lowercase
 * strings (mirroring federation #46 {@code ScopeKindTest}). Also pins that the legacy
 * {@link MediaPoisonDecision#validMode(String)} guard — now delegating here — keeps its
 * exact accept/reject verdict.
 */
class CloakModeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        assertThat(CloakMode.GLAZE.value()).isEqualTo("glaze");
        assertThat(CloakMode.NIGHTSHADE.value()).isEqualTo("nightshade");
        assertThat(CloakMode.LIGHT.value()).isEqualTo("light");
        assertThat(CloakMode.NONE.value()).isEqualTo("none");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(CloakMode.values()).map(CloakMode::value).toList())
                .containsExactly("glaze", "nightshade", "light", "none");
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (CloakMode m : CloakMode.values()) {
            assertThat(CloakMode.fromWire(m.value())).isEqualTo(m);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        assertThat(CloakMode.fromWire(null)).isNull();
        assertThat(CloakMode.fromWire("")).isNull();
        assertThat(CloakMode.fromWire("heavy")).isNull();
        assertThat(CloakMode.fromWire("GLAZE")).isNull();   // case-sensitive
    }

    @Test
    void isValid_matchesLegacyValidMode_exactly() {
        for (String ok : new String[] {"glaze", "nightshade", "light", "none"}) {
            assertThat(CloakMode.isValid(ok)).isTrue();
            assertThat(MediaPoisonDecision.validMode(ok)).isTrue();
        }
        for (String bad : new String[] {"bogus", "GLAZE", "", null}) {
            assertThat(CloakMode.isValid(bad)).isFalse();
            assertThat(MediaPoisonDecision.validMode(bad)).isFalse();
        }
    }

    @Test
    void json_roundTripsLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(CloakMode.NIGHTSHADE)).isEqualTo("\"nightshade\"");
        assertThat(MAPPER.readValue("\"glaze\"", CloakMode.class)).isEqualTo(CloakMode.GLAZE);
        assertThat(MAPPER.readValue("\"nope\"", CloakMode.class)).isNull();
    }
}
