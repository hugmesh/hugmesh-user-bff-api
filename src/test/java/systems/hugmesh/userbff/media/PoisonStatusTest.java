package systems.hugmesh.userbff.media;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link PoisonStatus} contract: the enum is a CODE-SIDE lens over the closed
 * {@code media_poison_decision.status} vocabulary, byte-identical to the prior lowercase
 * strings (mirroring federation #46 {@code ScopeKindTest}). Also pins that the legacy
 * {@link MediaPoisonDecision#validStatus(String)} guard — now delegating here — keeps its
 * exact accept/reject verdict.
 */
class PoisonStatusTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        assertThat(PoisonStatus.PROTECTED.value()).isEqualTo("protected");
        assertThat(PoisonStatus.DEGRADED.value()).isEqualTo("degraded");
        assertThat(PoisonStatus.SKIPPED.value()).isEqualTo("skipped");
        assertThat(PoisonStatus.NONE.value()).isEqualTo("none");
        assertThat(PoisonStatus.PENDING.value()).isEqualTo("pending");
        assertThat(PoisonStatus.FAILED.value()).isEqualTo("failed");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(PoisonStatus.values()).map(PoisonStatus::value).toList())
                .containsExactly("protected", "degraded", "skipped", "none", "pending", "failed");
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (PoisonStatus s : PoisonStatus.values()) {
            assertThat(PoisonStatus.fromWire(s.value())).isEqualTo(s);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        assertThat(PoisonStatus.fromWire(null)).isNull();
        assertThat(PoisonStatus.fromWire("")).isNull();
        assertThat(PoisonStatus.fromWire("ok")).isNull();
        assertThat(PoisonStatus.fromWire("PROTECTED")).isNull();   // case-sensitive
    }

    @Test
    void isValid_matchesLegacyValidStatus_exactly() {
        for (String ok : new String[] {"protected", "degraded", "skipped", "none", "pending", "failed"}) {
            assertThat(PoisonStatus.isValid(ok)).isTrue();
            assertThat(MediaPoisonDecision.validStatus(ok)).isTrue();
        }
        for (String bad : new String[] {"ok", "PROTECTED", "", null}) {
            assertThat(PoisonStatus.isValid(bad)).isFalse();
            assertThat(MediaPoisonDecision.validStatus(bad)).isFalse();
        }
    }

    @Test
    void json_roundTripsLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(PoisonStatus.PROTECTED)).isEqualTo("\"protected\"");
        assertThat(MAPPER.readValue("\"failed\"", PoisonStatus.class)).isEqualTo(PoisonStatus.FAILED);
        assertThat(MAPPER.readValue("\"nope\"", PoisonStatus.class)).isNull();
    }
}
