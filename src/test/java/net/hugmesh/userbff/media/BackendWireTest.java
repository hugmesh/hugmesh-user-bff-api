package net.hugmesh.userbff.media;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import net.hugmesh.userbff.media.PoisonModels.Backend;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link Backend} alignment to the federation #46 shape: this enum predated the
 * convention and already served as the code-side lens over the {@code backend} wire/DB
 * token. These tests pin that the NEW {@code @JsonValue value()} / {@code @JsonCreator
 * fromWire()} emit/parse the IDENTICAL lowercase tokens AND that the retained
 * {@link Backend#wire()} / {@link Backend#parse(String)} aliases keep their exact prior
 * behaviour (so every existing call site is unchanged).
 */
class BackendWireTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_equalsWire_andIsTheLowercaseToken() {
        for (Backend b : Backend.values()) {
            // value() (the #46 JsonValue) and wire() (the retained alias) are identical.
            assertThat(b.value()).isEqualTo(b.wire());
        }
        assertThat(Backend.CUDA.value()).isEqualTo("cuda");
        assertThat(Backend.ROCM.value()).isEqualTo("rocm");
        assertThat(Backend.CPU.value()).isEqualTo("cpu");
        assertThat(Backend.NONE.value()).isEqualTo("none");
    }

    @Test
    void wire_isByteIdenticalToTheOriginalNameLowerCase() {
        // The pre-alignment wire() was name().toLowerCase(); pin that the field-backed
        // value is still byte-identical for every constant.
        for (Backend b : Backend.values()) {
            assertThat(b.wire()).isEqualTo(b.name().toLowerCase());
        }
    }

    @Test
    void fromWire_isStrict_nullOnNullOrUnknown() {
        // The #46-shaped creator: exact-token-or-null (NO NONE-default, NO trim).
        assertThat(Backend.fromWire("cuda")).isEqualTo(Backend.CUDA);
        assertThat(Backend.fromWire("none")).isEqualTo(Backend.NONE);
        assertThat(Backend.fromWire(null)).isNull();
        assertThat(Backend.fromWire("")).isNull();
        assertThat(Backend.fromWire(" cuda ")).isNull();   // strict: no trim
        assertThat(Backend.fromWire("CUDA")).isNull();      // strict: case-sensitive
        assertThat(Backend.fromWire("gpu")).isNull();
    }

    @Test
    void parse_keepsLenientHealthBehaviour_nullUnknownPaddedToNone() {
        // The LENIENT worker-/health parser is unchanged: null/unknown/padded => NONE.
        assertThat(Backend.parse(null)).isEqualTo(Backend.NONE);
        assertThat(Backend.parse("")).isEqualTo(Backend.NONE);
        assertThat(Backend.parse("gpu")).isEqualTo(Backend.NONE);
        assertThat(Backend.parse("  CUDA  ")).isEqualTo(Backend.CUDA);  // trims + lowercases
        assertThat(Backend.parse("RoCm")).isEqualTo(Backend.ROCM);
        assertThat(Backend.parse("cpu")).isEqualTo(Backend.CPU);
    }

    @Test
    void present_isTrueForEveryBackendButNone() {
        assertThat(Backend.CUDA.present()).isTrue();
        assertThat(Backend.ROCM.present()).isTrue();
        assertThat(Backend.CPU.present()).isTrue();
        assertThat(Backend.NONE.present()).isFalse();
    }

    @Test
    void json_serializesToLowercaseToken_andParsesBack() throws Exception {
        // @JsonValue => lowercase token; @JsonCreator(fromWire) => strict parse-back.
        assertThat(MAPPER.writeValueAsString(Backend.CUDA)).isEqualTo("\"cuda\"");
        assertThat(MAPPER.writeValueAsString(Backend.NONE)).isEqualTo("\"none\"");
        assertThat(MAPPER.readValue("\"rocm\"", Backend.class)).isEqualTo(Backend.ROCM);
        assertThat(MAPPER.readValue("\"nope\"", Backend.class)).isNull();
    }
}
