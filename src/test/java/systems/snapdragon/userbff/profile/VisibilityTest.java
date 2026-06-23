package systems.snapdragon.userbff.profile;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link Visibility} contract: the enum is a CODE-SIDE lens over the closed
 * {@code user_profile.visibility} vocabulary ({@code public|internal}), byte-identical to
 * the prior lowercase strings (mirroring federation #46 {@code ScopeKindTest}). Pins that
 * {@link UserProfile#DEFAULT_VISIBILITY} — now sourced from {@link Visibility#INTERNAL} —
 * stays {@code "internal"}, so the default floor never drifts.
 */
class VisibilityTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        assertThat(Visibility.PUBLIC.value()).isEqualTo("public");
        assertThat(Visibility.INTERNAL.value()).isEqualTo("internal");
    }

    @Test
    void defaultVisibilityConstant_staysInternal_byteIdentical() {
        assertThat(UserProfile.DEFAULT_VISIBILITY).isEqualTo("internal");
        assertThat(UserProfile.DEFAULT_VISIBILITY).isEqualTo(Visibility.INTERNAL.value());
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(Visibility.values()).map(Visibility::value).toList())
                .containsExactly("public", "internal");
    }

    @Test
    void fromWire_roundTripsEveryToken_andIsNullTolerant() {
        for (Visibility v : Visibility.values()) {
            assertThat(Visibility.fromWire(v.value())).isEqualTo(v);
        }
        assertThat(Visibility.fromWire(null)).isNull();
        assertThat(Visibility.fromWire("")).isNull();
        assertThat(Visibility.fromWire("PUBLIC")).isNull();   // case-sensitive
        assertThat(Visibility.fromWire("private")).isNull();
    }

    @Test
    void isValid_acceptsOnlyTheTwoTokens() {
        assertThat(Visibility.isValid("public")).isTrue();
        assertThat(Visibility.isValid("internal")).isTrue();
        assertThat(Visibility.isValid("private")).isFalse();
        assertThat(Visibility.isValid(null)).isFalse();
    }

    @Test
    void json_roundTripsLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(Visibility.PUBLIC)).isEqualTo("\"public\"");
        assertThat(MAPPER.readValue("\"internal\"", Visibility.class)).isEqualTo(Visibility.INTERNAL);
        assertThat(MAPPER.readValue("\"nope\"", Visibility.class)).isNull();
    }
}
