package systems.hugmesh.userbff.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link PlatformKind} contract: the enum is a CODE-SIDE lens over the closed external
 * {@code matrix|mastodon} platform vocabulary, and its wire form is BYTE-IDENTICAL to the
 * prior lowercase strings the system stored / exchanged (mirroring federation #46
 * {@code ScopeKindTest}). These tests pin that equivalence so the enum can never silently
 * drift the DB/JSON value the media-proxy / connected-client / hs-token custody persist.
 */
class PlatformKindTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        assertThat(PlatformKind.MATRIX.value()).isEqualTo("matrix");
        assertThat(PlatformKind.MASTODON.value()).isEqualTo("mastodon");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(PlatformKind.values()).map(PlatformKind::value).toList())
                .containsExactly("matrix", "mastodon");
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (PlatformKind p : PlatformKind.values()) {
            assertThat(PlatformKind.fromWire(p.value())).isEqualTo(p);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        assertThat(PlatformKind.fromWire(null)).isNull();
        assertThat(PlatformKind.fromWire("")).isNull();
        assertThat(PlatformKind.fromWire("internal")).isNull();   // external set only — no 'internal'
        assertThat(PlatformKind.fromWire("MATRIX")).isNull();      // case-sensitive: the column is lowercase
    }

    @Test
    void isValid_acceptsOnlyTheTwoTokens() {
        assertThat(PlatformKind.isValid("matrix")).isTrue();
        assertThat(PlatformKind.isValid("mastodon")).isTrue();
        assertThat(PlatformKind.isValid("internal")).isFalse();
        assertThat(PlatformKind.isValid("bogus")).isFalse();
        assertThat(PlatformKind.isValid(null)).isFalse();
    }

    @Test
    void json_serializesToLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(PlatformKind.MATRIX)).isEqualTo("\"matrix\"");
        assertThat(MAPPER.writeValueAsString(PlatformKind.MASTODON)).isEqualTo("\"mastodon\"");
    }

    @Test
    void json_deserializesFromLowercaseToken() throws Exception {
        assertThat(MAPPER.readValue("\"matrix\"", PlatformKind.class)).isEqualTo(PlatformKind.MATRIX);
        assertThat(MAPPER.readValue("\"mastodon\"", PlatformKind.class)).isEqualTo(PlatformKind.MASTODON);
    }

    @Test
    void json_unknownTokenDeserializesToNull_neverThrows() throws Exception {
        assertThat(MAPPER.readValue("\"nope\"", PlatformKind.class)).isNull();
    }
}
