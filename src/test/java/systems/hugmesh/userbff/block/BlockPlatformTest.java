package systems.hugmesh.userbff.block;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link BlockPlatform} contract: the enum is a CODE-SIDE lens over the closed
 * {@code user_block.platform} vocabulary ({@code matrix|mastodon|internal}), byte-
 * identical to the prior lowercase strings (mirroring federation #46 {@code ScopeKindTest}).
 * Pins that the legacy {@link UserBlock#validPlatform(String)} guard — now delegating
 * here — keeps its exact accept/reject verdict, including the {@code internal} member the
 * shared external {@code web.PlatformKind} lens does NOT carry.
 */
class BlockPlatformTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        assertThat(BlockPlatform.MATRIX.value()).isEqualTo("matrix");
        assertThat(BlockPlatform.MASTODON.value()).isEqualTo("mastodon");
        assertThat(BlockPlatform.INTERNAL.value()).isEqualTo("internal");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(BlockPlatform.values()).map(BlockPlatform::value).toList())
                .containsExactly("matrix", "mastodon", "internal");
    }

    @Test
    void fromWire_roundTripsEveryToken_andIsNullTolerant() {
        for (BlockPlatform p : BlockPlatform.values()) {
            assertThat(BlockPlatform.fromWire(p.value())).isEqualTo(p);
        }
        assertThat(BlockPlatform.fromWire(null)).isNull();
        assertThat(BlockPlatform.fromWire("")).isNull();
        assertThat(BlockPlatform.fromWire("INTERNAL")).isNull();   // case-sensitive
        assertThat(BlockPlatform.fromWire("external")).isNull();
    }

    @Test
    void isValid_matchesLegacyValidPlatform_exactly_includingInternal() {
        for (String ok : new String[] {"matrix", "mastodon", "internal"}) {
            assertThat(BlockPlatform.isValid(ok)).isTrue();
            assertThat(UserBlock.validPlatform(ok)).isTrue();
        }
        for (String bad : new String[] {"external", "INTERNAL", "", null}) {
            assertThat(BlockPlatform.isValid(bad)).isFalse();
            assertThat(UserBlock.validPlatform(bad)).isFalse();
        }
    }

    @Test
    void json_roundTripsLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(BlockPlatform.INTERNAL)).isEqualTo("\"internal\"");
        assertThat(MAPPER.readValue("\"matrix\"", BlockPlatform.class)).isEqualTo(BlockPlatform.MATRIX);
        assertThat(MAPPER.readValue("\"nope\"", BlockPlatform.class)).isNull();
    }
}
