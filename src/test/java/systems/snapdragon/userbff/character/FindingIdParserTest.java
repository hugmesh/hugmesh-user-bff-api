package systems.snapdragon.userbff.character;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for {@link FindingIdParser} — the fail-soft federation-finding-id extractor.
 * The federation {@code fileFinding} response Map's {@code id} can decode as an Integer, a
 * Long, a numeric String, etc.; anything not a clean integer must yield {@code null} so
 * the capture leg leaves the row's back-link unset rather than throwing.
 */
class FindingIdParserTest {

    @Test
    void parsesIntegerLongAndOtherWholeNumbers() {
        assertThat(FindingIdParser.parse(4242)).isEqualTo(4242L);          // Integer
        assertThat(FindingIdParser.parse(7L)).isEqualTo(7L);               // Long
        assertThat(FindingIdParser.parse((short) 5)).isEqualTo(5L);        // Short
        assertThat(FindingIdParser.parse(BigInteger.valueOf(9))).isEqualTo(9L);
    }

    @Test
    void parsesNumericString() {
        assertThat(FindingIdParser.parse("4242")).isEqualTo(4242L);
        assertThat(FindingIdParser.parse("  88  ")).isEqualTo(88L);
    }

    @Test
    void nullAndBlankAndNonNumericYieldNull() {
        assertThat(FindingIdParser.parse(null)).isNull();
        assertThat(FindingIdParser.parse("")).isNull();
        assertThat(FindingIdParser.parse("   ")).isNull();
        assertThat(FindingIdParser.parse("not-a-number")).isNull();
        assertThat(FindingIdParser.parse("12.5")).isNull();
    }

    @Test
    void decimalNumbersYieldNull_noPrecisionLoss() {
        // a Double/Float would lose precision casting to long — reject rather than truncate.
        assertThat(FindingIdParser.parse(12.5d)).isNull();
        assertThat(FindingIdParser.parse(3.0f)).isNull();
    }

    @Test
    void unexpectedTypeYieldsNull() {
        assertThat(FindingIdParser.parse(new Object())).isNull();
        assertThat(FindingIdParser.parse(java.util.List.of(1))).isNull();
    }
}
