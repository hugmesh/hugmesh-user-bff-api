package systems.hugmesh.userbff.character;

import java.util.Set;

/**
 * The CANONICAL expression vocabulary for VN-character expression stickers (Phase B1).
 * Each value is the per-expression sticker key — also the MSC2545 pack image shortcode
 * (`[a-zA-Z0-9-_]+`, &le;100 bytes) when the active set is later advertised as an
 * {@code im.ponies.user_emotes} pack — so it is deliberately a lowercase, hyphen-free,
 * shortcode-safe token.
 *
 * <p>This is the SINGLE Java home for the enum; the DB carries a parallel CHECK
 * constraint (changelog 017) and the matrix-ui exports a parallel TS constant in a later
 * B1 PR. The two paired-but-separate vocabularies are kept identical by convention (the
 * 017 CHECK lists exactly these labels).
 *
 * <p>The {@code rule-based sentiment} fallback (a later B1 PR) maps keywords/emoji to
 * these labels (e.g. {@code lol/😂→happy}, {@code sorry/😢→sad}); {@code neutral} is the
 * default expression when nothing else matches.
 */
public final class StickerExpression {

    private StickerExpression() {}

    /** The 10 canonical expressions (the B1 scaffold's expression set). */
    public static final String NEUTRAL = "neutral";
    public static final String HAPPY = "happy";
    public static final String SAD = "sad";
    public static final String ANGRY = "angry";
    public static final String SURPRISED = "surprised";
    public static final String EMBARRASSED = "embarrassed";
    public static final String THINKING = "thinking";
    public static final String WINK = "wink";
    public static final String SLEEPY = "sleepy";
    public static final String SMUG = "smug";

    /**
     * The full canonical set, in a stable, immutable order. The API validates an inbound
     * {@code expression} against this set (a 422 otherwise) and the DB CHECK (017) lists
     * exactly these labels — so the API gate and the DB gate can never drift.
     */
    public static final Set<String> ALL = Set.of(
            NEUTRAL, HAPPY, SAD, ANGRY, SURPRISED,
            EMBARRASSED, THINKING, WINK, SLEEPY, SMUG);

    /** Whether {@code expression} is a recognised canonical expression label. */
    public static boolean isValid(String expression) {
        return expression != null && ALL.contains(expression);
    }
}
