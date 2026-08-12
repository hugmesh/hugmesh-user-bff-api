package net.hugmesh.userbff.character;

/**
 * Parse the federation {@code @system} finding id out of the {@code fileFinding} response
 * Map's {@code "id"} value into a {@code Long} (the {@code finding_id} bigint column type).
 *
 * <p>The federation-api response is decoded as a loosely-typed {@code Map<String,Object>},
 * so the {@code id} can arrive as a JSON number ({@link Number} — typically
 * {@link Integer}/{@link Long}) or, defensively, as a numeric {@link String}. This is a
 * FAIL-SOFT helper: anything that is not a clean integer (null, blank, non-numeric, or an
 * out-of-range/decimal value) yields {@code null} so the capture leg simply leaves the
 * row's back-link unset rather than throwing — a federation contract drift must never fail
 * the user's save.
 */
final class FindingIdParser {

    private FindingIdParser() {}

    /**
     * @param raw the {@code "id"} value from the federation response Map (any type).
     * @return the finding id as a {@code Long}, or {@code null} when it is absent or not a
     *         clean integer.
     */
    static Long parse(Object raw) {
        if (raw == null) {
            return null;
        }
        if (raw instanceof Number n) {
            // A JSON integer decodes as Integer/Long; a decimal would lose precision, so
            // only accept whole-number Numbers (Integer/Long/Short/Byte/BigInteger).
            if (n instanceof Integer || n instanceof Long
                    || n instanceof Short || n instanceof Byte
                    || n instanceof java.math.BigInteger) {
                return n.longValue();
            }
            return null;
        }
        if (raw instanceof String s) {
            String trimmed = s.trim();
            if (trimmed.isEmpty()) {
                return null;
            }
            try {
                return Long.valueOf(trimmed);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}
