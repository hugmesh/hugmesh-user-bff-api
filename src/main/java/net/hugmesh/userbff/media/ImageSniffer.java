package net.hugmesh.userbff.media;

/**
 * SERVER-SIDE image type detection by MAGIC BYTES — never trusting the client-supplied
 * {@code Content-Type}. The cloak only applies to images; a non-image (or a lie about
 * being an image) must be forwarded through unchanged, so the gate is "is this REALLY an
 * image?" answered from the bytes, not the header.
 *
 * <p>Recognises the raster formats the homeservers re-encode/thumbnail (the ones a cloak
 * is meaningful for): JPEG, PNG, GIF, WebP, BMP. Anything else (incl. SVG — an XML/script
 * vector, deliberately NOT treated as a cloakable raster) is reported {@code null}.
 */
public final class ImageSniffer {

    private ImageSniffer() {}

    /** A detected raster image type, or {@code null} if the bytes are not a known image. */
    public static String detect(byte[] b) {
        if (b == null || b.length < 12) return null;
        // JPEG: FF D8 FF
        if (u(b, 0) == 0xFF && u(b, 1) == 0xD8 && u(b, 2) == 0xFF) return "image/jpeg";
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if (u(b, 0) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G'
                && u(b, 4) == 0x0D && u(b, 5) == 0x0A && u(b, 6) == 0x1A && u(b, 7) == 0x0A) return "image/png";
        // GIF: "GIF87a" / "GIF89a"
        if (b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8'
                && (b[4] == '7' || b[4] == '9') && b[5] == 'a') return "image/gif";
        // WebP: "RIFF"...."WEBP"
        if (b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
                && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') return "image/webp";
        // BMP: "BM"
        if (b[0] == 'B' && b[1] == 'M') return "image/bmp";
        return null;
    }

    /** Whether the bytes are a known cloakable raster image. */
    public static boolean isImage(byte[] b) {
        return detect(b) != null;
    }

    private static int u(byte[] b, int i) { return b[i] & 0xFF; }
}
