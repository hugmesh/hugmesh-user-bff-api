package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the SERVER-SIDE magic-byte image sniffer — the gate that decides whether a
 * cloak is even meaningful, answered from the BYTES not the client Content-Type. A
 * non-image (incl. a lie about being an image, and SVG) must be forwarded through
 * unchanged, so it reports null.
 */
class ImageSnifferTest {

    @Test
    void detectsRasterFormats() {
        assertThat(ImageSniffer.detect(prefix(new int[]{0xFF, 0xD8, 0xFF, 0xE0}))).isEqualTo("image/jpeg");
        assertThat(ImageSniffer.detect(prefix(new int[]{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})))
                .isEqualTo("image/png");
        assertThat(ImageSniffer.detect(prefix(new int[]{'G', 'I', 'F', '8', '9', 'a'}))).isEqualTo("image/gif");
        assertThat(ImageSniffer.detect(prefix(new int[]{'B', 'M', 0, 0}))).isEqualTo("image/bmp");
    }

    @Test
    void detectsWebp() {
        // RIFF????WEBP
        byte[] b = prefix(new int[]{'R', 'I', 'F', 'F', 1, 2, 3, 4, 'W', 'E', 'B', 'P'});
        assertThat(ImageSniffer.detect(b)).isEqualTo("image/webp");
    }

    @Test
    void rejectsNonImages_andLies() {
        // a text/HTML payload claiming to be an image is NOT cloakable.
        assertThat(ImageSniffer.isImage("<html>not an image</html>".getBytes())).isFalse();
        // SVG (XML/script vector) is deliberately not a cloakable raster.
        assertThat(ImageSniffer.isImage("<svg xmlns='...'></svg>".getBytes())).isFalse();
        // too short.
        assertThat(ImageSniffer.detect(new byte[]{(byte) 0xFF, (byte) 0xD8})).isNull();
        // null.
        assertThat(ImageSniffer.detect(null)).isNull();
    }

    private static byte[] prefix(int[] head) {
        byte[] b = new byte[Math.max(16, head.length)];
        for (int i = 0; i < head.length; i++) b[i] = (byte) head[i];
        return b;
    }
}
