package systems.hugmesh.userbff.svg;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Hostile-SVG corpus for the authoritative server-side sanitizer. Every known
 * stored-XSS vector for SVG must be stripped, valid drawing markup must survive,
 * and unparseable / non-svg / DOCTYPE(XXE) input must fail closed.
 */
class SvgSanitizerServiceTest {

    private final SvgSanitizerService svc = new SvgSanitizerService();

    @Test
    void stripsScriptElement() {
        String out = svc.sanitize(
                "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script>"
                        + "<path class='region-fur' d='M0 0 L10 10 Z'/></svg>");
        assertThat(out).doesNotContainIgnoringCase("script");
        assertThat(out).contains("path").contains("region-fur");
    }

    @Test
    void stripsEventHandlerAttributes() {
        String out = svc.sanitize(
                "<svg xmlns='http://www.w3.org/2000/svg'>"
                        + "<rect x='0' y='0' width='10' height='10' onload='alert(1)' onclick='x()'/></svg>");
        assertThat(out).doesNotContainIgnoringCase("onload").doesNotContainIgnoringCase("onclick");
        assertThat(out).contains("rect");
    }

    @Test
    void stripsForeignObject() {
        String out = svc.sanitize(
                "<svg xmlns='http://www.w3.org/2000/svg'><foreignObject>"
                        + "<body xmlns='http://www.w3.org/1999/xhtml'><img src='x' onerror='alert(1)'/></body>"
                        + "</foreignObject><circle cx='5' cy='5' r='5'/></svg>");
        assertThat(out).doesNotContainIgnoringCase("foreignobject")
                .doesNotContainIgnoringCase("onerror");
        assertThat(out).contains("circle");
    }

    @Test
    void stripsUseImageAnchorAndExternalHref() {
        String out = svc.sanitize(
                "<svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'>"
                        + "<a xlink:href='javascript:alert(1)'><use href='#x'/></a>"
                        + "<image href='https://evil/x.png'/>"
                        + "<path d='M0 0 L1 1'/></svg>");
        assertThat(out).doesNotContainIgnoringCase("<use")
                .doesNotContainIgnoringCase("<image")
                .doesNotContainIgnoringCase("<a ")
                .doesNotContainIgnoringCase("javascript:")
                .doesNotContainIgnoringCase("href");
        assertThat(out).contains("path");
    }

    @Test
    void stripsInlineStyleElement() {
        String out = svc.sanitize(
                "<svg xmlns='http://www.w3.org/2000/svg'>"
                        + "<style>* { background: url(javascript:alert(1)) }</style>"
                        + "<rect width='5' height='5'/></svg>");
        assertThat(out).doesNotContainIgnoringCase("<style").doesNotContainIgnoringCase("javascript:");
    }

    @Test
    void failsClosedOnDoctypeXxe() {
        String xxe = "<?xml version='1.0'?><!DOCTYPE svg [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>"
                + "<svg xmlns='http://www.w3.org/2000/svg'><text>&x;</text></svg>";
        assertThatThrownBy(() -> svc.sanitize(xxe))
                .isInstanceOf(SvgSanitizerService.InvalidSvgException.class);
    }

    @Test
    void failsClosedOnNonSvgRoot() {
        assertThatThrownBy(() -> svc.sanitize("<html><body>hi</body></html>"))
                .isInstanceOf(SvgSanitizerService.InvalidSvgException.class);
    }

    @Test
    void failsClosedOnMalformed() {
        assertThatThrownBy(() -> svc.sanitize("<svg><path d='M0 0'"))
                .isInstanceOf(SvgSanitizerService.InvalidSvgException.class);
        assertThatThrownBy(() -> svc.sanitize("   "))
                .isInstanceOf(SvgSanitizerService.InvalidSvgException.class);
    }

    @Test
    void preservesValidDrawingMarkupAndRegionClass() {
        String out = svc.sanitize(
                "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1024 1024'>"
                        + "<g><path class='region-fur' d='M10 10 L20 20 Z' fill='#abc' stroke-width='2'/>"
                        + "<circle class='region-iris' cx='5' cy='5' r='3'/></g></svg>");
        assertThat(out).contains("region-fur").contains("region-iris")
                .contains("d=").contains("viewBox").contains("circle");
    }
}
