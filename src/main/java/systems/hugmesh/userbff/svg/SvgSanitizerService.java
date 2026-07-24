package systems.hugmesh.userbff.svg;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * AUTHORITATIVE server-side SVG sanitizer for user-authored character parts.
 *
 * <p>User SVG is a stored-XSS vector ({@code <script>}, {@code <foreignObject>},
 * {@code on*} handlers, {@code href}/{@code xlink:href} {@code javascript:}/{@code data:},
 * {@code <use>}/{@code <image>}/{@code <a>} external refs, {@code style url()},
 * {@code DOCTYPE}/XXE). Byte-regex sanitizers are routinely bypassed (CDATA/encoding),
 * so this DOM-PARSES the document (with XXE fully disabled) and rebuilds it from a
 * strict ELEMENT + ATTRIBUTE ALLOWLIST — anything not on the list is dropped. This is
 * the security boundary that runs BEFORE moderation/storage (SANITIZE → MODERATE →
 * STORE); the client DOMPurify pass is preview-only and never trusted.
 *
 * <p>Pure JDK (no third-party dependency) so the allowlist is fully under our control.
 */
@Service
public class SvgSanitizerService {

    /** Elements permitted in a part SVG (drawing primitives + gradients). */
    private static final Set<String> ALLOWED_ELEMENTS = Set.of(
            "svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline",
            "polygon", "defs", "lineargradient", "radialgradient", "stop", "title");

    /** Attributes permitted on those elements (geometry + presentation, no refs). */
    private static final Set<String> ALLOWED_ATTRS = Set.of(
            "d", "points", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry",
            "width", "height", "viewbox", "fill", "stroke", "stroke-width", "stroke-linecap",
            "stroke-linejoin", "stroke-dasharray", "opacity", "fill-opacity", "stroke-opacity",
            "fill-rule", "transform", "class", "gradientunits", "gradienttransform", "offset",
            "stop-color", "stop-opacity", "id", "xmlns");

    /** Raised when the input is not a valid, root-{@code <svg>} document. */
    public static final class InvalidSvgException extends RuntimeException {
        public InvalidSvgException(String message) {
            super(message);
        }
    }

    /**
     * Parse, allowlist-filter, and re-serialize an SVG to a safe subset. Throws
     * {@link InvalidSvgException} if the input is not well-formed XML or its root is
     * not {@code <svg>} (fail-closed — never echo unparseable input back).
     */
    public String sanitize(String dirty) {
        if (dirty == null || dirty.isBlank()) {
            throw new InvalidSvgException("empty svg");
        }
        Document doc = parseHardened(dirty);
        Element root = doc.getDocumentElement();
        if (root == null || !"svg".equals(localName(root))) {
            throw new InvalidSvgException("root element is not <svg>");
        }
        scrub(root);
        return serialize(doc);
    }

    /** DOM-parse with XXE / external-entity / DOCTYPE processing fully disabled. */
    private Document parseHardened(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            // rethrow parse problems (so we fail closed) WITHOUT the default stderr dump
            db.setErrorHandler(new ErrorHandler() {
                @Override public void warning(SAXParseException e) { /* ignore */ }
                @Override public void error(SAXParseException e) throws SAXException { throw e; }
                @Override public void fatalError(SAXParseException e) throws SAXException { throw e; }
            });
            return db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidSvgException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidSvgException("not well-formed svg: " + e.getMessage());
        }
    }

    /** Recursively drop disallowed elements + attributes from the tree. */
    private void scrub(Element el) {
        // strip every attribute not on the allowlist (handles on*, href, style, etc.)
        NamedNodeMap attrs = el.getAttributes();
        for (int i = attrs.getLength() - 1; i >= 0; i--) {
            Node attr = attrs.item(i);
            String name = attr.getNodeName().toLowerCase();
            // namespace declarations for SVG are fine; everything else must be allowlisted
            boolean xmlnsDecl = name.equals("xmlns") || name.startsWith("xmlns:");
            if (!xmlnsDecl && !ALLOWED_ATTRS.contains(strip(name))) {
                el.removeAttribute(attr.getNodeName());
            }
        }
        // recurse children; remove any element not on the allowlist (whole subtree)
        NodeList children = el.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                Element ce = (Element) child;
                if (!ALLOWED_ELEMENTS.contains(localName(ce))) {
                    el.removeChild(ce);
                } else {
                    scrub(ce);
                }
            } else if (child.getNodeType() == Node.PROCESSING_INSTRUCTION_NODE
                    || child.getNodeType() == Node.ENTITY_REFERENCE_NODE) {
                el.removeChild(child);
            }
        }
    }

    /** Lower-cased local name (namespace-agnostic). */
    private String localName(Node n) {
        String ln = n.getLocalName();
        return (ln != null ? ln : n.getNodeName()).toLowerCase();
    }

    /** Drop any namespace prefix from an attribute name (e.g. xlink:href → href). */
    private String strip(String name) {
        int c = name.indexOf(':');
        return c >= 0 ? name.substring(c + 1) : name;
    }

    private String serialize(Document doc) {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer t = tf.newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            t.setOutputProperty(OutputKeys.INDENT, "no");
            StringWriter out = new StringWriter();
            t.transform(new DOMSource(doc), new StreamResult(out));
            return out.toString();
        } catch (Exception e) {
            throw new InvalidSvgException("serialization failed: " + e.getMessage());
        }
    }
}
