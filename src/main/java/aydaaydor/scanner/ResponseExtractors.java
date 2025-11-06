package aydaaydor.scanner;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Utilities to extract normalized maps of significant values from HTTP responses (JSON, HTML, XML).
 */
final class ResponseExtractors {
    enum BodyType { JSON, HTML, XML, OTHER }

    private static final JsonParser JSON_PARSER = new JsonParser();

    private ResponseExtractors() {}

    static BodyType detectBodyType(HttpResponse resp, String body) {
        try {
            String ct = resp == null ? null : resp.headerValue("Content-Type");
            if (ct != null) {
                String l = ct.toLowerCase(Locale.ROOT);
                if (l.contains("json")) return BodyType.JSON;
                if (l.contains("html")) return BodyType.HTML;
                if (l.contains("xml")) return BodyType.XML;
            }
        } catch (Throwable ignored) {}
        if (body == null) return BodyType.OTHER;
        String t = body.trim();
        if (t.isEmpty()) return BodyType.OTHER;
        char c = t.charAt(0);
        if (c == '{' || c == '[') {
            return BodyType.JSON;
        }
        if (c == '<') {
            String lower = t.toLowerCase(Locale.ROOT);
            if (lower.contains("<html") || lower.contains("<!doctype html")) return BodyType.HTML;
            return BodyType.XML; // generic XML
        }
        return BodyType.OTHER;
    }

    static Map<String,String> extractSignificant(HttpResponse resp, String body, Collection<String> ignoredJsonKeys) {
        BodyType type = detectBodyType(resp, body);
        switch (type) {
            case JSON:
                return extractJsonMap(body, ignoredJsonKeys);
            case HTML:
                return extractHtmlMap(body);
            case XML:
                return extractXmlMap(body);
            default:
                return Collections.emptyMap();
        }
    }

    private static String norm(String s) {
        if (s == null) return null;
        String t = s.replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }

    // -------- HTML --------
    private static Map<String,String> extractHtmlMap(String body) {
        Map<String,String> out = new LinkedHashMap<>();
        try {
            org.jsoup.nodes.Document doc = Jsoup.parse(body);
            // Elements of interest
            String selectors = "h1,h2,h3,h4,h5,h6,p,td,th,caption,li,a,div[class],span[id]";
            Elements els = doc.select(selectors);
            for (Element e : els) {
                String text = norm(e.text());
                if (text == null) continue;
                String key;
                try { key = e.cssSelector(); } catch (Throwable ex) { key = e.tagName(); }
                if (key == null || key.isBlank()) key = e.tagName();
                // ensure uniqueness: if duplicate selector, append running index
                String k = key;
                int idx = 1;
                while (out.containsKey(k)) { k = key + "#" + (++idx); }
                out.put(k, text);
            }
        } catch (Throwable ignored) {}
        return out;
    }

    // -------- JSON --------
    private static Map<String,String> extractJsonMap(String body, Collection<String> ignoredKeys) {
        Map<String,String> out = new LinkedHashMap<>();
        if (body == null) return out;
        Set<String> ignored = new LinkedHashSet<>();
        if (ignoredKeys != null) ignored.addAll(ignoredKeys);
        try {
            JsonElement root = JSON_PARSER.parse(body);
            collectJson("$", root, out, ignored);
        } catch (Throwable ignoredEx) {}
        return out;
    }

    private static void collectJson(String path, JsonElement el, Map<String,String> out, Set<String> ignored) {
        if (el == null || el.isJsonNull()) return;
        if (el.isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                String name = e.getKey();
                if (ignored.contains(name)) continue;
                collectJson(path + "." + name, e.getValue(), out, ignored);
            }
        } else if (el.isJsonArray()) {
            int i = 0;
            for (JsonElement child : el.getAsJsonArray()) {
                collectJson(path + "[" + i + "]", child, out, ignored);
                i++;
            }
        } else if (el.isJsonPrimitive()) {
            JsonPrimitive p = el.getAsJsonPrimitive();
            String val;
            if (p.isBoolean()) val = String.valueOf(p.getAsBoolean());
            else if (p.isNumber()) val = String.valueOf(p.getAsNumber());
            else val = p.getAsString();
            String n = norm(val);
            if (n != null) out.put(path, n);
        }
    }

    // -------- XML --------
    private static Map<String,String> extractXmlMap(String body) {
        Map<String,String> out = new LinkedHashMap<>();
        if (body == null) return out;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
            if (doc.getDocumentElement() != null) {
                collectXml("/" + doc.getDocumentElement().getNodeName(), doc.getDocumentElement(), out);
            }
        } catch (Throwable ignored) {}
        return out;
    }

    private static void collectXml(String path, Node node, Map<String,String> out) {
        // If element has text content directly, record it
        String txt = node.getTextContent();
        if (txt != null) {
            String n = norm(txt);
            if (n != null && !n.isEmpty()) out.put(path, n);
        }
        NodeList children = node.getChildNodes();
        // Iterate child elements
        Map<String,Integer> tagCounts = new HashMap<>();
        for (int i = 0; i < children.getLength(); i++) {
            Node ch = children.item(i);
            if (ch.getNodeType() != Node.ELEMENT_NODE) continue;
            String name = ch.getNodeName();
            int idx = tagCounts.getOrDefault(name, 0) + 1; // 1-based index
            tagCounts.put(name, idx);
            String childPath = path + "/" + name + "[" + idx + "]";
            collectXml(childPath, ch, out);
        }
    }
}

