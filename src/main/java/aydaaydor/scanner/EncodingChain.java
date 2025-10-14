package aydaaydor.scanner;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class EncodingChain {
    enum Step { PLAIN, URL, UNICODE, BASE64, BASE64URL }
    final List<Step> steps; // steps applied during decoding (in order)

    EncodingChain(List<Step> steps) { this.steps = steps; }

    static Optional<EncodingChain> detect(String candidate, String wanted) {
        if (candidate == null) return Optional.empty();
        if (wanted == null) return Optional.empty();
        // Direct
        if (candidate.equals(wanted)) return Optional.of(new EncodingChain(List.of(Step.PLAIN)));

        // Single-step decodes
        if (decUrl(candidate).equals(wanted)) return Optional.of(new EncodingChain(List.of(Step.URL)));
        if (decUnicode(candidate).equals(wanted)) return Optional.of(new EncodingChain(List.of(Step.UNICODE)));
        if (decB64(candidate).map(s -> s.equals(wanted)).orElse(false)) return Optional.of(new EncodingChain(List.of(Step.BASE64)));
        if (decB64Url(candidate).map(s -> s.equals(wanted)).orElse(false)) return Optional.of(new EncodingChain(List.of(Step.BASE64URL)));

        // Two-step: URL -> B64
        String u = decUrl(candidate);
        if (decB64(u).map(s -> s.equals(wanted)).orElse(false)) return Optional.of(new EncodingChain(List.of(Step.URL, Step.BASE64)));
        if (decB64Url(u).map(s -> s.equals(wanted)).orElse(false)) return Optional.of(new EncodingChain(List.of(Step.URL, Step.BASE64URL)));

        // Two-step: B64 -> URL
        Optional<String> b = decB64(candidate);
        if (b.map(EncodingChain::decUrl).map(s -> s.equals(wanted)).orElse(false)) return Optional.of(new EncodingChain(List.of(Step.BASE64, Step.URL)));
        Optional<String> bu = decB64Url(candidate);
        if (bu.map(EncodingChain::decUrl).map(s -> s.equals(wanted)).orElse(false)) return Optional.of(new EncodingChain(List.of(Step.BASE64URL, Step.URL)));

        // Unicode then URL
        String un = decUnicode(candidate);
        if (decUrl(un).equals(wanted)) return Optional.of(new EncodingChain(List.of(Step.UNICODE, Step.URL)));

        return Optional.empty();
    }

    // New: find an occurrence of 'wanted' (after applying encoding) inside candidate string.
    static Optional<EncodedOccurrence> findOccurrence(String candidate, String wanted) {
        if (candidate == null || wanted == null) return Optional.empty();

        // Define decode-step chains we support (same semantics as before)
        List<List<Step>> chains = List.of(
                List.of(Step.PLAIN),
                List.of(Step.URL),
                List.of(Step.UNICODE),
                List.of(Step.BASE64),
                List.of(Step.BASE64URL),
                List.of(Step.URL, Step.BASE64),
                List.of(Step.URL, Step.BASE64URL),
                List.of(Step.BASE64, Step.URL),
                List.of(Step.BASE64URL, Step.URL),
                List.of(Step.UNICODE, Step.URL)
        );

        for (List<Step> steps : chains) {
            EncodingChain chain = new EncodingChain(steps);

            // Styles for ambiguous encodings
            List<String> samples = new ArrayList<>();
            samples.add(null); // default
            if (steps.contains(Step.UNICODE)) {
                samples.add("%u0000"); // force %u style
            }
            if (steps.contains(Step.BASE64URL)) {
                samples.add("="); // prefer padded style if applicable
            }

            for (String sample : samples) {
                String enc = chain.encode(wanted, sample);
                int idx = candidate.indexOf(enc);
                if (idx >= 0) {
                    return Optional.of(new EncodedOccurrence(chain, enc, idx));
                }
            }

            // Additionally: try decode-then-search for cases like Base64 wrapping multiple values
            String decoded = chain.decodeAll(candidate);
            if (decoded != null) {
                int dIdx = decoded.indexOf(wanted);
                if (dIdx >= 0) {
                    return Optional.of(new EncodedOccurrence(chain, decoded, dIdx, true));
                }
            }
        }

        return Optional.empty();
    }

    String decodeAll(String s) {
        String out = s;
        try {
            for (Step step : steps) {
                switch (step) {
                    case PLAIN:
                        break;
                    case URL:
                        out = decUrl(out);
                        break;
                    case UNICODE:
                        out = decUnicode(out);
                        break;
                    case BASE64: {
                        var r = decB64(out);
                        if (r.isEmpty()) return null;
                        out = r.get();
                        break;
                    }
                    case BASE64URL: {
                        var r = decB64Url(out);
                        if (r.isEmpty()) return null;
                        out = r.get();
                        break;
                    }
                }
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    String encode(String value, String sampleEncodedForm) {
        // Invert the decode steps to build encode chain
        List<Step> inv = new ArrayList<>(steps);
        Collections.reverse(inv);
        String out = value;
        for (Step s : inv) {
            switch (s) {
                case PLAIN: break;
                case URL: out = encUrl(out); break;
                case UNICODE: out = encUnicode(out, sampleEncodedForm); break;
                case BASE64: out = encB64(out); break;
                case BASE64URL: out = encB64Url(out, sampleEncodedForm); break;
            }
        }
        return out;
    }

    static String decUrl(String s) {
        try { return URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (Exception e) { return s; }
    }

    static String encUrl(String s) {
        try { return URLEncoder.encode(s, StandardCharsets.UTF_8); } catch (Exception e) { return s; }
    }

    static String decUnicode(String s) {
        // Handle "%uXXXX" and unicode escape-style sequences (e.g. backslash-u-XXXX)
        String out = s;
        // %uXXXX
        Pattern p1 = Pattern.compile("%u([0-9A-Fa-f]{4})");
        Matcher m1 = p1.matcher(out);
        StringBuffer sb1 = new StringBuffer();
        while (m1.find()) {
            char c = (char) Integer.parseInt(m1.group(1), 16);
            m1.appendReplacement(sb1, Matcher.quoteReplacement(String.valueOf(c)));
        }
        m1.appendTail(sb1);
        out = sb1.toString();
        // unicode-escape style sequences: backslash-uXXXX (avoid literal sequence in source)
        Pattern p2 = Pattern.compile("\\\\" + "u([0-9A-Fa-f]{4})");
        Matcher m2 = p2.matcher(out);
        StringBuffer sb2 = new StringBuffer();
        while (m2.find()) {
            char c = (char) Integer.parseInt(m2.group(1), 16);
            m2.appendReplacement(sb2, Matcher.quoteReplacement(String.valueOf(c)));
        }
        m2.appendTail(sb2);
        return sb2.toString();
    }

    static String encUnicode(String s, String sample) {
        // Choose style based on sample (prefer same style if present)
        boolean usePercentU = sample != null && sample.contains("%u");
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            String hex = String.format("%04X", (int) c);
            if (usePercentU) sb.append("%u").append(hex);
            else sb.append("\\u").append(hex);
        }
        return sb.toString();
    }

    static Optional<String> decB64(String s) {
        try {
            // add padding if missing
            String x = s;
            int mod = x.length() % 4;
            if (mod != 0) x = x + "====".substring(mod);
            byte[] bytes = Base64.getDecoder().decode(x);
            return Optional.of(new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception e) { return Optional.empty(); }
    }

    static Optional<String> decB64Url(String s) {
        try {
            String x = s.replace('-', '+').replace('_', '/');
            int mod = x.length() % 4;
            if (mod != 0) x = x + "====".substring(mod);
            byte[] bytes = Base64.getUrlDecoder().decode(x);
            return Optional.of(new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception e) { return Optional.empty(); }
    }

    static String encB64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    static String encB64Url(String s, String sample) {
        String enc = Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
        // If sample had padding, add it (rare for URL-safe)
        if (sample != null && sample.endsWith("=") && enc.length() % 4 != 0) {
            int mod = enc.length() % 4;
            enc = enc + "====".substring(mod);
        }
        return enc;
    }
}
