package aydaaydor.scanner;

import aydaaydor.config.AydaConfig;
import aydaaydor.config.DedupMode;
import aydaaydor.config.IdGroup;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.stream.Collectors.toList;

public class AydaScanner implements HttpHandler, ScannerControls {
    private static final String SCAN_HEADER = "X-AydaAydor-Scan";

    private final MontoyaApi api;
    private final AydaConfig config;
    private final ExecutorService exec = Executors.newFixedThreadPool(4);
    // Dedup caches (no inFlight as per requirements)
    private final TtlLruCache seen;
    private final TtlLruCache reported;

    public AydaScanner(MontoyaApi api, AydaConfig config) {
        this.api = api;
        this.config = config;
        this.seen = new TtlLruCache(() -> this.config.getDedupLruMax(), () -> this.config.getDedupTtlMillis());
        this.reported = new TtlLruCache(() -> this.config.getDedupLruMax(), () -> this.config.getDedupTtlMillis());
    }

    public void shutdown() {
        exec.shutdown();
        try { exec.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
    }

    @Override
    public void clearScanCache() {
        seen.clear();
    }

    @Override
    public void clearReportedCache() {
        reported.clear();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!config.isEnabled()) return ResponseReceivedAction.continueWith(responseReceived);
        if (!responseReceived.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        HttpRequest baseReq = responseReceived.initiatingRequest();
        HttpResponse baseResp = responseReceived;

        // skip our own
        if (baseReq.hasHeader(SCAN_HEADER)) return ResponseReceivedAction.continueWith(responseReceived);

        // find all matching occurrences across all groups and scan each
        List<Match> matches = findAllMatches(baseReq, config.allGroups());
        long now = System.currentTimeMillis();
        for (Match m : matches) {
            String scanKey = computeScanKey(baseReq, baseResp, m);
            if (seen.isFresh(scanKey, now)) {
                // recently scanned; skip
                continue;
            }
            exec.submit(() -> runIdorChecks(baseReq, baseResp, m, scanKey));
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void runIdorChecks(HttpRequest baseReq, HttpResponse baseResp, Match match, String scanKey) {
        try {
            String baseBody = baseResp.bodyToString();
            String baseHash = stableBodyHash(baseBody == null ? "" : baseBody);
            int baseLen = safeContentLength(baseResp, baseBody);
            // Build requests for each alternate id + dummy
            List<String> denied = config.getDeniedStrings().stream().map(String::toLowerCase).collect(toList());

            IdGroup group = match.group;
            List<String> otherIds = group.ids.stream().filter(id -> !id.equals(match.matchedId)).collect(toList());
            String dummy = group.generateDummyLike(match.matchedId);

            // Build and send dummy request first
            HttpRequest dummyReq = applyReplacement(baseReq, match, dummy);
            HttpRequestResponse dummyRR = api.http().sendRequest(tag(dummyReq));
            HttpResponse dummyResp = dummyRR.response();
            String dummyBody = dummyResp.bodyToString();
            int dummyLen = safeContentLength(dummyResp, dummyBody);

            for (String id : otherIds) {
                HttpRequest testReq = applyReplacement(baseReq, match, id);
                HttpRequestResponse testRR = api.http().sendRequest(tag(testReq));
                HttpResponse testResp = testRR.response();
                String testBody = testResp.bodyToString();
                int testLen = safeContentLength(testResp, testBody);

                boolean differentFromBase = responsesDifferent(baseResp, baseBody, testResp, testBody);
                boolean differentFromDummy = responsesDifferent(dummyResp, dummyBody, testResp, testBody);
                boolean containsDenied = containsAnyIgnoreCase(testBody, denied);
                boolean extraCriterion = (testLen == baseLen) && (testLen != dummyLen)
                        && (!Objects.equals(stableBodyHash(testBody == null ? "" : testBody), baseHash));

                if (((differentFromBase && differentFromDummy) || extraCriterion) && !containsDenied) {
                    reportIssue(baseReq, baseResp, testRR, match, id, dummy);
                    break; // one finding per base request
                }
            }
        } catch (Exception e) {
            api.logging().logToError("AydaAydor error: " + e);
        } finally {
            seen.mark(scanKey, System.currentTimeMillis());
        }
    }

    private boolean responsesDifferent(HttpResponse aResp, String aBody, HttpResponse bResp, String bBody) {
        // If body looks like JSON for both, compare stable hashes
        boolean aJson = looksLikeJson(aBody);
        boolean bJson = looksLikeJson(bBody);
        if (aJson && bJson) {
            String ha = stableBodyHash(aBody);
            String hb = stableBodyHash(bBody);
            return !Objects.equals(ha, hb);
        }
        // Otherwise, fall back to content-length compare
        int la = safeContentLength(aResp, aBody);
        int lb = safeContentLength(bResp, bBody);
        return la != lb;
    }

    private boolean looksLikeJson(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (t.isEmpty()) return false;
        char c = t.charAt(0);
        char e = t.charAt(t.length() - 1);
        return (c == '{' && e == '}') || (c == '[' && e == ']');
    }

    private int safeContentLength(HttpResponse resp, String body) {
        // Prefer actual body length; header Content-Length may be absent or compressed
        return body != null ? body.length() : 0;
    }

    private String stableBodyHash(String body) {
        // Simple, fast hash suitable for equality checks
        // Normalize trivial whitespace differences
        String norm = body.trim();
        int h = 1125899907; // offset basis-like prime
        for (int i = 0; i < norm.length(); i++) {
            h = (h * 16777619) ^ norm.charAt(i);
        }
        return Integer.toHexString(h);
    }

    private boolean containsAnyIgnoreCase(String haystack, List<String> needlesLower) {
        if (haystack == null) return false;
        String lower = haystack.toLowerCase();
        for (String n : needlesLower) if (lower.contains(n)) return true;
        return false;
    }

    private HttpRequest tag(HttpRequest req) {
        return req.withUpdatedHeader(SCAN_HEADER, "1");
    }

    private void reportIssue(HttpRequest baseReq, HttpResponse baseResp, HttpRequestResponse evidence, Match match, String toId, String dummy) {
        String name = "Potential IDOR (AydaAydor)";
        String detail = "Base ID '" + match.matchedId + "' in " + match.locationDescription() +
                " replaced with '" + toId + "' produced different response, also different from dummy '" + dummy + "'.";
        String remediation = "Enforce object-level authorization checks. Tie access to user/session, not identifiers.";
        String reportKey = computeReportKey(baseReq, match);
        if (reported.isFresh(reportKey, System.currentTimeMillis())) {
            return; // already reported recently
        }

        AuditIssue issue = auditIssue(
                name,
                detail,
                remediation,
                baseReq.url(),
                burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH,
                burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM,
                null,
                null,
                burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH,
                httpRequestResponse(baseReq, baseResp),
                evidence
        );
        reported.mark(reportKey, System.currentTimeMillis());
        api.siteMap().add(issue);
        api.logging().logToOutput("AydaAydor: Reported IDOR at " + baseReq.url());
    }

    private String computeScanKey(HttpRequest req, HttpResponse baseResp, Match m) {
        String method = req.method();
        String host = hostFromRequest(req);
        String path = safe(req.pathWithoutQuery());
        String loc = locationKey(m);
        String chain = m.chain.steps.toString();
        String groupSig = groupSignature(m.group);
        StringBuilder sb = new StringBuilder();
        sb.append(method).append('|').append(host).append('|').append(path).append('|')
          .append(loc).append('|').append(chain).append('|').append(groupSig);
        if (config.getDedupMode() == DedupMode.CONTENT_AWARE) {
            String baseSig = baseSignature(baseResp);
            sb.append('|').append(baseSig);
        }
        return sb.toString();
    }

    private String computeReportKey(HttpRequest req, Match m) {
        String method = req.method();
        String host = hostFromRequest(req);
        String path = safe(req.pathWithoutQuery());
        String loc = locationKey(m);
        return method + '|' + host + '|' + path + '|' + loc + '|' + m.group.name;
    }

    private String locationKey(Match m) {
        switch (m.candidate.type) {
            case PARAMETER:
                return "P|" + m.candidate.param.name() + '|' + m.candidate.param.type();
            case HEADER:
                return "H|" + m.candidate.headerName;
            case PATH_SEGMENT:
                return "S|" + m.candidate.pathIndex;
            case RAW_QUERY:
                return "Q";
            default:
                return "?";
        }
    }

    private String baseSignature(HttpResponse resp) {
        try {
            int code = resp.statusCode();
            String body = resp.bodyToString();
            return code + ":" + fastHash(body == null ? "" : body);
        } catch (Exception e) {
            return "0:";
        }
    }

    private String groupSignature(IdGroup g) {
        try {
            List<String> ids = new ArrayList<>(g.ids);
            Collections.sort(ids);
            String joined = String.join("\n", ids);
            return g.name + "#" + fastHash(joined);
        } catch (Exception e) {
            return g.name;
        }
    }

    private String hostFromRequest(HttpRequest req) {
        try {
            for (HttpHeader h : req.headers()) {
                if (h.name().equalsIgnoreCase("Host")) return h.value();
            }
        } catch (Exception ignored) {}
        return "";
    }

    private String safe(String s) { return s == null ? "" : s; }

    private String fastHash(String s) {
        // Reuse stableBodyHash logic for a simple, fast hash
        if (s == null) return "0";
        String norm = s.trim();
        int h = 1125899907; // prime-like seed
        for (int i = 0; i < norm.length(); i++) {
            h = (h * 16777619) ^ norm.charAt(i);
        }
        return Integer.toHexString(h);
    }

    private List<Match> findAllMatches(HttpRequest req, List<IdGroup> groups) {
        // Collect candidate value occurrences
        List<Candidate> candidates = new ArrayList<>();
        // Parameters (all types including URL, BODY, JSON, COOKIE, MULTIPART_ATTRIBUTE)
        for (var p : req.parameters()) {
            candidates.add(Candidate.forParam(p));
        }
        // Headers
        for (HttpHeader h : req.headers()) {
            String hn = h.name();
            if (hn.equalsIgnoreCase("Host")) continue;     // skip host header
            if (hn.equalsIgnoreCase("Referer")) continue;  // skip referer header
            candidates.add(Candidate.forHeader(hn, h.value()));
        }
        // Path segments
        String path = req.pathWithoutQuery();
        if (path != null && !path.isEmpty()) {
            String[] parts = path.split("/");
            int idx = 0;
            for (String s : parts) {
                if (s.isEmpty()) { idx++; continue; }
                candidates.add(Candidate.forPathSegment(idx, s));
                idx++;
            }
        }

        // Raw query as a whole (covers cases where entire query is Base64 blob)
        String fullPath = req.path();
        if (fullPath != null) {
            int q = fullPath.indexOf('?');
            if (q >= 0 && q + 1 < fullPath.length()) {
                String rawQuery = fullPath.substring(q + 1);
                if (!rawQuery.isEmpty()) {
                    candidates.add(Candidate.forRawQuery(rawQuery));
                }
            }
        }

        // Try to match each candidate against group IDs (with decoders), collect all unique matches
        List<Match> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Candidate c : candidates) {
            for (IdGroup g : groups) {
                for (String id : g.ids) {
                    var occ = EncodingChain.findOccurrence(c.value, id);
                    if (occ.isPresent()) {
                        var o = occ.get();
                        String modeTag;
                        String key;
                        if (o.reencodeWhole) {
                            modeTag = "D:" + o.decodedStart;
                            key = c.type + "|" + c.value + "|" + g.name + "|" + id + "|" + o.chain.steps.toString() + "|" + modeTag;
                            if (seen.add(key)) {
                                out.add(new Match(g, id, c, o.chain, o.decodedFull, o.decodedStart, true));
                            }
                        } else {
                            modeTag = "E:" + o.startIndex;
                            key = c.type + "|" + c.value + "|" + g.name + "|" + id + "|" + o.chain.steps.toString() + "|" + modeTag;
                            if (seen.add(key)) {
                                out.add(new Match(g, id, c, o.chain, o.fragment, o.startIndex));
                            }
                        }
                    }
                }
            }
        }
        return out;
    }

    private HttpRequest applyReplacement(HttpRequest req, Match match, String newId) {
        String encoded = match.chain.encode(newId, match.candidate.value);
        switch (match.candidate.type) {
            case PARAMETER: {
                HttpParameter p = match.candidate.param;
                String newVal;
                if (match.reencodeWhole) {
                    String decoded = match.decodedFull;
                    String mutated = replaceAt(decoded, match.decodedStart, match.matchedId.length(), newId);
                    newVal = match.chain.encode(mutated, match.candidate.value);
                } else {
                    String oldVal = match.candidate.value;
                    newVal = replaceAt(oldVal, match.startIndex, match.encodedFragment.length(), encoded);
                }
                HttpParameter updated = HttpParameter.parameter(p.name(), newVal, p.type());
                return req.withUpdatedParameters(updated);
            }
            case HEADER: {
                String newVal;
                if (match.reencodeWhole) {
                    String decoded = match.decodedFull;
                    String mutated = replaceAt(decoded, match.decodedStart, match.matchedId.length(), newId);
                    newVal = match.chain.encode(mutated, match.candidate.value);
                } else {
                    String oldVal = match.candidate.value;
                    newVal = replaceAt(oldVal, match.startIndex, match.encodedFragment.length(), encoded);
                }
                return req.withUpdatedHeader(match.candidate.headerName, newVal);
            }
            case PATH_SEGMENT: {
                String path = req.path();
                String[] parts = path.split("/");
                int segIndex = match.candidate.pathIndex;
                int i = 0; List<String> rebuilt = new ArrayList<>();
                for (String s : parts) {
                    if (i == segIndex && !s.isEmpty()) {
                        String newSeg;
                        int qpos = s.indexOf('?');
                        String segCore = qpos >= 0 ? s.substring(0, qpos) : s;
                        String suffix = qpos >= 0 ? s.substring(qpos) : ""; // includes '?...'
                        if (match.reencodeWhole) {
                            String decoded = match.decodedFull; // decoded original segment core
                            String mutated = replaceAt(decoded, match.decodedStart, match.matchedId.length(), newId);
                            String encodedCore = match.chain.encode(mutated, segCore);
                            newSeg = encodedCore + suffix;
                        } else {
                            String replacedCore = replaceAt(segCore, match.startIndex, match.encodedFragment.length(), encoded);
                            newSeg = replacedCore + suffix;
                        }
                        rebuilt.add(newSeg);
                    } else {
                        rebuilt.add(s);
                    }
                    i++;
                }
                String newPath = String.join("/", rebuilt);
                if (!newPath.startsWith("/")) newPath = "/" + newPath;
                return req.withPath(newPath);
            }
            case RAW_QUERY: {
                String full = req.path();
                int q = full.indexOf('?');
                String base = q >= 0 ? full.substring(0, q) : full;
                String oldQuery = q >= 0 && q + 1 < full.length() ? full.substring(q + 1) : "";
                String newQuery;
                if (match.reencodeWhole) {
                    String decoded = match.decodedFull;
                    String mutated = replaceAt(decoded, match.decodedStart, match.matchedId.length(), newId);
                    newQuery = match.chain.encode(mutated, match.candidate.value);
                } else {
                    newQuery = replaceAt(oldQuery, match.startIndex, match.encodedFragment.length(), encoded);
                }
                String rebuilt = base + (newQuery.isEmpty() ? "" : ("?" + newQuery));
                return req.withPath(rebuilt);
            }
            default:
                return req;
        }
    }

    private static String replaceAt(String original, int start, int length, String replacement) {
        StringBuilder sb = new StringBuilder();
        sb.append(original, 0, Math.max(0, start));
        sb.append(replacement);
        int end = Math.min(original.length(), start + Math.max(0, length));
        if (end < original.length()) sb.append(original.substring(end));
        return sb.toString();
    }
}
