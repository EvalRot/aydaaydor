import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.stream.Collectors.toList;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AydaAydor");

        Preferences prefs = api.persistence().preferences();
        Logging log = api.logging();

        AydaConfig config = new AydaConfig(prefs, log);
        config.load();

        // UI Tab
        UserInterface ui = api.userInterface();
        JPanel tab = new AydaTab(config, log);
        ui.applyThemeToComponent(tab);
        ui.registerSuiteTab("AydaAydor", tab);

        // HTTP handler
        AydaScanner scanner = new AydaScanner(api, config);
        api.http().registerHttpHandler(scanner);

        // Clean shutdown
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                scanner.shutdown();
                config.save();
            }
        });

        log.logToOutput("AydaAydor initialized. Ready to detect IDORs.");
    }

    // ====== Configuration model and persistence ======
    static class AydaConfig {
        private static final String PREF_PREFIX = "ayda_aydor.";
        private static final String PREF_GROUPS = PREF_PREFIX + "groups"; // CSV of keys
        private static final String PREF_DENIED = PREF_PREFIX + "denied"; // lines
        private static final String PREF_ENABLED = PREF_PREFIX + "enabled"; // boolean

        private final Preferences prefs;
        private final Logging log;
        private final Map<String, IdGroup> groups = new LinkedHashMap<>();
        private final java.util.List<String> deniedStrings = new ArrayList<>();
        private volatile boolean enabled = true;

        AydaConfig(Preferences prefs, Logging log) {
            this.prefs = prefs;
            this.log = log;
        }

        synchronized void addGroup(IdGroup g) {
            groups.put(g.name, g);
        }

        synchronized void removeGroup(String name) {
            groups.remove(name);
        }

        synchronized java.util.List<IdGroup> allGroups() {
            return new ArrayList<>(groups.values());
        }

        synchronized IdGroup getGroup(String name) {
            return groups.get(name);
        }

        synchronized void setDeniedStrings(java.util.List<String> values) {
            deniedStrings.clear();
            for (String s : values) {
                if (s != null && !s.isBlank()) deniedStrings.add(s.trim());
            }
        }

        synchronized java.util.List<String> getDeniedStrings() {
            return new ArrayList<>(deniedStrings);
        }

        synchronized boolean isEnabled() { return enabled; }
        synchronized void setEnabled(boolean e) { enabled = e; }

        synchronized void load() {
            try {
                enabled = Boolean.TRUE.equals(prefs.getBoolean(PREF_ENABLED));

                groups.clear();
                String list = prefs.getString(PREF_GROUPS);
                if (list != null) {
                    for (String key : list.split(",")) {
                        key = key.trim();
                        if (key.isEmpty()) continue;
                        String name = prefs.getString(PREF_PREFIX + "group." + key + ".name");
                        String ids = prefs.getString(PREF_PREFIX + "group." + key + ".ids");
                        if (name == null || ids == null) continue;
                        IdGroup g = new IdGroup(name);
                        for (String id : ids.split("\n")) {
                            id = id.trim();
                            if (!id.isEmpty()) g.ids.add(id);
                        }
                        g.recalculateType();
                        groups.put(name, g);
                    }
                }

                deniedStrings.clear();
                String denied = prefs.getString(PREF_DENIED);
                if (denied != null) {
                    for (String d : denied.split("\n")) {
                        d = d.trim();
                        if (!d.isEmpty()) deniedStrings.add(d);
                    }
                }
            } catch (Exception e) {
                log.logToError("AydaAydor: Failed to load preferences: " + e);
            }
        }

        synchronized void save() {
            try {
                prefs.setBoolean(PREF_ENABLED, enabled);
                // store groups with stable keys
                java.util.List<String> keys = new ArrayList<>();
                int i = 0;
                for (IdGroup g : groups.values()) {
                    String key = slug(g.name) + "_" + (i++);
                    keys.add(key);
                    prefs.setString(PREF_PREFIX + "group." + key + ".name", g.name);
                    prefs.setString(PREF_PREFIX + "group." + key + ".ids", String.join("\n", g.ids));
                }
                prefs.setString(PREF_GROUPS, String.join(",", keys));

                prefs.setString(PREF_DENIED, String.join("\n", deniedStrings));
            } catch (Exception e) {
                log.logToError("AydaAydor: Failed to save preferences: " + e);
            }
        }

        private static String slug(String s) {
            String out = s.replaceAll("[^A-Za-z0-9]+", "_");
            out = out.replaceAll("_+", "_");
            if (out.isBlank()) out = "group";
            return out;
        }
    }

    static class IdGroup {
        final String name;
        final java.util.Set<String> ids = new LinkedHashSet<>();
        GroupType type = GroupType.ALPHANUM;

        IdGroup(String name) { this.name = name; }

        void recalculateType() {
            this.type = GroupType.infer(ids);
        }

        String generateDummyLike(String like) {
            return type.generateDummy(like);
        }
    }

    enum GroupType {
        NUMERIC, ALPHA, ALPHANUM, UUID;

        static GroupType infer(Collection<String> values) {
            if (values.isEmpty()) return ALPHANUM;
            boolean allNumeric = true, allAlpha = true, allAlnum = true, allUuid = true;
            Pattern uuid = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
            for (String v : values) {
                if (!v.matches("\\d+")) allNumeric = false;
                if (!v.matches("[A-Za-z]+")) allAlpha = false;
                if (!v.matches("[A-Za-z0-9]+")) allAlnum = false;
                if (!uuid.matcher(v).matches()) allUuid = false;
            }
            if (allUuid) return UUID;
            if (allNumeric) return NUMERIC;
            if (allAlpha) return ALPHA;
            if (allAlnum) return ALPHANUM;
            return ALPHANUM;
        }

        String generateDummy(String like) {
            int len = like != null ? like.length() : 8;
            Random r = new Random();
            switch (this) {
                case UUID:
                    return java.util.UUID.randomUUID().toString();
                case NUMERIC: {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < len; i++) sb.append((char)('0' + r.nextInt(10)));
                    return sb.toString();
                }
                case ALPHA: {
                    String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < len; i++) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
                    return sb.toString();
                }
                case ALPHANUM:
                default: {
                    String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < len; i++) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
                    return sb.toString();
                }
            }
        }
    }

    // ====== UI Tab ======
    static class AydaTab extends JPanel {
        private final AydaConfig config;
        private final Logging log;
        private final DefaultListModel<String> groupsModel = new DefaultListModel<>();
        private final JList<String> groupsList = new JList<>(groupsModel);
        private final JTextArea idsArea = new JTextArea(10, 40);
        private final JLabel typeLabel = new JLabel("Type: ");
        private final JTextArea deniedArea = new JTextArea(6, 40);
        private final JCheckBox enabledBox = new JCheckBox("Enable scanning");

        AydaTab(AydaConfig config, Logging log) {
            super(new BorderLayout());
            this.config = config;
            this.log = log;
            buildUi();
            reloadFromConfig();
        }

        private void buildUi() {
            // Left: groups list + buttons
            JPanel left = new JPanel(new BorderLayout());
            left.setBorder(new TitledBorder("ID Groups"));
            groupsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            groupsList.addListSelectionListener(e -> onGroupSelected());
            left.add(new JScrollPane(groupsList), BorderLayout.CENTER);

            JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
            btns.add(new JButton(new AbstractAction("Add Group") {
                @Override public void actionPerformed(ActionEvent e) { addGroupDialog(); }
            }));
            btns.add(new JButton(new AbstractAction("Remove Group") {
                @Override public void actionPerformed(ActionEvent e) { removeSelectedGroup(); }
            }));
            left.add(btns, BorderLayout.SOUTH);

            // Right: group details and denied strings
            JPanel right = new JPanel();
            right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));

            JPanel groupPanel = new JPanel(new BorderLayout());
            groupPanel.setBorder(new TitledBorder("Selected Group IDs"));
            idsArea.setLineWrap(true);
            idsArea.setWrapStyleWord(true);
            groupPanel.add(new JScrollPane(idsArea), BorderLayout.CENTER);
            JPanel grpSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            grpSouth.add(typeLabel);
            grpSouth.add(new JButton(new AbstractAction("Save Group") {
                @Override public void actionPerformed(ActionEvent e) { saveCurrentGroup(); }
            }));
            groupPanel.add(grpSouth, BorderLayout.SOUTH);

            JPanel deniedPanel = new JPanel(new BorderLayout());
            deniedPanel.setBorder(new TitledBorder("Denied strings (one per line, case-insensitive)"));
            deniedArea.setLineWrap(true);
            deniedArea.setWrapStyleWord(true);
            deniedPanel.add(new JScrollPane(deniedArea), BorderLayout.CENTER);
            JPanel deniedSouth = new JPanel(new FlowLayout(FlowLayout.LEFT));
            deniedSouth.add(new JButton(new AbstractAction("Save Denied") {
                @Override public void actionPerformed(ActionEvent e) {
                    var lines = Arrays.stream(deniedArea.getText().split("\n")).map(String::trim).filter(s -> !s.isEmpty()).collect(toList());
                    config.setDeniedStrings(lines);
                    config.save();
                }
            }));
            deniedPanel.add(deniedSouth, BorderLayout.SOUTH);

            enabledBox.setSelected(config.isEnabled());
            enabledBox.addActionListener(e -> { config.setEnabled(enabledBox.isSelected()); config.save(); });

            right.add(groupPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(deniedPanel);
            right.add(Box.createVerticalStrut(8));
            right.add(enabledBox);

            add(left, BorderLayout.WEST);
            add(right, BorderLayout.CENTER);
        }

        private void reloadFromConfig() {
            groupsModel.clear();
            for (IdGroup g : config.allGroups()) groupsModel.addElement(g.name);
            if (!groupsModel.isEmpty()) groupsList.setSelectedIndex(0);
            deniedArea.setText(String.join("\n", config.getDeniedStrings()));
        }

        private void onGroupSelected() {
            String name = groupsList.getSelectedValue();
            if (name == null) { idsArea.setText(""); typeLabel.setText("Type: "); return; }
            IdGroup g = config.getGroup(name);
            if (g == null) return;
            idsArea.setText(String.join("\n", g.ids));
            g.recalculateType();
            typeLabel.setText("Type: " + g.type);
        }

        private void addGroupDialog() {
            String name = JOptionPane.showInputDialog(this, "New group name:", "Add Group", JOptionPane.PLAIN_MESSAGE);
            if (name == null || name.isBlank()) return;
            if (config.getGroup(name) != null) {
                JOptionPane.showMessageDialog(this, "Group already exists.");
                return;
            }
            IdGroup g = new IdGroup(name.trim());
            config.addGroup(g);
            config.save();
            groupsModel.addElement(g.name);
            groupsList.setSelectedValue(g.name, true);
        }

        private void removeSelectedGroup() {
            String name = groupsList.getSelectedValue();
            if (name == null) return;
            int res = JOptionPane.showConfirmDialog(this, "Remove group '" + name + "'?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (res == JOptionPane.YES_OPTION) {
                config.removeGroup(name);
                config.save();
                groupsModel.removeElement(name);
                idsArea.setText("");
                typeLabel.setText("Type: ");
            }
        }

        private void saveCurrentGroup() {
            String name = groupsList.getSelectedValue();
            if (name == null) return;
            IdGroup g = config.getGroup(name);
            if (g == null) return;
            g.ids.clear();
            for (String line : idsArea.getText().split("\n")) {
                String id = line.trim();
                if (!id.isEmpty()) g.ids.add(id);
            }
            g.recalculateType();
            typeLabel.setText("Type: " + g.type);
            config.save();
        }
    }

    // ====== HTTP Scanner ======
    static class AydaScanner implements HttpHandler {
        private static final String SCAN_HEADER = "X-AydaAydor-Scan";

        private final MontoyaApi api;
        private final AydaConfig config;
        private final ExecutorService exec = Executors.newFixedThreadPool(4);

        AydaScanner(MontoyaApi api, AydaConfig config) {
            this.api = api;
            this.config = config;
        }

        void shutdown() {
            exec.shutdown();
            try { exec.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            // Avoid scanning our own requests
            if (requestToBeSent.hasHeader(SCAN_HEADER)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
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
            java.util.List<Match> matches = findAllMatches(baseReq, config.allGroups());
            for (Match m : matches) {
                exec.submit(() -> runIdorChecks(baseReq, baseResp, m));
            }

            return ResponseReceivedAction.continueWith(responseReceived);
        }

        private void runIdorChecks(HttpRequest baseReq, HttpResponse baseResp, Match match) {
            try {
                String baseBody = baseResp.bodyToString();
                // Build requests for each alternate id + dummy
                java.util.List<String> denied = config.getDeniedStrings().stream().map(String::toLowerCase).collect(toList());

                IdGroup group = match.group;
                java.util.List<String> otherIds = group.ids.stream().filter(id -> !id.equals(match.matchedId)).collect(toList());
                String dummy = group.generateDummyLike(match.matchedId);

                // Build and send dummy request first
                HttpRequest dummyReq = applyReplacement(baseReq, match, dummy);
                HttpRequestResponse dummyRR = api.http().sendRequest(tag(dummyReq));
                HttpResponse dummyResp = dummyRR.response();
                String dummyBody = dummyResp.bodyToString();

                for (String id : otherIds) {
                    HttpRequest testReq = applyReplacement(baseReq, match, id);
                    HttpRequestResponse testRR = api.http().sendRequest(tag(testReq));
                    HttpResponse testResp = testRR.response();
                    String testBody = testResp.bodyToString();

                    boolean differentFromBase = responsesDifferent(baseResp, baseBody, testResp, testBody);
                    boolean differentFromDummy = responsesDifferent(dummyResp, dummyBody, testResp, testBody);
                    boolean containsDenied = containsAnyIgnoreCase(testBody, denied);

                    if (differentFromBase && differentFromDummy && !containsDenied) {
                        reportIssue(baseReq, baseResp, testRR, match, id, dummy);
                        break; // one finding per base request
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("AydaAydor error: " + e);
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

        private boolean containsAnyIgnoreCase(String haystack, java.util.List<String> needlesLower) {
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

            AuditIssue issue = auditIssue(
                    name,
                    detail,
                    remediation,
                    baseReq.url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    null,
                    null,
                    AuditIssueSeverity.HIGH,
                    httpRequestResponse(baseReq, baseResp),
                    evidence
            );

            api.siteMap().add(issue);
            api.logging().logToOutput("AydaAydor: Reported IDOR at " + baseReq.url());
        }

        private java.util.List<Match> findAllMatches(HttpRequest req, java.util.List<IdGroup> groups) {
            // Collect candidate value occurrences
            java.util.List<Candidate> candidates = new ArrayList<>();
            // Parameters (all types including URL, BODY, JSON, COOKIE, MULTIPART_ATTRIBUTE)
            for (var p : req.parameters()) {
                candidates.add(Candidate.forParam(p));
            }
            // Headers
            for (HttpHeader h : req.headers()) {
                if (h.name().equalsIgnoreCase("Host")) continue; // skip host header
                candidates.add(Candidate.forHeader(h.name(), h.value()));
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

            // Try to match each candidate against group IDs (with decoders), collect all unique matches
            java.util.List<Match> out = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (Candidate c : candidates) {
                for (IdGroup g : groups) {
                    for (String id : g.ids) {
                        Optional<EncodingChain> chain = EncodingChain.detect(c.value, id);
                        if (chain.isPresent()) {
                            String key = c.type + "|" + c.value + "|" + g.name + "|" + id + "|" + chain.get().steps.toString();
                            if (seen.add(key)) {
                                out.add(new Match(g, id, c, chain.get()));
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
                    HttpParameter updated = HttpParameter.parameter(p.name(), encoded, p.type());
                    return req.withUpdatedParameters(updated);
                }
                case HEADER: {
                    return req.withUpdatedHeader(match.candidate.headerName, encoded);
                }
                case PATH_SEGMENT: {
                    String path = req.path();
                    String[] parts = path.split("/");
                    int segIndex = match.candidate.pathIndex;
                    int i = 0; java.util.List<String> rebuilt = new ArrayList<>();
                    for (String s : parts) {
                        if (i == segIndex && !s.isEmpty()) {
                            rebuilt.add(encoded);
                        } else {
                            rebuilt.add(s);
                        }
                        i++;
                    }
                    String newPath = String.join("/", rebuilt);
                    if (!newPath.startsWith("/")) newPath = "/" + newPath;
                    return req.withPath(newPath);
                }
                default:
                    return req;
            }
        }
    }

    // ====== Matching support classes ======
    static class Candidate {
        enum Type { PARAMETER, HEADER, PATH_SEGMENT }
        final Type type;
        final String value;
        final HttpParameter param; // for PARAMETER
        final String headerName;   // for HEADER
        final int pathIndex;       // for PATH_SEGMENT (segment position in split array)

        private Candidate(Type t, String value, HttpParameter p, String headerName, int pathIndex) {
            this.type = t; this.value = value; this.param = p; this.headerName = headerName; this.pathIndex = pathIndex;
        }

        static Candidate forParam(HttpParameter p) {
            return new Candidate(Type.PARAMETER, p.value(), p, null, -1);
        }

        static Candidate forHeader(String name, String value) {
            return new Candidate(Type.HEADER, value, null, name, -1);
        }

        static Candidate forPathSegment(int index, String value) {
            return new Candidate(Type.PATH_SEGMENT, value, null, null, index);
        }
    }

    static class Match {
        final IdGroup group;
        final String matchedId;
        final Candidate candidate;
        final EncodingChain chain;

        Match(IdGroup group, String matchedId, Candidate candidate, EncodingChain chain) {
            this.group = group; this.matchedId = matchedId; this.candidate = candidate; this.chain = chain;
        }

        String locationDescription() {
            switch (candidate.type) {
                case PARAMETER:
                    return "parameter '" + candidate.param.name() + "' (" + candidate.param.type() + ")";
                case HEADER:
                    return "header '" + candidate.headerName + "'";
                case PATH_SEGMENT:
                    return "URL path segment";
                default:
                    return "request";
            }
        }
    }

    // ====== Encoding detection and application ======
    static class EncodingChain {
        enum Step { PLAIN, URL, UNICODE, BASE64, BASE64URL }
        final java.util.List<Step> steps; // steps applied during decoding (in order)

        EncodingChain(java.util.List<Step> steps) { this.steps = steps; }

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

        String encode(String value, String sampleEncodedForm) {
            // Invert the decode steps to build encode chain
            java.util.List<Step> inv = new ArrayList<>(steps);
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
            // unicode-escape style sequences
            Pattern p2 = Pattern.compile("\\\\u([0-9A-Fa-f]{4})");
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
}
