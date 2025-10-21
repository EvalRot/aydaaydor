package aydaaydor.config;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class AydaConfig {
    private static final String PREF_PREFIX = "ayda_aydor.";
    private static final String PREF_GROUPS = PREF_PREFIX + "groups"; // CSV of keys
    private static final String PREF_DENIED = PREF_PREFIX + "denied"; // lines
    private static final String PREF_ENABLED = PREF_PREFIX + "enabled"; // boolean
    private static final String PREF_DEDUP_MODE = PREF_PREFIX + "dedup.mode"; // STRICT | CONTENT_AWARE
    private static final String PREF_DEDUP_TTL_MS = PREF_PREFIX + "dedup.ttl_ms"; // long ms
    private static final String PREF_DEDUP_LRU = PREF_PREFIX + "dedup.lru"; // int entries
    private static final String PREF_IGNORED_PARAMS = PREF_PREFIX + "ignored.params"; // lines of TYPE:name
    private static final String PREF_PROJECT_DIR = PREF_PREFIX + "project.dir"; // string path to project folder

    private final Preferences prefs;
    private final Logging log;
    private final Map<String, IdGroup> groups = new LinkedHashMap<>();
    private final List<String> deniedStrings = new ArrayList<>();
    private final EnumMap<HttpParameterType, Set<String>> ignoredParams = new EnumMap<>(HttpParameterType.class);
    private volatile Path projectDir; // chosen in startup dialog
    // Project YAML settings
    private final List<String> pathExcludeRegex = new ArrayList<>();
    private final List<String> ignoredHeaders = new ArrayList<>();
    private final List<String> skipExtensions = new ArrayList<>();
    private final List<String> ignoredJsonKeys = new ArrayList<>();
    private volatile int requestTimeoutMs = 10000;
    private volatile int delayMsBetweenMutations = 0;
    private volatile int maxMutationsPerBase = 20;
    private volatile int maxParallelMutations = 4;
    private volatile boolean enabled = true;
    private volatile DedupMode dedupMode = DedupMode.STRICT;
    private volatile long dedupTtlMillis = 12L * 60 * 60 * 1000; // 12h default
    private volatile int dedupLruMax = 20000; // default LRU size

    public AydaConfig(Preferences prefs, Logging log) {
        this.prefs = prefs;
        this.log = log;
    }

    public synchronized void addGroup(IdGroup g) {
        groups.put(g.name, g);
    }

    public synchronized void removeGroup(String name) {
        groups.remove(name);
    }

    public synchronized List<IdGroup> allGroups() {
        return new ArrayList<>(groups.values());
    }

    public synchronized IdGroup getGroup(String name) {
        return groups.get(name);
    }

    public synchronized void setDeniedStrings(List<String> values) {
        deniedStrings.clear();
        for (String s : values) {
            if (s != null && !s.isBlank()) deniedStrings.add(s.trim());
        }
    }

    public synchronized List<String> getDeniedStrings() {
        return new ArrayList<>(deniedStrings);
    }

    // Ignored parameters management
    public synchronized void addIgnoredParam(HttpParameterType type, String name) {
        if (type == null || name == null) return;
        String key = name.trim();
        if (key.isEmpty()) return;
        key = key.toLowerCase(java.util.Locale.ROOT);
        ignoredParams.computeIfAbsent(type, t -> new LinkedHashSet<>()).add(key);
    }

    public synchronized void removeIgnoredParam(HttpParameterType type, String name) {
        if (type == null || name == null) return;
        Set<String> set = ignoredParams.get(type);
        if (set != null) set.remove(name.trim().toLowerCase(java.util.Locale.ROOT));
    }

    public synchronized boolean isParamIgnored(HttpParameterType type, String name) {
        if (type == null || name == null) return false;
        Set<String> set = ignoredParams.get(type);
        if (set == null) return false;
        return set.contains(name.trim().toLowerCase(java.util.Locale.ROOT));
    }

    public synchronized Map<HttpParameterType, Set<String>> allIgnoredParams() {
        Map<HttpParameterType, Set<String>> copy = new EnumMap<>(HttpParameterType.class);
        for (var e : ignoredParams.entrySet()) copy.put(e.getKey(), new LinkedHashSet<>(e.getValue()));
        return copy;
    }

    // Getters/setters for YAML settings
    public synchronized List<String> getPathExcludeRegex() { return new ArrayList<>(pathExcludeRegex); }
    public synchronized void setPathExcludeRegex(List<String> list) {
        pathExcludeRegex.clear();
        if (list != null) for (String s : list) if (s != null && !s.isBlank()) pathExcludeRegex.add(s.trim());
    }
    public synchronized List<String> getIgnoredHeaders() { return new ArrayList<>(ignoredHeaders); }
    public synchronized void setIgnoredHeaders(List<String> list) {
        ignoredHeaders.clear();
        if (list != null) for (String s : list) if (s != null && !s.isBlank()) ignoredHeaders.add(s.trim().toLowerCase(Locale.ROOT));
    }
    public synchronized List<String> getSkipExtensions() { return new ArrayList<>(skipExtensions); }
    public synchronized void setSkipExtensions(List<String> list) {
        skipExtensions.clear();
        if (list != null) for (String s : list) if (s != null && !s.isBlank()) {
            String v = s.trim().toLowerCase(Locale.ROOT);
            if (!v.startsWith(".")) v = "." + v;
            skipExtensions.add(v);
        }
    }
    public synchronized List<String> getIgnoredJsonKeys() { return new ArrayList<>(ignoredJsonKeys); }
    public synchronized void setIgnoredJsonKeys(List<String> list) {
        ignoredJsonKeys.clear();
        if (list != null) for (String s : list) if (s != null && !s.isBlank()) {
            String v = s.trim(); // JSON keys are case-sensitive; do not lowercase
            if (!ignoredJsonKeys.contains(v)) ignoredJsonKeys.add(v);
        }
    }
    public synchronized int getRequestTimeoutMs() { return requestTimeoutMs; }
    public synchronized void setRequestTimeoutMs(int v) { requestTimeoutMs = Math.max(0, v); }
    public synchronized int getDelayMsBetweenMutations() { return delayMsBetweenMutations; }
    public synchronized void setDelayMsBetweenMutations(int v) { delayMsBetweenMutations = Math.max(0, v); }
    public synchronized int getMaxMutationsPerBase() { return maxMutationsPerBase; }
    public synchronized void setMaxMutationsPerBase(int v) { maxMutationsPerBase = Math.max(1, v); }
    public synchronized int getMaxParallelMutations() { return maxParallelMutations; }
    public synchronized void setMaxParallelMutations(int v) { maxParallelMutations = Math.max(1, v); }

    // Project directory handling
    public synchronized void setProjectDir(Path dir) {
        this.projectDir = dir;
    }

    public synchronized Path getProjectDir() { return projectDir; }

    public synchronized Path getProjectSettingsPath() {
        if (projectDir == null) return null;
        return projectDir.resolve("aydaaydor").resolve("settings.yaml");
    }

    public synchronized boolean isEnabled() { return enabled; }
    public synchronized void setEnabled(boolean e) { enabled = e; }

    public synchronized DedupMode getDedupMode() { return dedupMode; }
    public synchronized void setDedupMode(DedupMode mode) { if (mode != null) dedupMode = mode; }
    public synchronized long getDedupTtlMillis() { return dedupTtlMillis; }
    public synchronized void setDedupTtlMillis(long ms) { dedupTtlMillis = Math.max(0, ms); }
    public synchronized int getDedupLruMax() { return dedupLruMax; }
    public synchronized void setDedupLruMax(int max) { dedupLruMax = Math.max(100, max); }

    public synchronized void load() {
        try {
            enabled = Boolean.TRUE.equals(prefs.getBoolean(PREF_ENABLED));
            // Dedup settings
            String modeStr = prefs.getString(PREF_DEDUP_MODE);
            if (modeStr != null) {
                try { dedupMode = DedupMode.valueOf(modeStr); } catch (Exception ignored) {}
            }
            Long ttlPref = prefs.getLong(PREF_DEDUP_TTL_MS);
            if (ttlPref != null && ttlPref > 0) dedupTtlMillis = ttlPref;
            Integer lruPref = prefs.getInteger(PREF_DEDUP_LRU);
            if (lruPref != null && lruPref > 0) dedupLruMax = lruPref;

            // Project dir
            String proj = prefs.getString(PREF_PROJECT_DIR);
            if (proj != null && !proj.isBlank()) {
                try { projectDir = Paths.get(proj.trim()); } catch (Exception ignored) {}
            }

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

            // Ignored params from preferences (legacy)
            ignoredParams.clear();
            String ignoredPref = prefs.getString(PREF_IGNORED_PARAMS);
            if (ignoredPref != null) {
                for (String line : ignoredPref.split("\n")) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    int colon = line.indexOf(':');
                    if (colon <= 0 || colon + 1 >= line.length()) continue;
                    String typeStr = line.substring(0, colon).trim();
                    String name = line.substring(colon + 1).trim();
                    try {
                        HttpParameterType type = HttpParameterType.valueOf(typeStr);
                        addIgnoredParam(type, name);
                    } catch (Exception ignoredEx) {}
                }
            }

            // Load project-level YAML
            try { loadYamlSettings(); }
            catch (Exception e) { log.logToError("AydaAydor: Failed to load YAML settings: " + e); }

            // Provide sensible defaults if YAML missing
            if (ignoredHeaders.isEmpty()) {
                setIgnoredHeaders(Arrays.asList(
                        "host","cookie","content-length","sec-ch-ua-platform","sec-ch-ua","sec-ch-ua-mobile",
                        "content-type","user-agent","accept","origin","sec-fetch-site","sec-fetch-mode",
                        "sec-fetch-dest","referer","accept-encoding","priority"
                ));
            }
            if (skipExtensions.isEmpty()) {
                setSkipExtensions(Arrays.asList(".gif", ".jpg", ".png", ".ico", ".css", ".woff", ".woff2", ".ttf", ".svg"));
            }
        } catch (Exception e) {
            log.logToError("AydaAydor: Failed to load preferences: " + e);
        }
    }

    public synchronized void save() {
        try {
            prefs.setBoolean(PREF_ENABLED, enabled);
            // Dedup settings
            prefs.setString(PREF_DEDUP_MODE, dedupMode.name());
            prefs.setLong(PREF_DEDUP_TTL_MS, dedupTtlMillis);
            prefs.setInteger(PREF_DEDUP_LRU, dedupLruMax);
            if (projectDir != null) {
                prefs.setString(PREF_PROJECT_DIR, projectDir.toString());
            }
            // store groups with stable keys
            List<String> keys = new ArrayList<>();
            int i = 0;
            for (IdGroup g : groups.values()) {
                String key = slug(g.name) + "_" + (i++);
                keys.add(key);
                prefs.setString(PREF_PREFIX + "group." + key + ".name", g.name);
                prefs.setString(PREF_PREFIX + "group." + key + ".ids", String.join("\n", g.ids));
            }
            prefs.setString(PREF_GROUPS, String.join(",", keys));

            prefs.setString(PREF_DENIED, String.join("\n", deniedStrings));
            // Save ignored params back to preferences (legacy)
            List<String> lines = new ArrayList<>();
            for (var e : ignoredParams.entrySet()) {
                HttpParameterType type = e.getKey();
                if (type == null) continue;
                List<String> names = new ArrayList<>(e.getValue());
                Collections.sort(names);
                for (String n : names) lines.add(type.name() + ":" + n);
            }
            prefs.setString(PREF_IGNORED_PARAMS, String.join("\n", lines));

            // Save project-level YAML
            try { saveYamlSettings(); } catch (Exception e) { log.logToError("AydaAydor: Failed to save YAML settings: " + e); }
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

    // YAML load/save
    @SuppressWarnings("unchecked")
    private synchronized void loadYamlSettings() throws IOException {
        Path yamlPath = getProjectSettingsPath();
        if (yamlPath == null || !Files.exists(yamlPath)) return;
        try (InputStream in = Files.newInputStream(yamlPath)) {
            Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
            Object data = yaml.load(in);
            if (!(data instanceof Map)) return;
            Map<?,?> root = (Map<?,?>) data;
            Object ign = root.get("ignored_parameters");
            if (ign instanceof Map) {
                Map<?,?> m = (Map<?,?>) ign;
                for (Map.Entry<?,?> e : m.entrySet()) {
                    String typeStr = String.valueOf(e.getKey());
                    try {
                        HttpParameterType type = HttpParameterType.valueOf(typeStr);
                        Object v = e.getValue();
                        if (v instanceof Collection) {
                            for (Object nameObj : (Collection<?>) v) {
                                if (nameObj == null) continue;
                                String name = String.valueOf(nameObj).trim();
                                if (!name.isEmpty()) addIgnoredParam(type, name);
                            }
                        }
                    } catch (Exception ignoredEx) {}
                }
            }

            Object denied = root.get("denied_strings");
            if (denied instanceof Collection) {
                List<String> ds = new ArrayList<>();
                for (Object o : (Collection<?>) denied) if (o != null) {
                    String s = String.valueOf(o).trim(); if (!s.isEmpty()) ds.add(s);
                }
                setDeniedStrings(ds);
            }

            Object hdrs = root.get("ignored_headers");
            if (hdrs instanceof Collection) {
                List<String> hs = new ArrayList<>();
                for (Object o : (Collection<?>) hdrs) if (o != null) hs.add(String.valueOf(o));
                setIgnoredHeaders(hs);
            }

            Object exts = root.get("skip_extensions");
            if (exts instanceof Collection) {
                List<String> se = new ArrayList<>();
                for (Object o : (Collection<?>) exts) if (o != null) se.add(String.valueOf(o));
                setSkipExtensions(se);
            }

            Object ignoredJson = root.get("ignored_json_keys");
            if (ignoredJson instanceof Collection) {
                List<String> keys = new ArrayList<>();
                for (Object o : (Collection<?>) ignoredJson) if (o != null) keys.add(String.valueOf(o));
                setIgnoredJsonKeys(keys);
            }

            Object paths = root.get("path_exclude_regex");
            if (paths instanceof Collection) {
                List<String> pe = new ArrayList<>();
                for (Object o : (Collection<?>) paths) if (o != null) pe.add(String.valueOf(o));
                setPathExcludeRegex(pe);
            }

            Object groupsNode = root.get("id_groups");
            if (groupsNode instanceof Collection) {
                for (Object obj : (Collection<?>) groupsNode) {
                    if (!(obj instanceof Map)) continue;
                    Map<?,?> g = (Map<?,?>) obj;
                    String name = g.get("name") == null ? null : String.valueOf(g.get("name")).trim();
                    if (name == null || name.isEmpty()) continue;
                    IdGroup ig = new IdGroup(name);
                    Object idsNode = g.get("ids");
                    if (idsNode instanceof Collection) {
                        for (Object id : (Collection<?>) idsNode) {
                            if (id == null) continue;
                            String s = String.valueOf(id).trim();
                            if (!s.isEmpty()) ig.ids.add(s);
                        }
                    }
                    ig.recalculateType();
                    addGroup(ig);
                }
            }

            Object to = root.get("request_timeout_ms");
            if (to instanceof Number) setRequestTimeoutMs(((Number) to).intValue());
            Object delay = root.get("delay_ms_between_mutations");
            if (delay instanceof Number) setDelayMsBetweenMutations(((Number) delay).intValue());
            Object maxm = root.get("max_mutations_per_base");
            if (maxm instanceof Number) setMaxMutationsPerBase(((Number) maxm).intValue());
            Object par = root.get("max_parallel_mutations");
            if (par instanceof Number) setMaxParallelMutations(((Number) par).intValue());

            Object dm = root.get("dedup_mode");
            if (dm instanceof String) {
                try { setDedupMode(DedupMode.valueOf(((String) dm).trim())); } catch (Exception ignoredEx) {}
            }
            Object ttl = root.get("dedup_ttl_ms");
            if (ttl instanceof Number) setDedupTtlMillis(((Number) ttl).longValue());
        }
    }

    private synchronized void saveYamlSettings() throws IOException {
        Path yamlPath = getProjectSettingsPath();
        if (yamlPath == null) return;
        Path parent = yamlPath.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        Map<String,Object> root = new LinkedHashMap<>();
        Map<String,List<String>> ignored = new LinkedHashMap<>();
        // Deterministic order for stable file
        List<HttpParameterType> types = Arrays.stream(HttpParameterType.values()).collect(Collectors.toList());
        for (HttpParameterType t : types) {
            Set<String> names = ignoredParams.get(t);
            if (names == null || names.isEmpty()) continue;
            List<String> list = new ArrayList<>(names);
            Collections.sort(list);
            ignored.put(t.name(), list);
        }
        root.put("ignored_parameters", ignored);

        // additional settings
        root.put("denied_strings", getDeniedStrings());
        root.put("ignored_headers", getIgnoredHeaders());
        root.put("skip_extensions", getSkipExtensions());
        root.put("ignored_json_keys", getIgnoredJsonKeys());
        root.put("path_exclude_regex", getPathExcludeRegex());
        List<Map<String,Object>> groupsOut = new ArrayList<>();
        for (IdGroup g : allGroups()) {
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("name", g.name);
            m.put("ids", new ArrayList<>(g.ids));
            groupsOut.add(m);
        }
        root.put("id_groups", groupsOut);
        root.put("request_timeout_ms", getRequestTimeoutMs());
        root.put("delay_ms_between_mutations", getDelayMsBetweenMutations());
        root.put("max_mutations_per_base", getMaxMutationsPerBase());
        root.put("max_parallel_mutations", getMaxParallelMutations());
        root.put("dedup_mode", getDedupMode().name());
        root.put("dedup_ttl_ms", getDedupTtlMillis());

        DumperOptions opts = new DumperOptions();
        opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        opts.setPrettyFlow(true);
        Yaml yaml = new Yaml(opts);
        String out = yaml.dump(root);
        try (OutputStream os = Files.newOutputStream(yamlPath)) {
            os.write(out.getBytes(StandardCharsets.UTF_8));
        }
    }
}
