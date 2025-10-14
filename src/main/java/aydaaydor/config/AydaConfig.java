package aydaaydor.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;

import java.util.*;

public class AydaConfig {
    private static final String PREF_PREFIX = "ayda_aydor.";
    private static final String PREF_GROUPS = PREF_PREFIX + "groups"; // CSV of keys
    private static final String PREF_DENIED = PREF_PREFIX + "denied"; // lines
    private static final String PREF_ENABLED = PREF_PREFIX + "enabled"; // boolean
    private static final String PREF_DEDUP_MODE = PREF_PREFIX + "dedup.mode"; // STRICT | CONTENT_AWARE
    private static final String PREF_DEDUP_TTL_MS = PREF_PREFIX + "dedup.ttl_ms"; // long ms
    private static final String PREF_DEDUP_LRU = PREF_PREFIX + "dedup.lru"; // int entries

    private final Preferences prefs;
    private final Logging log;
    private final Map<String, IdGroup> groups = new LinkedHashMap<>();
    private final List<String> deniedStrings = new ArrayList<>();
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

    public synchronized void save() {
        try {
            prefs.setBoolean(PREF_ENABLED, enabled);
            // Dedup settings
            prefs.setString(PREF_DEDUP_MODE, dedupMode.name());
            prefs.setLong(PREF_DEDUP_TTL_MS, dedupTtlMillis);
            prefs.setInteger(PREF_DEDUP_LRU, dedupLruMax);
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
