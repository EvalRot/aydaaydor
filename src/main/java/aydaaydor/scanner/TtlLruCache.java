package aydaaydor.scanner;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Thread-safe TTL + LRU cache for String->timestamp (epochMillis).
 */
class TtlLruCache {
    private final Supplier<Integer> maxEntriesSupplier;
    private final Supplier<Long> ttlMillisSupplier;
    private final Map<String, Long> map;

    TtlLruCache(Supplier<Integer> maxEntriesSupplier, Supplier<Long> ttlMillisSupplier) {
        this.maxEntriesSupplier = maxEntriesSupplier;
        this.ttlMillisSupplier = ttlMillisSupplier;
        this.map = Collections.synchronizedMap(new LinkedHashMap<>(1024, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                Integer max = TtlLruCache.this.maxEntriesSupplier.get();
                return max != null && max > 0 && size() > max;
            }
        });
    }

    boolean isFresh(String key, long now) {
        Long ts;
        synchronized (map) {
            ts = map.get(key);
            if (ts == null) return false;
            long ttl = Math.max(0, ttlMillisSupplier.get());
            if (ttl > 0 && now - ts >= ttl) {
                map.remove(key);
                return false;
            }
            return true;
        }
    }

    void mark(String key, long now) {
        synchronized (map) {
            map.put(key, now);
        }
    }

    void clear() {
        synchronized (map) {
            map.clear();
        }
    }
}

