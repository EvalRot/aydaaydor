package aydaaydor.config;

import java.util.LinkedHashSet;
import java.util.Set;

public class IdGroup {
    public final String name;
    public final Set<String> ids = new LinkedHashSet<>();
    public GroupType type = GroupType.ALPHANUM;

    public IdGroup(String name) { this.name = name; }

    public void recalculateType() {
        this.type = GroupType.infer(ids);
    }

    public String generateDummyLike(String like) {
        return type.generateDummy(like);
    }
}

