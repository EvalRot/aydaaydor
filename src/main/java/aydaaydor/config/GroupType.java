package aydaaydor.config;

import java.util.Collection;
import java.util.Random;
import java.util.regex.Pattern;

public enum GroupType {
    NUMERIC, ALPHA, ALPHANUM, UUID;

    public static GroupType infer(Collection<String> values) {
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

    public String generateDummy(String like) {
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

