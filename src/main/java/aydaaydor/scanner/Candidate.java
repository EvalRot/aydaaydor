package aydaaydor.scanner;

import burp.api.montoya.http.message.params.HttpParameter;

class Candidate {
    enum Type { PARAMETER, HEADER, PATH_SEGMENT, RAW_QUERY }
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

    static Candidate forRawQuery(String value) {
        return new Candidate(Type.RAW_QUERY, value, null, null, -1);
    }
}
