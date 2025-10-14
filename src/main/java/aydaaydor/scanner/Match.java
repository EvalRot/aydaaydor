package aydaaydor.scanner;

import aydaaydor.config.IdGroup;
import burp.api.montoya.http.message.params.HttpParameter;

class Match {
    final IdGroup group;
    final String matchedId;
    final Candidate candidate;
    final EncodingChain chain;
    final String encodedFragment; // exact substring in candidate.value that corresponds to matchedId (for encoded-fragment mode)
    final int startIndex;         // start index of encodedFragment inside candidate.value
    final boolean reencodeWhole;  // if true, mutate decodedFull at decodedStart and re-encode whole value
    final String decodedFull;
    final int decodedStart;

    Match(IdGroup group, String matchedId, Candidate candidate, EncodingChain chain, String encodedFragment, int startIndex) {
        this.group = group; this.matchedId = matchedId; this.candidate = candidate; this.chain = chain; 
        this.encodedFragment = encodedFragment; this.startIndex = startIndex; 
        this.reencodeWhole = false; this.decodedFull = null; this.decodedStart = -1;
    }

    Match(IdGroup group, String matchedId, Candidate candidate, EncodingChain chain, String decodedFull, int decodedStart, boolean reencodeWhole) {
        this.group = group; this.matchedId = matchedId; this.candidate = candidate; this.chain = chain;
        this.encodedFragment = null; this.startIndex = -1; 
        this.reencodeWhole = reencodeWhole; this.decodedFull = decodedFull; this.decodedStart = decodedStart;
    }

        String locationDescription() {
            switch (candidate.type) {
                case PARAMETER:
                    HttpParameter p = candidate.param;
                    return "parameter '" + p.name() + "' (" + p.type() + ")";
                case HEADER:
                    return "header '" + candidate.headerName + "'";
                case PATH_SEGMENT:
                    return "URL path segment";
                case RAW_QUERY:
                    return "raw query";
                default:
                    return "request";
            }
        }
}
