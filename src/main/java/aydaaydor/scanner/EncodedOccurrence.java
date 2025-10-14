package aydaaydor.scanner;

class EncodedOccurrence {
    final EncodingChain chain;
    // For encoded-fragment match (direct indexOf on encoded string)
    final String fragment;
    final int startIndex;

    // For decode-then-search match (e.g., Base64 wrapping multiple fields)
    final boolean reencodeWhole;
    final String decodedFull;
    final int decodedStart;

    // Encoded-fragment constructor
    EncodedOccurrence(EncodingChain chain, String fragment, int startIndex) {
        this.chain = chain;
        this.fragment = fragment;
        this.startIndex = startIndex;
        this.reencodeWhole = false;
        this.decodedFull = null;
        this.decodedStart = -1;
    }

    // Decode-then-search constructor
    EncodedOccurrence(EncodingChain chain, String decodedFull, int decodedStart, boolean reencodeWhole) {
        this.chain = chain;
        this.fragment = null;
        this.startIndex = -1;
        this.reencodeWhole = reencodeWhole;
        this.decodedFull = decodedFull;
        this.decodedStart = decodedStart;
    }
}
