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

    // Encode a target value and then search in encoded candidate case constructor
    EncodedOccurrence(EncodingChain chain, String fragment, int startIndex) {
        this.chain = chain;
        this.fragment = fragment;
        this.startIndex = startIndex;
        this.reencodeWhole = false;
        this.decodedFull = null;
        this.decodedStart = -1;
    }

    // Decode entire candidate value and then search for a target value in it constructor
    EncodedOccurrence(EncodingChain chain, String decodedFull, int decodedStart, boolean reencodeWhole) {
        this.chain = chain;
        this.fragment = null;
        this.startIndex = -1;
        this.reencodeWhole = reencodeWhole; // is needed for reencoding the whole candidate after the target value is replaced with other ID from a group
        this.decodedFull = decodedFull;
        this.decodedStart = decodedStart;
    }
}
