#ifndef HAMMING_HPP
#define HAMMING_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace DLL {

struct HammingResult {
    std::string originalDataStr;
    std::vector<int> originalBits;
    std::vector<int> codeword;           // Parity bits at powers of 2 (1-indexed: 1, 2, 4, 8...)
    std::vector<int> corruptedCodeword;  // Codeword after noise injection (if any)
    int errorPosition;                   // 1-indexed syndrome position (0 = no error)
    bool errorDetected;
    bool errorCorrected;
    std::vector<int> correctedCodeword;
    std::vector<int> decodedBits;
    std::string decodedDataStr;
    std::vector<std::string> calculationSteps;
};

class HammingCodec {
public:
    // Determine number of parity bits required for m data bits: 2^r >= m + r + 1
    static int calculateParityBits(int m);

    // Encode a vector of data bits into a Hamming codeword
    // Parity positions: 1, 2, 4, 8, ... (1-indexed)
    static std::vector<int> encode(const std::vector<int>& dataBits, std::vector<std::string>* steps = nullptr);

    // Decode a received Hamming codeword, detect and correct single-bit error
    static HammingResult decode(const std::vector<int>& receivedCodeword);

    // Convenience functions for string payloads
    static std::vector<int> stringToBits(const std::string& str);
    static std::string bitsToString(const std::vector<int>& bits);

    // Encode complete ASCII string to Hamming bit stream
    // Uses standard 7,4 nibble encoding or block encoding
    static std::vector<uint8_t> encodePayload(const std::string& text, std::vector<HammingResult>& blockResults);
    static std::string decodePayload(const std::vector<uint8_t>& encodedBytes, std::vector<HammingResult>& blockResults);

    // Noise injection: flip a specific bit (1-indexed) or a random bit
    static bool injectBitError(std::vector<int>& codeword, int targetBitIndex = -1);
    static bool injectByteError(std::vector<uint8_t>& data, double errorProbability = 0.2);

    // Formatter helpers
    static std::string bitsToBitString(const std::vector<int>& bits, const std::vector<int>& highlightIndices = {});
};

} // namespace DLL

#endif // HAMMING_HPP
