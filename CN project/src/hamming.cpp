#include "../include/hamming.hpp"
#include <iostream>
#include <sstream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <algorithm>

namespace DLL {

int HammingCodec::calculateParityBits(int m) {
    int r = 1;
    while ((1 << r) < (m + r + 1)) {
        r++;
    }
    return r;
}

std::vector<int> HammingCodec::encode(const std::vector<int>& dataBits, std::vector<std::string>* steps) {
    int m = static_cast<int>(dataBits.size());
    if (m == 0) return {};

    int r = calculateParityBits(m);
    int n = m + r;

    // 1-indexed positions in codeword vector of size n
    std::vector<int> codeword(n, 0);

    // Step 1: Place data bits in non-power-of-2 positions
    int dataIdx = 0;
    for (int pos = 1; pos <= n; ++pos) {
        // If pos is not a power of 2
        if ((pos & (pos - 1)) != 0) {
            codeword[pos - 1] = dataBits[dataIdx++];
        }
    }

    if (steps) {
        std::ostringstream ss;
        ss << "Data bits (" << m << " bits): ";
        for (int b : dataBits) ss << b;
        ss << " | Parity bits needed (r): " << r << " (Total codeword length n = " << n << ")";
        steps->push_back(ss.str());
    }

    // Step 2: Calculate each parity bit at positions 2^i (1, 2, 4, 8...)
    for (int i = 0; i < r; ++i) {
        int parityPos = (1 << i);
        int parityVal = 0;
        std::vector<int> coveredPositions;

        for (int pos = 1; pos <= n; ++pos) {
            if ((pos & parityPos) != 0 && pos != parityPos) {
                parityVal ^= codeword[pos - 1];
                coveredPositions.push_back(pos);
            }
        }

        codeword[parityPos - 1] = parityVal;

        if (steps) {
            std::ostringstream ss;
            ss << "Parity bit P" << parityPos << " (at pos " << parityPos << ") covers positions [";
            for (size_t k = 0; k < coveredPositions.size(); ++k) {
                ss << coveredPositions[k] << (k + 1 < coveredPositions.size() ? ", " : "");
            }
            ss << "] -> Value = " << parityVal;
            steps->push_back(ss.str());
        }
    }

    return codeword;
}

HammingResult HammingCodec::decode(const std::vector<int>& receivedCodeword) {
    HammingResult res;
    res.codeword = receivedCodeword;
    res.corruptedCodeword = receivedCodeword;
    res.errorDetected = false;
    res.errorCorrected = false;
    res.errorPosition = 0;

    int n = static_cast<int>(receivedCodeword.size());
    if (n == 0) return res;

    // Determine r
    int r = 0;
    while ((1 << r) <= n) {
        r++;
    }

    // Calculate syndrome
    int syndrome = 0;
    for (int i = 0; i < r; ++i) {
        int parityPos = (1 << i);
        int parityCheck = 0;
        std::vector<int> checkedPositions;

        for (int pos = 1; pos <= n; ++pos) {
            if ((pos & parityPos) != 0) {
                parityCheck ^= receivedCodeword[pos - 1];
                checkedPositions.push_back(pos);
            }
        }

        if (parityCheck != 0) {
            syndrome += parityPos;
        }

        std::ostringstream ss;
        ss << "Parity check C" << parityPos << " over positions [";
        for (size_t k = 0; k < checkedPositions.size(); ++k) {
            ss << checkedPositions[k] << (k + 1 < checkedPositions.size() ? ", " : "");
        }
        ss << "] -> Parity sum = " << parityCheck;
        res.calculationSteps.push_back(ss.str());
    }

    res.errorPosition = syndrome;
    res.correctedCodeword = receivedCodeword;

    if (syndrome == 0) {
        res.errorDetected = false;
        res.calculationSteps.push_back("Syndrome = 0: No bit error detected. Codeword is valid!");
    } else {
        res.errorDetected = true;
        if (syndrome <= n) {
            // Correct the single-bit error
            res.correctedCodeword[syndrome - 1] ^= 1;
            res.errorCorrected = true;
            std::ostringstream ss;
            ss << "Syndrome = " << syndrome << ": Single-bit error detected at position "
               << syndrome << ". Bit flipped from " << receivedCodeword[syndrome - 1]
               << " to " << res.correctedCodeword[syndrome - 1] << " (Successfully corrected!)";
            res.calculationSteps.push_back(ss.str());
        } else {
            res.calculationSteps.push_back("Syndrome exceeds codeword length: Multiple bit errors detected (uncorrectable)!");
        }
    }

    // Extract original data bits from non-power-of-2 positions
    for (int pos = 1; pos <= n; ++pos) {
        if ((pos & (pos - 1)) != 0) {
            res.decodedBits.push_back(res.correctedCodeword[pos - 1]);
        }
    }

    return res;
}

std::vector<int> HammingCodec::stringToBits(const std::string& str) {
    std::vector<int> bits;
    for (unsigned char c : str) {
        for (int b = 7; b >= 0; --b) {
            bits.push_back((c >> b) & 1);
        }
    }
    return bits;
}

std::string HammingCodec::bitsToString(const std::vector<int>& bits) {
    std::string str;
    for (size_t i = 0; i + 8 <= bits.size(); i += 8) {
        unsigned char c = 0;
        for (int b = 0; b < 8; ++b) {
            c = (c << 1) | bits[i + b];
        }
        str.push_back(static_cast<char>(c));
    }
    return str;
}

std::vector<uint8_t> HammingCodec::encodePayload(const std::string& text, std::vector<HammingResult>& blockResults) {
    blockResults.clear();
    std::vector<int> allEncodedBits;

    // Encode nibble by nibble (4 bits -> 7 bits Hamming code)
    for (unsigned char c : text) {
        // High nibble
        std::vector<int> highNibble;
        for (int b = 7; b >= 4; --b) highNibble.push_back((c >> b) & 1);
        std::vector<std::string> stepsH;
        std::vector<int> codeH = encode(highNibble, &stepsH);
        allEncodedBits.insert(allEncodedBits.end(), codeH.begin(), codeH.end());

        HammingResult resH;
        resH.originalBits = highNibble;
        resH.codeword = codeH;
        resH.calculationSteps = stepsH;
        blockResults.push_back(resH);

        // Low nibble
        std::vector<int> lowNibble;
        for (int b = 3; b >= 0; --b) lowNibble.push_back((c >> b) & 1);
        std::vector<std::string> stepsL;
        std::vector<int> codeL = encode(lowNibble, &stepsL);
        allEncodedBits.insert(allEncodedBits.end(), codeL.begin(), codeL.end());

        HammingResult resL;
        resL.originalBits = lowNibble;
        resL.codeword = codeL;
        resL.calculationSteps = stepsL;
        blockResults.push_back(resL);
    }

    // Pack bits into bytes for network transmission
    std::vector<uint8_t> packedBytes;
    uint8_t currentByte = 0;
    int bitCount = 0;

    for (int bit : allEncodedBits) {
        currentByte = (currentByte << 1) | (bit & 1);
        bitCount++;
        if (bitCount == 8) {
            packedBytes.push_back(currentByte);
            currentByte = 0;
            bitCount = 0;
        }
    }
    if (bitCount > 0) {
        currentByte <<= (8 - bitCount); // pad
        packedBytes.push_back(currentByte);
    }

    return packedBytes;
}

std::string HammingCodec::decodePayload(const std::vector<uint8_t>& encodedBytes, std::vector<HammingResult>& blockResults) {
    blockResults.clear();

    // Unpack bytes into bits
    std::vector<int> allBits;
    for (uint8_t byte : encodedBytes) {
        for (int b = 7; b >= 0; --b) {
            allBits.push_back((byte >> b) & 1);
        }
    }

    // Decode 7-bit blocks (Hamming(7,4))
    std::vector<int> extractedDataBits;
    size_t i = 0;
    while (i + 7 <= allBits.size()) {
        std::vector<int> block(allBits.begin() + i, allBits.begin() + i + 7);
        HammingResult res = decode(block);
        blockResults.push_back(res);
        extractedDataBits.insert(extractedDataBits.end(), res.decodedBits.begin(), res.decodedBits.end());
        i += 7;
    }

    // Convert 4-bit nibbles back to characters
    std::string resultStr;
    for (size_t k = 0; k + 8 <= extractedDataBits.size(); k += 8) {
        unsigned char c = 0;
        for (int b = 0; b < 8; ++b) {
            c = (c << 1) | extractedDataBits[k + b];
        }
        resultStr.push_back(static_cast<char>(c));
    }

    return resultStr;
}

bool HammingCodec::injectBitError(std::vector<int>& codeword, int targetBitIndex) {
    if (codeword.empty()) return false;
    int n = static_cast<int>(codeword.size());

    int idx = targetBitIndex;
    if (idx < 1 || idx > n) {
        idx = (std::rand() % n) + 1; // 1-indexed
    }

    codeword[idx - 1] ^= 1; // flip bit
    return true;
}

bool HammingCodec::injectByteError(std::vector<uint8_t>& data, double errorProbability) {
    if (data.empty()) return false;
    double r = static_cast<double>(std::rand()) / RAND_MAX;
    if (r <= errorProbability) {
        int byteIdx = std::rand() % data.size();
        int bitIdx = std::rand() % 8;
        data[byteIdx] ^= (1 << bitIdx); // flip 1 bit
        return true;
    }
    return false;
}

std::string HammingCodec::bitsToBitString(const std::vector<int>& bits, const std::vector<int>& highlightIndices) {
    std::ostringstream ss;
    for (size_t i = 0; i < bits.size(); ++i) {
        int pos = static_cast<int>(i) + 1;
        bool highlight = (std::find(highlightIndices.begin(), highlightIndices.end(), pos) != highlightIndices.end());
        if (highlight) {
            ss << "[" << bits[i] << "]";
        } else {
            ss << bits[i];
        }
    }
    return ss.str();
}

} // namespace DLL
