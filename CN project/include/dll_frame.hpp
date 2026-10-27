#ifndef DLL_FRAME_HPP
#define DLL_FRAME_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace DLL {

enum class FrameType : uint8_t {
    DATA = 0x01,
    ACK  = 0x02,
    NAK  = 0x03,
    JAM  = 0x04
};

inline std::string frameTypeToString(FrameType t) {
    switch (t) {
        case FrameType::DATA: return "DATA";
        case FrameType::ACK:  return "ACK";
        case FrameType::NAK:  return "NAK";
        case FrameType::JAM:  return "JAM (Collision)";
        default: return "UNKNOWN";
    }
}

#pragma pack(push, 1)
struct FrameHeader {
    uint8_t  preamble[2]; // 0xAA, 0x7E
    uint8_t  frameType;   // FrameType enum
    uint8_t  srcNode;     // Sender ID
    uint8_t  dstNode;     // Receiver ID
    uint16_t seqNum;      // Go-Back-N Sequence number
    uint16_t ackNum;      // Go-Back-N Ack number
    uint8_t  windowSize;  // Sender window size N
    uint16_t payloadLen;  // Length of raw payload bytes
};
#pragma pack(pop)

class DLLFrame {
public:
    FrameHeader header;
    std::vector<uint8_t> payload; // Hamming encoded payload or raw payload
    uint16_t fcs;                 // Frame Check Sequence (CRC16)

    DLLFrame() {
        header.preamble[0] = 0xAA;
        header.preamble[1] = 0x7E;
        header.frameType = static_cast<uint8_t>(FrameType::DATA);
        header.srcNode = 1;
        header.dstNode = 2;
        header.seqNum = 0;
        header.ackNum = 0;
        header.windowSize = 4;
        header.payloadLen = 0;
        fcs = 0;
    }

    // Static constructor helpers
    static DLLFrame createData(uint8_t src, uint8_t dst, uint16_t seq, uint8_t winSize, const std::vector<uint8_t>& encPayload) {
        DLLFrame f;
        f.header.frameType = static_cast<uint8_t>(FrameType::DATA);
        f.header.srcNode = src;
        f.header.dstNode = dst;
        f.header.seqNum = seq;
        f.header.ackNum = 0;
        f.header.windowSize = winSize;
        f.header.payloadLen = static_cast<uint16_t>(encPayload.size());
        f.payload = encPayload;
        f.fcs = f.calculateCRC16();
        return f;
    }

    static DLLFrame createAck(uint8_t src, uint8_t dst, uint16_t ack) {
        DLLFrame f;
        f.header.frameType = static_cast<uint8_t>(FrameType::ACK);
        f.header.srcNode = src;
        f.header.dstNode = dst;
        f.header.seqNum = 0;
        f.header.ackNum = ack;
        f.header.windowSize = 0;
        f.header.payloadLen = 0;
        f.fcs = f.calculateCRC16();
        return f;
    }

    static DLLFrame createNak(uint8_t src, uint8_t dst, uint16_t nakSeq) {
        DLLFrame f;
        f.header.frameType = static_cast<uint8_t>(FrameType::NAK);
        f.header.srcNode = src;
        f.header.dstNode = dst;
        f.header.seqNum = 0;
        f.header.ackNum = nakSeq;
        f.header.windowSize = 0;
        f.header.payloadLen = 0;
        f.fcs = f.calculateCRC16();
        return f;
    }

    static DLLFrame createJam(uint8_t src) {
        DLLFrame f;
        f.header.frameType = static_cast<uint8_t>(FrameType::JAM);
        f.header.srcNode = src;
        f.header.dstNode = 0xFF; // Broadcast
        f.header.seqNum = 0;
        f.header.ackNum = 0;
        f.header.windowSize = 0;
        // 32-bit jam pattern
        f.payload = {0xAA, 0xAA, 0xAA, 0xAA};
        f.header.payloadLen = 4;
        f.fcs = f.calculateCRC16();
        return f;
    }

    // CRC16-CCITT calculation
    uint16_t calculateCRC16() const {
        uint16_t crc = 0xFFFF;
        const uint8_t* hdrPtr = reinterpret_cast<const uint8_t*>(&header);
        for (size_t i = 0; i < sizeof(FrameHeader); ++i) {
            crc ^= (uint16_t)hdrPtr[i] << 8;
            for (int b = 0; b < 8; ++b) {
                if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
                else crc <<= 1;
            }
        }
        for (uint8_t b : payload) {
            crc ^= (uint16_t)b << 8;
            for (int j = 0; j < 8; ++j) {
                if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
                else crc <<= 1;
            }
        }
        return crc;
    }

    bool verifyFCS() const {
        return calculateCRC16() == fcs;
    }

    // Serialize frame to byte vector for UDP transmission
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        buffer.resize(sizeof(FrameHeader) + payload.size() + sizeof(uint16_t));

        std::memcpy(buffer.data(), &header, sizeof(FrameHeader));
        if (!payload.empty()) {
            std::memcpy(buffer.data() + sizeof(FrameHeader), payload.data(), payload.size());
        }
        uint16_t fcsVal = fcs;
        std::memcpy(buffer.data() + sizeof(FrameHeader) + payload.size(), &fcsVal, sizeof(uint16_t));
        return buffer;
    }

    // Deserialize byte vector from UDP packet
    static bool deserialize(const uint8_t* data, size_t length, DLLFrame& outFrame) {
        if (length < sizeof(FrameHeader) + sizeof(uint16_t)) return false;

        std::memcpy(&outFrame.header, data, sizeof(FrameHeader));
        if (outFrame.header.preamble[0] != 0xAA || outFrame.header.preamble[1] != 0x7E) {
            return false;
        }

        size_t payloadSize = outFrame.header.payloadLen;
        if (length < sizeof(FrameHeader) + payloadSize + sizeof(uint16_t)) {
            return false;
        }

        outFrame.payload.resize(payloadSize);
        if (payloadSize > 0) {
            std::memcpy(outFrame.payload.data(), data + sizeof(FrameHeader), payloadSize);
        }

        std::memcpy(&outFrame.fcs, data + sizeof(FrameHeader) + payloadSize, sizeof(uint16_t));
        return true;
    }

    // Hex and formatted dump
    std::string toHexDump() const {
        std::vector<uint8_t> bytes = serialize();
        std::ostringstream ss;
        for (size_t i = 0; i < bytes.size(); ++i) {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)bytes[i] << " ";
            if ((i + 1) % 16 == 0 && i + 1 < bytes.size()) ss << "\n  ";
        }
        return ss.str();
    }

    std::string summary() const {
        std::ostringstream ss;
        ss << "[" << frameTypeToString(static_cast<FrameType>(header.frameType)) << "] "
           << "Node " << (int)header.srcNode << " -> Node " << (int)header.dstNode
           << " | Seq: " << header.seqNum << " | Ack: " << header.ackNum
           << " | Win: " << (int)header.windowSize << " | Len: " << header.payloadLen
           << " | FCS: 0x" << std::hex << std::setw(4) << std::setfill('0') << fcs << std::dec;
        return ss.str();
    }
};

} // namespace DLL

#endif // DLL_FRAME_HPP
