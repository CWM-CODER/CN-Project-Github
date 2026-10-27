#ifndef GO_BACK_N_HPP
#define GO_BACK_N_HPP

#include <vector>
#include <map>
#include <string>
#include <functional>
#include "dll_frame.hpp"
#include "hamming.hpp"
#include "compat_threading.hpp"

namespace DLL {

struct GBNStats {
    int framesSent;
    int framesRetransmitted;
    int acksReceived;
    int naksReceived;
    int timeouts;
    int framesDelivered;
    int corruptedFramesReceived;
    int outOfOrderFramesReceived;

    GBNStats() : framesSent(0), framesRetransmitted(0), acksReceived(0),
                 naksReceived(0), timeouts(0), framesDelivered(0),
                 corruptedFramesReceived(0), outOfOrderFramesReceived(0) {}
};

class GBNSender {
private:
    uint8_t nodeId;
    uint8_t destNodeId;
    uint8_t windowSize; // N
    uint16_t base;
    uint16_t nextSeqNum;
    int timeoutMs;

    std::map<uint16_t, DLLFrame> windowBuffer;
    uint64_t timerStartMs;
    bool timerRunning;
    FastMutex mtx;

    GBNStats stats;

public:
    GBNSender(uint8_t node, uint8_t dest, uint8_t winSize = 4, int timeout = 1000)
        : nodeId(node), destNodeId(dest), windowSize(winSize), base(0), nextSeqNum(0),
          timeoutMs(timeout), timerStartMs(0), timerRunning(false) {}

    bool canSend() const {
        return (nextSeqNum < base + windowSize);
    }

    uint16_t getBase() const { return base; }
    uint16_t getNextSeqNum() const { return nextSeqNum; }
    uint8_t getWindowSize() const { return windowSize; }

    // Prepare a new DATA frame with Hamming-encoded payload
    DLLFrame createFrame(const std::string& chunkData, std::vector<HammingResult>& hammingResults);

    // Process outgoing frame transmission
    void onFrameSent(const DLLFrame& frame);

    // Process incoming ACK
    // Returns true if window moved forward
    bool onAckReceived(uint16_t ackNum, std::vector<std::string>& logs);

    // Process incoming NAK
    // Returns list of frames to retransmit
    std::vector<DLLFrame> onNakReceived(uint16_t nakSeq, std::vector<std::string>& logs);

    // Check if sender timer expired, returns frames to retransmit if timeout occurred
    std::vector<DLLFrame> checkTimeout(std::vector<std::string>& logs);

    std::string getWindowDiagram() const;
    GBNStats getStats() const { return stats; }
};

class GBNReceiver {
private:
    uint8_t nodeId;
    uint8_t expectedSenderId;
    uint16_t expectedSeqNum;
    std::string reassembledMessage;
    GBNStats stats;

public:
    GBNReceiver(uint8_t node, uint8_t expectedSender)
        : nodeId(node), expectedSenderId(expectedSender), expectedSeqNum(0) {}

    uint16_t getExpectedSeqNum() const { return expectedSeqNum; }
    std::string getReassembledMessage() const { return reassembledMessage; }

    // Process incoming frame
    // Returns response frame (ACK or NAK)
    DLLFrame processFrame(const DLLFrame& frame, bool simulateCorrupt,
                          std::vector<std::string>& logs,
                          std::vector<HammingResult>& hammingResults);

    GBNStats getStats() const { return stats; }
};

} // namespace DLL

#endif // GO_BACK_N_HPP
