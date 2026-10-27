#include "../include/go_back_n.hpp"
#include <iostream>
#include <sstream>

namespace DLL {

DLLFrame GBNSender::createFrame(const std::string& chunkData, std::vector<HammingResult>& hammingResults) {
    FastLock lock(mtx);
    std::vector<uint8_t> encodedBytes = HammingCodec::encodePayload(chunkData, hammingResults);
    return DLLFrame::createData(nodeId, destNodeId, nextSeqNum, windowSize, encodedBytes);
}

void GBNSender::onFrameSent(const DLLFrame& frame) {
    FastLock lock(mtx);
    windowBuffer[frame.header.seqNum] = frame;

    if (base == nextSeqNum) {
        timerStartMs = getTimestampMs();
        timerRunning = true;
    }

    nextSeqNum++;
    stats.framesSent++;
}

bool GBNSender::onAckReceived(uint16_t ackNum, std::vector<std::string>& logs) {
    FastLock lock(mtx);
    stats.acksReceived++;

    if (ackNum > base) {
        std::ostringstream ss;
        ss << "[Go-Back-N Sender] ACK " << ackNum << " received (Cumulative). "
           << "Sliding window from [" << base << ".." << (nextSeqNum - 1) << "] ";

        for (uint16_t seq = base; seq < ackNum; ++seq) {
            windowBuffer.erase(seq);
        }
        base = ackNum;

        ss << "to [" << base << ".." << (base + windowSize - 1) << "].";
        logs.push_back(ss.str());

        if (base == nextSeqNum) {
            timerRunning = false; // All sent frames acknowledged
            logs.push_back("[Go-Back-N Sender] All in-flight frames acknowledged. Timer stopped.");
        } else {
            timerStartMs = getTimestampMs(); // Restart timer for base
            std::ostringstream ts;
            ts << "[Go-Back-N Sender] Timer restarted for oldest unacknowledged Frame " << base << ".";
            logs.push_back(ts.str());
        }
        return true;
    } else {
        std::ostringstream ss;
        ss << "[Go-Back-N Sender] Duplicate/Old ACK " << ackNum << " ignored (Current base is " << base << ").";
        logs.push_back(ss.str());
        return false;
    }
}

std::vector<DLLFrame> GBNSender::onNakReceived(uint16_t nakSeq, std::vector<std::string>& logs) {
    FastLock lock(mtx);
    stats.naksReceived++;

    std::vector<DLLFrame> retransmitList;
    std::ostringstream ss;
    ss << "[Go-Back-N Sender] NAK received for Frame " << nakSeq << "! Go-Back-N protocol triggered.";
    logs.push_back(ss.str());

    std::ostringstream rs;
    rs << "[Go-Back-N Sender] Retransmitting frames in current window: [ ";
    for (uint16_t seq = base; seq < nextSeqNum; ++seq) {
        if (windowBuffer.find(seq) != windowBuffer.end()) {
            retransmitList.push_back(windowBuffer[seq]);
            rs << seq << " ";
            stats.framesRetransmitted++;
        }
    }
    rs << "]";
    logs.push_back(rs.str());

    timerStartMs = getTimestampMs();
    timerRunning = true;
    return retransmitList;
}

std::vector<DLLFrame> GBNSender::checkTimeout(std::vector<std::string>& logs) {
    FastLock lock(mtx);
    std::vector<DLLFrame> retransmitList;

    if (!timerRunning || base == nextSeqNum) {
        return retransmitList;
    }

    uint64_t now = getTimestampMs();
    uint64_t elapsed = now - timerStartMs;

    if (elapsed >= static_cast<uint64_t>(timeoutMs)) {
        stats.timeouts++;
        std::ostringstream ss;
        ss << "[Go-Back-N Sender] !!! TIMEOUT on Frame " << base << " (" << elapsed << "ms elapsed, timeout="
           << timeoutMs << "ms)! Go-Back-N Retransmission triggered.";
        logs.push_back(ss.str());

        std::ostringstream rs;
        rs << "[Go-Back-N Sender] Retransmitting entire unacknowledged window [ ";
        for (uint16_t seq = base; seq < nextSeqNum; ++seq) {
            if (windowBuffer.find(seq) != windowBuffer.end()) {
                retransmitList.push_back(windowBuffer[seq]);
                rs << seq << " ";
                stats.framesRetransmitted++;
            }
        }
        rs << "]";
        logs.push_back(rs.str());

        // Restart timer
        timerStartMs = getTimestampMs();
    }

    return retransmitList;
}

std::string GBNSender::getWindowDiagram() const {
    std::ostringstream ss;
    ss << "Window [";
    for (uint16_t s = base; s < base + windowSize; ++s) {
        if (s < nextSeqNum) {
            ss << " " << s << "*"; // Sent, unacked
        } else {
            ss << " " << s << " "; // Usable
        }
    }
    ss << " ] (Base=" << base << ", Next=" << nextSeqNum << ", N=" << (int)windowSize << ")";
    return ss.str();
}

// -------------------------------------------------------------
// GBN Receiver implementation
// -------------------------------------------------------------
DLLFrame GBNReceiver::processFrame(const DLLFrame& frame, bool simulateCorrupt,
                                   std::vector<std::string>& logs,
                                   std::vector<HammingResult>& hammingResults) {
    // Check if frame is corrupted
    if (simulateCorrupt || !frame.verifyFCS()) {
        stats.corruptedFramesReceived++;
        std::ostringstream ss;
        ss << "[Go-Back-N Receiver] Frame " << frame.header.seqNum << " corrupted! (FCS error / noise). Discarding frame.";
        logs.push_back(ss.str());

        std::ostringstream ns;
        ns << "[Go-Back-N Receiver] Sending NAK for expected Frame " << expectedSeqNum;
        logs.push_back(ns.str());

        return DLLFrame::createNak(nodeId, frame.header.srcNode, expectedSeqNum);
    }

    // Attempt Hamming decoding
    std::string decodedChunk = HammingCodec::decodePayload(frame.payload, hammingResults);
    bool anyCorrected = false;
    for (size_t i = 0; i < hammingResults.size(); ++i) {
        if (hammingResults[i].errorCorrected) anyCorrected = true;
    }
    if (anyCorrected) {
        std::ostringstream hs;
        hs << "[Hamming Codec] Single-bit transmission error detected and successfully corrected via parity syndrome!";
        logs.push_back(hs.str());
    }

    // In-order check
    if (frame.header.seqNum == expectedSeqNum) {
        reassembledMessage += decodedChunk;
        stats.framesDelivered++;
        expectedSeqNum++;

        std::ostringstream ss;
        ss << "[Go-Back-N Receiver] In-order Frame " << frame.header.seqNum
           << " accepted! Decoded data chunk: \"" << decodedChunk << "\". Expected next: " << expectedSeqNum;
        logs.push_back(ss.str());

        std::ostringstream as;
        as << "[Go-Back-N Receiver] Transmitting cumulative ACK " << expectedSeqNum << " to Node " << (int)frame.header.srcNode;
        logs.push_back(as.str());

        return DLLFrame::createAck(nodeId, frame.header.srcNode, expectedSeqNum);
    } else if (frame.header.seqNum > expectedSeqNum) {
        // Out of order frame
        stats.outOfOrderFramesReceived++;
        std::ostringstream ss;
        ss << "[Go-Back-N Receiver] Out-of-order Frame " << frame.header.seqNum
           << " received! (Expecting " << expectedSeqNum << "). Discarding frame.";
        logs.push_back(ss.str());

        std::ostringstream as;
        as << "[Go-Back-N Receiver] Re-sending duplicate ACK " << expectedSeqNum;
        logs.push_back(as.str());

        return DLLFrame::createAck(nodeId, frame.header.srcNode, expectedSeqNum);
    } else {
        // Duplicate frame already processed
        std::ostringstream ss;
        ss << "[Go-Back-N Receiver] Duplicate old Frame " << frame.header.seqNum
           << " received. Re-sending ACK " << expectedSeqNum;
        logs.push_back(ss.str());

        return DLLFrame::createAck(nodeId, frame.header.srcNode, expectedSeqNum);
    }
}

} // namespace DLL
