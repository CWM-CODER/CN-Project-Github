#include "../include/node.hpp"
#include <iostream>
#include <sstream>

namespace DLL {

NetworkNode::NetworkNode(uint8_t id, const std::string& name, uint16_t myPort, uint16_t targetPort,
                         uint8_t targetId, SharedChannel& sharedChan, PcapWriter& pcapRef,
                         std::function<void(const std::string&)> logCallback)
    : nodeId(id), nodeName(name), listenPort(myPort), peerPort(targetPort),
      peerNodeId(targetId), channel(sharedChan), pcap(pcapRef), running(false),
      logFn(logCallback) {
    socket.bindPort(listenPort);
}

NetworkNode::~NetworkNode() {
    stop();
}

void NetworkNode::initSender(uint8_t windowSize, int timeoutMs) {
    sender = std::unique_ptr<GBNSender>(new GBNSender(nodeId, peerNodeId, windowSize, timeoutMs));
}

void NetworkNode::initReceiver() {
    receiver = std::unique_ptr<GBNReceiver>(new GBNReceiver(nodeId, peerNodeId));
}

void NetworkNode::start() {
    if (running) return;
    running = true;
    listenerThread = FastThread([this]() {
        this->listenLoop();
    });
}

void NetworkNode::stop() {
    if (!running) return;
    running = false;
    if (listenerThread.joinable()) {
        listenerThread.join();
    }
    socket.closeSocket();
}

void NetworkNode::listenLoop() {
    while (running) {
        std::vector<uint8_t> rxBuffer;
        uint16_t srcPort = 0;
        std::string srcIp;

        int bytesRead = socket.receiveFrom(rxBuffer, srcPort, srcIp, 50);
        if (bytesRead > 0) {
            DLLFrame rxFrame;
            if (DLLFrame::deserialize(rxBuffer.data(), rxBuffer.size(), rxFrame)) {
                // Log and record to PCAP
                pcap.writePacket(rxBuffer.data(), rxBuffer.size(), srcPort, listenPort);

                FrameType fType = static_cast<FrameType>(rxFrame.header.frameType);

                if (fType == FrameType::ACK && sender) {
                    std::vector<std::string> logs;
                    sender->onAckReceived(rxFrame.header.ackNum, logs);
                    for (size_t i = 0; i < logs.size(); ++i) logFn(logs[i]);
                } else if (fType == FrameType::NAK && sender) {
                    std::vector<std::string> logs;
                    std::vector<DLLFrame> toRetransmit = sender->onNakReceived(rxFrame.header.ackNum, logs);
                    for (size_t i = 0; i < logs.size(); ++i) logFn(logs[i]);

                    for (size_t j = 0; j < toRetransmit.size(); ++j) {
                        transmitFrame(toRetransmit[j]);
                    }
                } else if (fType == FrameType::DATA && receiver) {
                    std::vector<std::string> logs;
                    std::vector<HammingResult> hResults;
                    DLLFrame resp = receiver->processFrame(rxFrame, false, logs, hResults);
                    for (size_t i = 0; i < logs.size(); ++i) logFn(logs[i]);

                    // Send response (ACK or NAK) back to sender
                    std::vector<uint8_t> respBytes = resp.serialize();
                    socket.sendTo(respBytes, srcPort);
                    pcap.writePacket(respBytes.data(), respBytes.size(), listenPort, srcPort);
                } else if (fType == FrameType::JAM) {
                    std::ostringstream js;
                    js << "[" << nodeName << "] Detected broadcast JAM signal from Node "
                       << (int)rxFrame.header.srcNode << ". Pausing transmission queue.";
                    logFn(js.str());
                }
            }
        }

        // Sender timeout check
        if (sender) {
            std::vector<std::string> timeoutLogs;
            std::vector<DLLFrame> toRetransmit = sender->checkTimeout(timeoutLogs);
            for (size_t i = 0; i < timeoutLogs.size(); ++i) logFn(timeoutLogs[i]);

            for (size_t j = 0; j < toRetransmit.size(); ++j) {
                transmitFrame(toRetransmit[j]);
            }
        }
    }
}

bool NetworkNode::transmitFrame(const DLLFrame& frame) {
    auto sendViaSocket = [this](const DLLFrame& f) {
        std::vector<uint8_t> wireBytes = f.serialize();
        socket.sendTo(wireBytes, peerPort);
        pcap.writePacket(wireBytes.data(), wireBytes.size(), listenPort, peerPort);
    };

    return channel.attemptTransmit(nodeId, frame, logFn, sendViaSocket);
}

} // namespace DLL
