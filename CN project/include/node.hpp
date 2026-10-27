#ifndef NODE_HPP
#define NODE_HPP

#include <string>
#include <vector>
#include <memory>
#include "dll_frame.hpp"
#include "hamming.hpp"
#include "csma_cd.hpp"
#include "go_back_n.hpp"
#include "udp_socket.hpp"
#include "compat_threading.hpp"

namespace DLL {

class NetworkNode {
private:
    uint8_t nodeId;
    std::string nodeName;
    uint16_t listenPort;
    uint16_t peerPort;
    uint8_t peerNodeId;

    UDPSocket socket;
    SharedChannel& channel;
    PcapWriter& pcap;

    std::unique_ptr<GBNSender> sender;
    std::unique_ptr<GBNReceiver> receiver;

    bool running;
    FastThread listenerThread;

    std::function<void(const std::string&)> logFn;

    void listenLoop();

public:
    NetworkNode(uint8_t id, const std::string& name, uint16_t myPort, uint16_t targetPort,
                uint8_t targetId, SharedChannel& sharedChan, PcapWriter& pcapRef,
                std::function<void(const std::string&)> logCallback);
    ~NetworkNode();

    void initSender(uint8_t windowSize, int timeoutMs);
    void initReceiver();

    void start();
    void stop();

    // High level transmission
    bool transmitFrame(const DLLFrame& frame);

    GBNSender* getSender() { return sender.get(); }
    GBNReceiver* getReceiver() { return receiver.get(); }
    uint8_t getId() const { return nodeId; }
    std::string getName() const { return nodeName; }
    uint16_t getPort() const { return listenPort; }
};

} // namespace DLL

#endif // NODE_HPP
