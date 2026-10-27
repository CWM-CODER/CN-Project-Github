#ifndef UDP_SOCKET_HPP
#define UDP_SOCKET_HPP

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

namespace DLL {

class PcapWriter {
private:
    FILE* pcapFile;
    bool writeHeader();

public:
    PcapWriter();
    ~PcapWriter();
    bool open(const std::string& filename);
    void close();
    void writePacket(const uint8_t* data, size_t length, uint16_t srcPort, uint16_t dstPort);
};

class UDPSocket {
private:
    SOCKET sockFd;
    uint16_t boundPort;
    std::string ipAddress;
    static bool wsaInitialized;
    static void initWSA();

public:
    UDPSocket();
    ~UDPSocket();

    bool bindPort(uint16_t port, const std::string& ip = "127.0.0.1");
    bool sendTo(const std::vector<uint8_t>& data, uint16_t destPort, const std::string& destIp = "127.0.0.1");
    int receiveFrom(std::vector<uint8_t>& outData, uint16_t& outSrcPort, std::string& outSrcIp, int timeoutMs = 100);

    uint16_t getBoundPort() const { return boundPort; }
    void closeSocket();
};

} // namespace DLL

#endif // UDP_SOCKET_HPP
