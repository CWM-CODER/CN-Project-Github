#include "../include/udp_socket.hpp"
#include <iostream>
#include <cstring>
#include <chrono>

namespace DLL {

bool UDPSocket::wsaInitialized = false;

void UDPSocket::initWSA() {
#ifdef _WIN32
    if (!wsaInitialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
            wsaInitialized = true;
        }
    }
#endif
}

UDPSocket::UDPSocket() : sockFd(INVALID_SOCKET), boundPort(0), ipAddress("127.0.0.1") {
    initWSA();
}

UDPSocket::~UDPSocket() {
    closeSocket();
}

bool UDPSocket::bindPort(uint16_t port, const std::string& ip) {
    closeSocket();
    sockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockFd == INVALID_SOCKET) {
        return false;
    }

    // Set SO_REUSEADDR
    int opt = 1;
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (bind(sockFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closeSocket();
        return false;
    }

    boundPort = port;
    ipAddress = ip;
    return true;
}

bool UDPSocket::sendTo(const std::vector<uint8_t>& data, uint16_t destPort, const std::string& destIp) {
    if (sockFd == INVALID_SOCKET) {
        sockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockFd == INVALID_SOCKET) return false;
    }

    sockaddr_in destAddr;
    std::memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(destPort);
    destAddr.sin_addr.s_addr = inet_addr(destIp.c_str());

    int sent = ::sendto(sockFd, reinterpret_cast<const char*>(data.data()),
                        static_cast<int>(data.size()), 0,
                        reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr));
    return (sent == static_cast<int>(data.size()));
}

int UDPSocket::receiveFrom(std::vector<uint8_t>& outData, uint16_t& outSrcPort, std::string& outSrcIp, int timeoutMs) {
    if (sockFd == INVALID_SOCKET) return -1;

    // Set receive timeout
#ifdef _WIN32
    DWORD tv = timeoutMs;
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    uint8_t buffer[4096];
    sockaddr_in srcAddr;
    socklen_t addrLen = sizeof(srcAddr);
    std::memset(&srcAddr, 0, sizeof(srcAddr));

    int bytesRead = ::recvfrom(sockFd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                               reinterpret_cast<sockaddr*>(&srcAddr), &addrLen);

    if (bytesRead > 0) {
        outData.assign(buffer, buffer + bytesRead);
        outSrcPort = ntohs(srcAddr.sin_port);
        outSrcIp = inet_ntoa(srcAddr.sin_addr);
        return bytesRead;
    }

    return 0; // Timeout or no data
}

void UDPSocket::closeSocket() {
    if (sockFd != INVALID_SOCKET) {
        closesocket(sockFd);
        sockFd = INVALID_SOCKET;
    }
}

// -------------------------------------------------------------
// PCAP Writer implementation
// -------------------------------------------------------------
#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number;  // 0xa1b2c3d4
    uint16_t version_major; // 2
    uint16_t version_minor; // 4
    int32_t  thiszone;      // 0
    uint32_t sigfigs;       // 0
    uint32_t snaplen;       // 65535
    uint32_t network;       // 1 = LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct EthHeader {
    uint8_t  dstMac[6];
    uint8_t  srcMac[6];
    uint16_t etherType; // 0x0800 for IPv4
};

struct IPv4Header {
    uint8_t  verIhl; // 0x45
    uint8_t  tos;    // 0
    uint16_t totalLen;
    uint16_t id;
    uint16_t flagsFrag;
    uint8_t  ttl;    // 64
    uint8_t  protocol; // 17 for UDP
    uint16_t checksum;
    uint32_t srcIp;
    uint32_t dstIp;
};

struct UDPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

PcapWriter::PcapWriter() : pcapFile(nullptr) {}

PcapWriter::~PcapWriter() {
    close();
}

bool PcapWriter::open(const std::string& filename) {
    close();
    pcapFile = fopen(filename.c_str(), "wb");
    if (!pcapFile) return false;
    return writeHeader();
}

bool PcapWriter::writeHeader() {
    if (!pcapFile) return false;
    PcapGlobalHeader gh;
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1; // Ethernet
    return (fwrite(&gh, sizeof(gh), 1, pcapFile) == 1);
}

void PcapWriter::close() {
    if (pcapFile) {
        fflush(pcapFile);
        fclose(pcapFile);
        pcapFile = nullptr;
    }
}

void PcapWriter::writePacket(const uint8_t* data, size_t length, uint16_t srcPort, uint16_t dstPort) {
    if (!pcapFile) return;

    // Build Ethernet + IPv4 + UDP packet
    EthHeader eth;
    std::memset(eth.dstMac, 0x00, 6);
    std::memset(eth.srcMac, 0x00, 6);
    eth.dstMac[5] = 0x02;
    eth.srcMac[5] = 0x01;
    eth.etherType = htons(0x0800); // IPv4

    IPv4Header ip;
    ip.verIhl = 0x45;
    ip.tos = 0;
    uint16_t ipTotalLen = static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(UDPHeader) + length);
    ip.totalLen = htons(ipTotalLen);
    ip.id = htons(1);
    ip.flagsFrag = 0;
    ip.ttl = 64;
    ip.protocol = 17; // UDP
    ip.checksum = 0;
    ip.srcIp = inet_addr("127.0.0.1");
    ip.dstIp = inet_addr("127.0.0.1");

    UDPHeader udp;
    udp.srcPort = htons(srcPort);
    udp.dstPort = htons(dstPort);
    udp.length = htons(static_cast<uint16_t>(sizeof(UDPHeader) + length));
    udp.checksum = 0;

    size_t fullLen = sizeof(EthHeader) + sizeof(IPv4Header) + sizeof(UDPHeader) + length;

    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(epoch).count() % 1000000;

    PcapPacketHeader ph;
    ph.ts_sec = static_cast<uint32_t>(seconds);
    ph.ts_usec = static_cast<uint32_t>(micros);
    ph.incl_len = static_cast<uint32_t>(fullLen);
    ph.orig_len = static_cast<uint32_t>(fullLen);

    fwrite(&ph, sizeof(ph), 1, pcapFile);
    fwrite(&eth, sizeof(eth), 1, pcapFile);
    fwrite(&ip, sizeof(ip), 1, pcapFile);
    fwrite(&udp, sizeof(udp), 1, pcapFile);
    if (length > 0) {
        fwrite(data, 1, length, pcapFile);
    }
    fflush(pcapFile);
}

} // namespace DLL
