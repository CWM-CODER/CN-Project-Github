#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <iomanip>
#include <cstdlib>
#include <ctime>

#include "../include/colors.hpp"
#include "../include/dll_frame.hpp"
#include "../include/hamming.hpp"
#include "../include/csma_cd.hpp"
#include "../include/go_back_n.hpp"
#include "../include/udp_socket.hpp"
#include "../include/node.hpp"
#include "../include/compat_threading.hpp"

using namespace DLL;

void printBanner() {
    std::cout << Colors::BRIGHT_CYAN << Colors::BOLD
              << "================================================================================\n"
              << "     DATA LINK LAYER (DLL) SIMULATION & PROTOCOL ANALYZER (C++ / PYSHARK)     \n"
              << "================================================================================\n"
              << Colors::RESET;
    std::cout << Colors::BRIGHT_YELLOW
              << "  Features: CSMA/CD (Non-Persistent) | Hamming SEC Codec | Go-Back-N Flow Control\n"
              << "  Capture:  Loopback UDP (127.0.0.1) | PCAP Generator  | PyShark Sniffer\n"
              << Colors::RESET;
    std::cout << Colors::DIM
              << "--------------------------------------------------------------------------------\n"
              << Colors::RESET;
}

void printSectionHeader(const std::string& title) {
    std::cout << "\n" << Colors::BRIGHT_BLUE << Colors::BOLD
              << ">>> ========================================================================\n"
              << ">>> " << title << "\n"
              << ">>> ========================================================================\n"
              << Colors::RESET;
}

// ---------------------------------------------------------------------------
// 1. DEMO: CSMA/CD Non-Persistent Carrier Sense & Collision Handling
// ---------------------------------------------------------------------------
void demoCSMACD(int numNodes, double colProb) {
    printSectionHeader("SUB-SYSTEM A: CSMA/CD WITH NON-PERSISTENT STRATEGY");

    std::cout << Colors::WHITE
              << "Rule 1: If channel is IDLE -> Transmit immediately.\n"
              << "Rule 2: If channel is BUSY -> Non-persistent wait: sleep random backoff, then re-sense.\n"
              << "Rule 3: If COLLISION occurs -> Stop immediately, send 32-bit JAM signal, apply BEB.\n\n"
              << Colors::RESET;

    SharedChannel channel(40, 10, colProb);
    auto logger = [](const std::string& log) {
        if (log.find("COLLISION") != std::string::npos || log.find("JAM") != std::string::npos) {
            std::cout << Colors::BRIGHT_RED << Colors::BOLD << "  " << log << Colors::RESET << "\n";
        } else if (log.find("BUSY") != std::string::npos) {
            std::cout << Colors::BRIGHT_YELLOW << "  " << log << Colors::RESET << "\n";
        } else if (log.find("capture") != std::string::npos || log.find("clear") != std::string::npos) {
            std::cout << Colors::BRIGHT_GREEN << "  " << log << Colors::RESET << "\n";
        } else {
            std::cout << Colors::CYAN << "  " << log << Colors::RESET << "\n";
        }
    };

    std::vector<std::unique_ptr<FastThread>> nodeThreads;
    for (int i = 1; i <= numNodes; ++i) {
        nodeThreads.push_back(std::unique_ptr<FastThread>(new FastThread([i, &channel, logger]() {
            std::vector<uint8_t> dummyPayload = {0xDE, 0xAD, 0xBE, 0xEF};
            DLLFrame testFrame = DLLFrame::createData(i, 255, i, 4, dummyPayload);
            channel.attemptTransmit(i, testFrame, logger, [i](const DLLFrame& f) {
                // Sent callback
            });
        })));
    }

    for (size_t i = 0; i < nodeThreads.size(); ++i) {
        if (nodeThreads[i]->joinable()) nodeThreads[i]->join();
    }

    CSMACDStats stats = channel.getStats();
    std::cout << Colors::BOLD << "\n  CSMA/CD Execution Summary:\n" << Colors::RESET;
    std::cout << "  - Total Transmissions:     " << stats.totalTransmissions << "\n"
              << "  - Successful Deliveries:   " << stats.successfulTransmissions << "\n"
              << "  - Busy Channel Senses:     " << stats.busySenses << " (Non-persistent backoffs)\n"
              << "  - Collisions Detected:     " << stats.collisionsDetected << "\n"
              << "  - Jam Signals Broadcasted: " << stats.jamSignalsSent << "\n";
}

// ---------------------------------------------------------------------------
// 2. DEMO: Hamming Code SEC Error Handling
// ---------------------------------------------------------------------------
void demoHamming(const std::string& testWord) {
    printSectionHeader("SUB-SYSTEM B: ERROR CONTROL (HAMMING CODES - SEC)");

    std::cout << Colors::WHITE
              << "Goal: Detect and correct single-bit transmission noise using redundant parity bits.\n"
              << "Parity positions placed at powers of 2 (1, 2, 4, 8, ...).\n"
              << "Input String: \"" << testWord << "\"\n\n"
              << Colors::RESET;

    for (size_t cIdx = 0; cIdx < testWord.size(); ++cIdx) {
        char c = testWord[cIdx];
        std::cout << Colors::BRIGHT_MAGENTA << Colors::BOLD
                  << "--- Processing Character: '" << c << "' (ASCII: " << (int)c << ") ---"
                  << Colors::RESET << "\n";

        // High nibble (4 bits)
        std::vector<int> highNibble;
        for (int b = 7; b >= 4; --b) highNibble.push_back((c >> b) & 1);

        std::vector<std::string> encSteps;
        std::vector<int> codeword = HammingCodec::encode(highNibble, &encSteps);

        std::cout << Colors::CYAN << "  [Sender] Original 4-bit data: ";
        for (size_t i = 0; i < highNibble.size(); ++i) std::cout << highNibble[i];
        std::cout << "\n";

        for (size_t s = 0; s < encSteps.size(); ++s) {
            std::cout << Colors::DIM << "    " << encSteps[s] << Colors::RESET << "\n";
        }

        std::cout << Colors::BRIGHT_GREEN << "  [Sender] Hamming(7,4) Codeword generated: ";
        for (size_t i = 0; i < codeword.size(); ++i) {
            int pos = static_cast<int>(i) + 1;
            if ((pos & (pos - 1)) == 0) {
                std::cout << Colors::BRIGHT_YELLOW << "[" << codeword[i] << "]" << Colors::BRIGHT_GREEN; // Parity
            } else {
                std::cout << codeword[i]; // Data
            }
        }
        std::cout << " (Yellow brackets [] = Parity bits)" << Colors::RESET << "\n";

        // Inject 1-bit noise (channel simulation)
        std::vector<int> noisyCodeword = codeword;
        int flippedBitPos = 3; // Intentionally flip bit 3
        HammingCodec::injectBitError(noisyCodeword, flippedBitPos);

        std::cout << Colors::BRIGHT_RED
                  << "  [Channel Noise] Simulated bit-flip error at bit position " << flippedBitPos << "!\n"
                  << "                  Corrupted Codeword: ";
        for (size_t i = 0; i < noisyCodeword.size(); ++i) {
            if (static_cast<int>(i) + 1 == flippedBitPos) {
                std::cout << Colors::BG_RED << Colors::BRIGHT_WHITE << noisyCodeword[i] << Colors::RESET << Colors::BRIGHT_RED;
            } else {
                std::cout << noisyCodeword[i];
            }
        }
        std::cout << Colors::RESET << "\n";

        // Receiver Decoding & Correction
        HammingResult decResult = HammingCodec::decode(noisyCodeword);
        for (size_t s = 0; s < decResult.calculationSteps.size(); ++s) {
            std::cout << Colors::DIM << "    " << decResult.calculationSteps[s] << Colors::RESET << "\n";
        }

        std::cout << Colors::BRIGHT_GREEN
                  << "  [Receiver] Error Correction Verified!\n"
                  << "             Calculated Syndrome: " << decResult.errorPosition << "\n"
                  << "             Corrected Codeword:  ";
        for (size_t i = 0; i < decResult.correctedCodeword.size(); ++i) std::cout << decResult.correctedCodeword[i];
        std::cout << "\n             Extracted Data:      ";
        for (size_t i = 0; i < decResult.decodedBits.size(); ++i) std::cout << decResult.decodedBits[i];
        std::cout << Colors::RESET << "\n\n";
    }
}

// ---------------------------------------------------------------------------
// 3. DEMO: Go-Back-N Flow Control Protocol Movement
// ---------------------------------------------------------------------------
void demoGoBackN(int windowSize, const std::string& message) {
    printSectionHeader("SUB-SYSTEM C: FLOW CONTROL (GO-BACK-N SLIDING WINDOW)");

    std::cout << Colors::WHITE
              << "Window Size N = " << windowSize << " frames.\n"
              << "Demonstrating: In-Order Delivery, Cumulative ACKs, Packet Loss, Timeout, and Retransmission.\n\n"
              << Colors::RESET;

    GBNSender sender(1, 2, windowSize, 350); // 350ms timeout
    GBNReceiver receiver(2, 1);

    // Split message into chunks (2 chars per frame)
    std::vector<std::string> chunks;
    for (size_t i = 0; i < message.size(); i += 2) {
        chunks.push_back(message.substr(i, 2));
    }

    size_t chunkIdx = 0;
    int step = 1;

    // Simulation scenario: Frame 2 will intentionally be corrupted on first attempt
    bool frame2Corrupted = false;

    while (receiver.getExpectedSeqNum() < chunks.size()) {
        std::cout << Colors::BOLD << Colors::BRIGHT_CYAN
                  << "=== Step " << step++ << ": Current Sender " << sender.getWindowDiagram()
                  << " ===" << Colors::RESET << "\n";

        // Sender transmits up to window capacity
        while (sender.canSend() && chunkIdx < chunks.size()) {
            std::vector<HammingResult> hResults;
            DLLFrame frame = sender.createFrame(chunks[chunkIdx], hResults);
            sender.onFrameSent(frame);

            std::cout << Colors::CYAN
                      << "  [Sender] Transmitting Frame " << frame.header.seqNum
                      << " (Payload: \"" << chunks[chunkIdx] << "\", FCS: 0x"
                      << std::hex << frame.fcs << std::dec << ")\n"
                      << Colors::RESET;

            sleepMs(40);

            // Inject simulated error on Frame 2 once
            bool dropThis = false;
            if (frame.header.seqNum == 2 && !frame2Corrupted) {
                dropThis = true;
                frame2Corrupted = true;
                std::cout << Colors::BRIGHT_RED << Colors::BOLD
                          << "  [Channel] ** NOISE INJECTED: Frame 2 corrupted in transit! **\n"
                          << Colors::RESET;
            }

            std::vector<std::string> rxLogs;
            std::vector<HammingResult> decResults;
            DLLFrame resp = receiver.processFrame(frame, dropThis, rxLogs, decResults);

            for (size_t l = 0; l < rxLogs.size(); ++l) {
                const auto& log = rxLogs[l];
                if (log.find("corrupted") != std::string::npos || log.find("Discarding") != std::string::npos) {
                    std::cout << Colors::BRIGHT_RED << "  " << log << Colors::RESET << "\n";
                } else if (log.find("ACK") != std::string::npos) {
                    std::cout << Colors::BRIGHT_GREEN << "  " << log << Colors::RESET << "\n";
                } else {
                    std::cout << Colors::WHITE << "  " << log << Colors::RESET << "\n";
                }
            }

            // Deliver ACK/NAK back to sender
            if (resp.header.frameType == static_cast<uint8_t>(FrameType::ACK)) {
                std::vector<std::string> ackLogs;
                sender.onAckReceived(resp.header.ackNum, ackLogs);
                for (size_t a = 0; a < ackLogs.size(); ++a) {
                    std::cout << Colors::GREEN << "  " << ackLogs[a] << Colors::RESET << "\n";
                }
            } else if (resp.header.frameType == static_cast<uint8_t>(FrameType::NAK)) {
                std::vector<std::string> nakLogs;
                sender.onNakReceived(resp.header.ackNum, nakLogs);
                for (size_t n = 0; n < nakLogs.size(); ++n) {
                    std::cout << Colors::YELLOW << "  " << nakLogs[n] << Colors::RESET << "\n";
                }
            }

            chunkIdx++;
        }

        // Check if timeout occurs when waiting for ACK
        sleepMs(400);
        std::vector<std::string> timeoutLogs;
        std::vector<DLLFrame> retxList = sender.checkTimeout(timeoutLogs);

        if (!retxList.empty()) {
            for (size_t t = 0; t < timeoutLogs.size(); ++t) {
                std::cout << Colors::BRIGHT_RED << Colors::BOLD << "  " << timeoutLogs[t] << Colors::RESET << "\n";
            }

            // Re-deliver retransmitted frames
            for (size_t r = 0; r < retxList.size(); ++r) {
                const auto& rf = retxList[r];
                std::cout << Colors::BRIGHT_YELLOW
                          << "  [Sender Retransmission] Resending Frame " << rf.header.seqNum << "...\n"
                          << Colors::RESET;

                std::vector<std::string> rxLogs;
                std::vector<HammingResult> decResults;
                DLLFrame resp = receiver.processFrame(rf, false, rxLogs, decResults);

                for (size_t l = 0; l < rxLogs.size(); ++l) {
                    std::cout << Colors::BRIGHT_GREEN << "  " << rxLogs[l] << Colors::RESET << "\n";
                }

                if (resp.header.frameType == static_cast<uint8_t>(FrameType::ACK)) {
                    std::vector<std::string> ackLogs;
                    sender.onAckReceived(resp.header.ackNum, ackLogs);
                    for (size_t a = 0; a < ackLogs.size(); ++a) {
                        std::cout << Colors::GREEN << "  " << ackLogs[a] << Colors::RESET << "\n";
                    }
                }
            }
        }
    }

    std::cout << "\n" << Colors::BRIGHT_GREEN << Colors::BOLD
              << "  [Receiver Final Output] Reassembled Message: \""
              << receiver.getReassembledMessage() << "\"\n"
              << Colors::RESET;
}

// ---------------------------------------------------------------------------
// 4. DEMO: Live UDP Loopback Transmission & PyShark PCAP Generation
// ---------------------------------------------------------------------------
void demoFullIntegrated(int windowSize, const std::string& message, double errProb) {
    printSectionHeader("SUB-SYSTEM D: FULL INTEGRATION OVER UDP LOOPBACK & PCAP GENERATION");

    std::cout << Colors::WHITE
              << "Encapsulating DLL frames inside UDP packets over 127.0.0.1 (Ports: 9001 -> 9002).\n"
              << "Capturing all frames into standard Libpcap file: 'capture.pcap'\n"
              << "All layers active: CSMA/CD + Hamming Codes + Go-Back-N.\n\n"
              << Colors::RESET;

    SharedChannel channel(40, 10, 0.1);
    PcapWriter pcap;
    if (pcap.open("capture.pcap")) {
        std::cout << Colors::GREEN << "  [PCAP Engine] Initialized 'capture.pcap' (Ready for PyShark & Wireshark)\n" << Colors::RESET;
    }

    auto logger = [](const std::string& log) {
        if (log.find("COLLISION") != std::string::npos || log.find("JAM") != std::string::npos || log.find("corrupted") != std::string::npos) {
            std::cout << Colors::BRIGHT_RED << "  " << log << Colors::RESET << "\n";
        } else if (log.find("ACK") != std::string::npos || log.find("accepted") != std::string::npos) {
            std::cout << Colors::BRIGHT_GREEN << "  " << log << Colors::RESET << "\n";
        } else {
            std::cout << Colors::CYAN << "  " << log << Colors::RESET << "\n";
        }
    };

    NetworkNode senderNode(1, "Sender-A", 9001, 9002, 2, channel, pcap, logger);
    NetworkNode receiverNode(2, "Receiver-B", 9002, 9001, 1, channel, pcap, logger);

    senderNode.initSender(windowSize, 500);
    receiverNode.initReceiver();

    senderNode.start();
    receiverNode.start();

    // Transmit data in 2-byte chunks
    std::vector<std::string> chunks;
    for (size_t i = 0; i < message.size(); i += 2) {
        chunks.push_back(message.substr(i, 2));
    }

    std::cout << Colors::YELLOW << "  [Sender] Transmitting message: \"" << message << "\" in " << chunks.size() << " frames...\n\n" << Colors::RESET;

    for (size_t i = 0; i < chunks.size(); ++i) {
        std::vector<HammingResult> hResults;
        DLLFrame frame = senderNode.getSender()->createFrame(chunks[i], hResults);

        // Print PyShark packet hex dump
        std::cout << Colors::BRIGHT_MAGENTA << "\n--- [PyShark Encapsulated DLL Frame #" << frame.header.seqNum << "] ---\n" << Colors::RESET;
        std::cout << Colors::DIM << frame.summary() << "\n" << Colors::RESET;
        std::cout << Colors::WHITE << "Hex Payload Dump:\n  " << frame.toHexDump() << "\n" << Colors::RESET;

        senderNode.getSender()->onFrameSent(frame);
        senderNode.transmitFrame(frame);

        sleepMs(120);
    }

    // Allow completion and ACKs
    sleepMs(800);

    senderNode.stop();
    receiverNode.stop();
    pcap.close();

    std::cout << "\n" << Colors::BRIGHT_GREEN << Colors::BOLD
              << ">>> Integrated Simulation Completed Successfully!\n"
              << ">>> PCAP File Saved: capture.pcap\n"
              << ">>> To inspect packets with PyShark, run: python sniffer/pyshark_sniffer.py\n"
              << Colors::RESET;
}

// ---------------------------------------------------------------------------
// Main Interactive Entrypoint
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    Colors::init();
    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    printBanner();

    int numNodes = 3;
    std::string message = "NETWORKS PROJECT 2026";
    int windowSize = 4;
    double errorProb = 0.20;

    if (argc >= 2) {
        // Quick run with default parameters
        std::cout << Colors::CYAN << "Running with standard configuration...\n" << Colors::RESET;
    } else {
        std::cout << Colors::BRIGHT_YELLOW
                  << "Configuration Parameters (Press Enter to accept defaults):\n"
                  << Colors::RESET;

        std::cout << "1. Number of Nodes [Default = 3]: ";
        std::string input;
        std::getline(std::cin, input);
        if (!input.empty()) numNodes = std::max(2, std::atoi(input.c_str()));

        std::cout << "2. Message Data to Transmit [Default = \"" << message << "\"]: ";
        std::getline(std::cin, input);
        if (!input.empty()) message = input;

        std::cout << "3. Go-Back-N Window Size (N) [Default = 4]: ";
        std::getline(std::cin, input);
        if (!input.empty()) windowSize = std::max(1, std::atoi(input.c_str()));

        std::cout << "4. Error Probability (0.0 to 1.0) [Default = 0.20]: ";
        std::getline(std::cin, input);
        if (!input.empty()) errorProb = std::atof(input.c_str());
    }

    std::cout << Colors::GREEN << "\nSimulation Parameters Configured:\n"
              << "  - Nodes:             " << numNodes << "\n"
              << "  - Payload Message:   \"" << message << "\"\n"
              << "  - Window Size (N):   " << windowSize << "\n"
              << "  - Error Probability: " << (errorProb * 100.0) << "%\n\n"
              << Colors::RESET;

    // Execute all 4 core sub-systems
    demoCSMACD(numNodes, 0.35); // 35% collision trigger for clear demonstration
    demoHamming(message.substr(0, (message.size() < 4 ? message.size() : 4)));
    demoGoBackN(windowSize, message);
    demoFullIntegrated(windowSize, message, errorProb);

    return 0;
}
