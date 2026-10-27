# Team Contribution Breakdown & Project Work Division

## Computer Networks Project: Data Link Layer Simulation
**Protocol Suite**: CSMA/CD (Non-Persistent) + Hamming Codes (SEC) + Go-Back-N Flow Control + PyShark Packet Analyzer  
**Language**: C++ (Core Simulation Engine) & Python (PyShark Dissector & Verification)

---

## 1. Work Distribution Overview

| Roll Number | Team Member Role | Focus Area | Contribution % |
|:---|:---|:---|:---:|
| **24CSB1A39** | **Project Lead & Core Protocol Architect** | Overall Architecture, Go-Back-N Protocol Engine, CSMA/CD Multi-Access Channel & End-to-End Integration | **40%** |
| **24CSB1A28** | **Error Control Engineer** | Hamming Code (7,4) & SEC Codec, Parity Matrix Math, Noise Injection, Syndrome Calculation & Bit Correction | **20%** |
| **24CSB1A35** | **Network Transport & Systems Engineer** | Winsock2 UDP Loopback Layer, Binary Frame Serialization, CRC16 FCS Checksum & PCAP File Generation | **20%** |
| **24CSB1A46** | **Packet Sniffer & Analytics Lead** | PyShark Dissector, Live Hex/Binary Dump Analyzer, Presentation Deck & Comprehensive Documentation | **20%** |
| **Total** | | | **100%** |

---

## 2. Detailed Member Contributions & Deliverables

### A. Roll No: `24CSB1A39` (Contribution: 40% - Project Lead & Architect)
* **Subsystems Built**:
  1. **Go-Back-N Sliding Window Flow Control Engine (`include/go_back_n.hpp`, `src/go_back_n.cpp`)**:
     - Implemented sender window tracking (`base`, `next_seq_num`, `window_size` $N$).
     - Designed unacknowledged frame buffer (`std::map<uint16_t, DLLFrame> windowBuffer`).
     - Implemented millisecond-accuracy retransmission timer and timeout expiration detection.
     - Implemented cumulative ACK processing, sliding window bounds updates, and window retransmissions.
     - Implemented receiver sequence ordering (`expected_seq_num`), out-of-order frame rejection, and duplicate ACK generation.
  2. **CSMA/CD Non-Persistent Medium Access Control (`include/csma_cd.hpp`, `src/csma_cd.cpp`)**:
     - Built the shared transmission medium (`SharedChannel`) abstraction.
     - Implemented non-persistent carrier sensing: senses channel; if busy, enters random backoff without continuous listening.
     - Implemented collision detection within the propagation delay window ($\tau$).
     - Implemented 32-bit `JAM` signal generation (`0xAAAAAAAA`) and broadcast to immediately abort medium access.
     - Implemented Truncated Binary Exponential Backoff (BEB) algorithm ($R \in [0, 2^k - 1]$, $k = \min(\text{attempt}, 10)$).
  3. **End-to-End System Integration (`src/main.cpp`, `run_all.bat`)**:
     - Orchestrated multi-threaded simulation of concurrent sender and receiver nodes.
     - Implemented interactive CLI menu, configurable parameters (Nodes, Message, Window $N$, Error Rate).
     - Directed overall repository structure and workflow integration.

---

### B. Roll No: `24CSB1A28` (Contribution: 20% - Error Control Engineer)
* **Subsystems Built**:
  1. **Hamming Code Error Detection & Correction (`include/hamming.hpp`, `src/hamming.cpp`)**:
     - Formulated mathematical placement of parity bits at powers of 2 ($1, 2, 4, 8, \dots$).
     - Formulated even-parity equations covering bit subsets:
       $$P_1 = D_1 \oplus D_2 \oplus D_4, \quad P_2 = D_1 \oplus D_3 \oplus D_4, \quad P_4 = D_2 \oplus D_3 \oplus D_4$$
     - Implemented general bit-vector Hamming encoder for arbitrary message lengths ($2^r \ge m + r + 1$).
     - Implemented byte/nibble serialization to pack 7-bit Hamming codewords into network payload bytes.
  2. **Noise Simulation & Syndrome Correction**:
     - Implemented controlled channel noise injection: flipping random single bits in codewords.
     - Implemented receiver syndrome recalculation ($S = C_4 C_2 C_1$); identified the exact 1-indexed error position.
     - Implemented bit inversion for single-error correction (SEC) and clean payload extraction.
  3. **Verification Suite (`python_sim/test_hamming.py`)**:
     - Created 128 automated test vectors verifying all 16 nibbles and all 7 bit positions.

---

### C. Roll No: `24CSB1A35` (Contribution: 20% - Network Transport & Systems Engineer)
* **Subsystems Built**:
  1. **UDP Loopback Network Transport (`include/udp_socket.hpp`, `src/udp_socket.cpp`)**:
     - Implemented native Winsock2 / POSIX UDP socket wrapper.
     - Enabled loopback communication over `127.0.0.1` between independent ports (Node 1 on port 9001, Node 2 on port 9002).
     - Implemented non-blocking receive timeouts and robust socket lifetime management.
  2. **DLL Frame Serialization & Integrity (`include/dll_frame.hpp`)**:
     - Defined packed frame structure with preamble (`0xAA 0x7E`), frame type, addresses, sequence numbers, and payload length.
     - Implemented binary serialization (`serialize()`) and deserialization (`deserialize()`).
     - Implemented CRC16-CCITT Frame Check Sequence (FCS) calculation and verification.
  3. **Libpcap Capture Engine (`PcapWriter`)**:
     - Implemented native binary `.pcap` file generation.
     - Wrapped raw DLL frames into standard Ethernet + IPv4 + UDP packet headers.
     - Allowed any external tool (PyShark, Wireshark, tcpdump) to open `capture.pcap` without third-party drivers.

---

### D. Roll No: `24CSB1A46` (Contribution: 20% - Packet Sniffer & Analytics Lead)
* **Subsystems Built**:
  1. **PyShark Packet Dissector (`sniffer/pyshark_sniffer.py`)**:
     - Built PyShark packet dissector reading `pyshark.FileCapture` and `pyshark.LiveCapture`.
     - Engineered dual-mode operation: leverages Wireshark/TShark backend when installed, with seamless automatic native PCAP fallback when run standalone.
  2. **Packet Inspection & Dump Formatting**:
     - Formatted complete packet layer hierarchy: Ethernet $\rightarrow$ IPv4 $\rightarrow$ UDP $\rightarrow$ DLL Frame.
     - Implemented hexadecimal dump with offset indices and ASCII side-by-side view.
     - Parsed Hamming payload bitstreams, displaying codeword syndromes and validity per packet.
  3. **Presentation & Documentation (`docs/PRESENTATION_DOC.md`, `docs/ARCHITECTURE.md`)**:
     - Designed presentation slides sequence, talking points, and Q&A defense guide.
     - Authored complete technical manuals and installation/execution instructions.
