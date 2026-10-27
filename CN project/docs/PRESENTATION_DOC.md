# Complete Presentation Guide & Project Lifecycle Document

## Project: Implementation of Data Link Layer Protocol Suite
**Core Technologies**: C++14 (High-Performance DLL Engine), Python 3 (PyShark Packet Dissector & Analyzer), Winsock2 UDP Loopback Transport, Libpcap.

---

## 1. Executive Summary

This project simulates a complete, fully functioning **Data Link Layer (Layer 2)** of the OSI model. It brings together three fundamental pillars of computer networking:
1. **Multiple Access Control (MAC)**: Non-Persistent CSMA/CD with Truncated Binary Exponential Backoff (BEB) and 32-bit Jam Signaling.
2. **Error Control**: Single Error Correction (SEC) Hamming Codes with dynamic bit parity calculation, channel noise simulation, and syndrome correction.
3. **Flow Control**: Go-Back-N (GBN) Sliding Window protocol with cumulative acknowledgements (ACKs), negative acknowledgements (NAKs), transmission timers, and full window retransmission on timeout.
4. **Network Encapsulation & Sniffing**: Encapsulation of custom DLL frames into standard UDP datagrams transmitted across localhost (`127.0.0.1`), generating standard `.pcap` files inspected via **PyShark**.

---

## 2. Project Lifecycle: How We Started and What Was Done in Sequence

### Phase 1: Problem Analysis & Mathematical Formulation (Day 1)
- **Starting Point**: Analyzed the assignment requirements to design a modular Layer-2 architecture that could run on real network sockets without requiring kernel-level raw socket privileges.
- **Decision**: Encapsulate custom Data Link Layer frames inside standard UDP packets over the loopback interface (`127.0.0.1`).
- **Mathematical Design**: Formulated Hamming Code (7,4) parity equations:
  $$P_1 = D_1 \oplus D_2 \oplus D_4, \quad P_2 = D_1 \oplus D_3 \oplus D_4, \quad P_4 = D_2 \oplus D_3 \oplus D_4$$
  and syndrome equations $S_1, S_2, S_4$ to correct single-bit errors.

### Phase 2: Frame Structure & Transport Protocol Design (Day 2)
- Created the byte-level DLL Frame layout with a 2-byte sync preamble (`0xAA 0x7E`), frame type flags (`DATA`, `ACK`, `NAK`, `JAM`), sequence numbers, window size, payload length, and CRC16-CCITT Frame Check Sequence (FCS).
- Implemented `PcapWriter` to generate genuine `.pcap` capture files directly containing Ethernet + IPv4 + UDP + DLL Frame structures.

### Phase 3: Subsystem Implementation in Sequence (Day 3)
1. **Subsystem A - CSMA/CD Engine**: Implemented non-persistent carrier sensing, channel lockouts, collision detection within the propagation delay window ($\tau$), 32-bit JAM signals (`0xAAAAAAAA`), and Binary Exponential Backoff.
2. **Subsystem B - Hamming Codec**: Implemented bitwise encoder, bit-flip noise injector, syndrome evaluator, and bit corrector.
3. **Subsystem C - Go-Back-N Engine**: Implemented sender window tracking (`base`, `next_seq_num`, $N$), timeout timer, cumulative ACKs, and receiver in-order sequence verification.

### Phase 4: Full Multi-Threaded Integration & Socket Dispatch (Day 4)
- Linked the C++ modules using cross-platform threading (`compat_threading.hpp`), supporting MinGW g++ on Windows.
- Constructed concurrent network nodes communicating over UDP loopback ports (Node 1 on port 9001, Node 2 on port 9002).

### Phase 5: PyShark Dissector & Protocol Sniffing (Day 5)
- Developed `sniffer/pyshark_sniffer.py` using PyShark to sniff and dissect packets traversing the loopback interface.
- Built detailed packet breakdowns: Ethernet, IPv4, UDP, custom DLL header fields, Hamming codeword status, and side-by-side hex/ASCII dumps.

### Phase 6: Automated Testing & Packaging (Day 6)
- Built automated batch scripts (`build.bat`, `run_all.bat`), automated Python unit tests (`test_hamming.py`), and documentation.

---

## 3. Team Member Contributions & Roles

| Roll Number | Role | Key Contributions | % Weight |
|:---|:---|:---|:---:|
| **24CSB1A39** | **Project Lead & Core Protocol Architect** | Overall System Design, Go-Back-N Sliding Window Engine, CSMA/CD Multi-Node Channel & State Machine, End-to-End System Integration. | **40%** |
| **24CSB1A28** | **Error Control Engineer** | Hamming Code (7,4) & SEC Implementation, Parity Generation at Powers of 2, Noise Simulation, Syndrome Recalculation & Correction. | **20%** |
| **24CSB1A35** | **Network Transport & Systems Engineer** | Winsock2 UDP Loopback Layer (`127.0.0.1`), Frame Serialization/Deserialization, CRC16 FCS Checksum & Libpcap File Generation. | **20%** |
| **24CSB1A46** | **Packet Sniffer & Analytics Lead** | PyShark Dissector Integration (`pyshark_sniffer.py`), Hex/Binary Dumps, Layer Dissection & Comprehensive Documentation. | **20%** |

---

## 4. Slide-by-Slide Presentation Structure (10 Slides)

### Slide 1: Title & Team Credentials
- **Title**: Simulation of Data Link Layer: CSMA/CD, Hamming Codes & Go-Back-N with PyShark
- **Course**: Computer Networks Laboratory
- **Team**:
  - `24CSB1A39` (40% - Lead Architect)
  - `24CSB1A28` (20% - Error Control)
  - `24CSB1A35` (20% - Transport & Systems)
  - `24CSB1A46` (20% - Packet Sniffer & Analytics)
- **Speaker Notes**: *"Good morning respected evaluators. Today our team presents a complete Data Link Layer simulation developed in C++ and analyzed live using PyShark over actual UDP network sockets."*

---

### Slide 2: Objectives & Architecture Overview
- **Goal**: Simulate Layer 2 functionality without kernel drivers by encapsulating DLL frames inside standard UDP loopback packets.
- **Three Core Pillars**:
  1. *MAC Sublayer*: CSMA/CD (Non-Persistent)
  2. *Error Control*: Hamming Single Error Correction (SEC)
  3. *Flow Control*: Go-Back-N Sliding Window ($N$ frames)
- **Inspection**: Live capture via PyShark and Wireshark using standard Libpcap format.
- **Speaker Notes**: *"Instead of a toy discrete-event script, we built an actual network communication system where independent processes exchange serialized binary packets over localhost sockets."*

---

### Slide 3: Subsystem 1 - Medium Access Control (CSMA/CD Non-Persistent)
- **Carrier Sensing**:
  - Senses channel before transmitting.
  - If **IDLE**: Immediately transmits.
  - If **BUSY**: Non-persistent strategy — backs off a random delay ($1 \dots 4$ slot times) and sleeps. Does *not* monopolize CPU with continuous sensing.
- **Collision Detection**:
  - If concurrent transmissions occur within propagation delay $\tau$, collision is flagged.
  - Nodes abort transmission immediately and broadcast a 32-bit **JAM Signal** (`0xAAAAAAAA`).
  - **Truncated Binary Exponential Backoff (BEB)**:
    $$R \in [0, 2^k - 1], \quad k = \min(\text{collisionCount}, 10)$$
    Backoff time: $T_b = R \times \text{SlotTime}$.
- **Speaker Notes**: *"Non-persistent CSMA reduces collision probability compared to 1-persistent CSMA while BEB dynamically adjusts to channel congestion."*

---

### Slide 4: Subsystem 2 - Error Control (Hamming Codes - SEC)
- **Encoding**:
  - Parity bits positioned at powers of 2 (positions $1, 2, 4, 8, \dots$).
  - For $m=4$ data bits, $r=3$ parity bits are required since $2^3 \ge 4 + 3 + 1$.
  - Generates 7-bit codewords: $[P_1, P_2, D_1, P_4, D_2, D_3, D_4]$.
- **Noise Injection**:
  - Simulates physical transmission noise by inverting a bit at index $pos$.
- **Receiver Syndrome Evaluation**:
  - Calculates parity checks $C_1, C_2, C_4$:
    $$\text{Syndrome} = C_4 \cdot 4 + C_2 \cdot 2 + C_1 \cdot 1$$
  - If Syndrome $= 0$: Valid, no error.
  - If Syndrome $> 0$: Bit at index `Syndrome` is inverted to restore the original data!
- **Speaker Notes**: *"Our codec processes ASCII strings into nibbles, encodes them into 7-bit blocks, and successfully recovers data even when transmission noise flips bits."*

---

### Slide 5: Subsystem 3 - Flow Control (Go-Back-N Protocol)
- **Sender Mechanics**:
  - Maintains window $[base \dots base + N - 1]$.
  - Can transmit up to $N$ unacknowledged frames.
  - Starts a timer for the oldest unacknowledged frame (`base`).
- **Receiver Mechanics**:
  - Tracks `expected_seq_num`.
  - Discards out-of-order frames to preserve strict FIFO ordering.
  - Sends cumulative ACKs for the last successfully received in-order frame.
- **Error Handling & Timeout**:
  - If a frame is corrupted or dropped, receiver discards it and issues a NAK or duplicate ACK.
  - Sender timer expires $\rightarrow$ Go-Back-N triggers $\rightarrow$ retransmits all frames from `base` to `next_seq_num - 1`.
- **Speaker Notes**: *"In our live demo, we intentionally corrupt Frame 2. You will observe out-of-order discards and full window retransmission."*

---

### Slide 6: Frame Structure & UDP Loopback Encapsulation
- **Custom DLL Frame Layout**:
  ```
  +---------------+---------------+---------------+---------------+
  |   Preamble    |  Frame Type   |  Src Node ID  |  Dst Node ID  |
  | (0xAA, 0x7E)  | (DATA/ACK/JAM)|   (1 byte)    |   (1 byte)    |
  +---------------+---------------+---------------+---------------+
  |       Sequence Number         |     Acknowledgement Number    |
  |          (2 bytes)            |           (2 bytes)           |
  +---------------+---------------+---------------+---------------+
  |  Window Size  | Payload Length|   Hamming-Encoded Payload     |
  |   (1 byte)    |   (2 bytes)   |       (Variable size)         |
  +---------------+---------------+---------------+---------------+
  |                  CRC16 Frame Check Sequence                   |
  +---------------------------------------------------------------+
  ```
- **Loopback Route**: Transmitted over UDP port 9001 $\rightarrow$ port 9002 on `127.0.0.1`.
- **Speaker Notes**: *"This clean serialization ensures our frames can be captured and decoded by any standard protocol analyzer."*

---

### Slide 7: PyShark Integration & Dissection Engine
- **PyShark Execution**:
  - Reads live network packets or the generated `capture.pcap`.
  - Parses protocol stack: Ethernet $\rightarrow$ IPv4 $\rightarrow$ UDP $\rightarrow$ Custom DLL.
- **Dissection Capabilities**:
  - Flags frame types in color.
  - Validates sequence numbers and cumulative ACK sliding.
  - Evaluates Hamming syndrome for every 7-bit payload block.
  - Displays formatted side-by-side hexadecimal and ASCII packet dump.
- **Speaker Notes**: *"PyShark gives us industry-grade packet inspection, proving our simulated Data Link Layer works over genuine network interfaces."*

---

### Slide 8: Live Demonstration & Console Output Highlights
- **CSMA/CD Log**:
  `[CSMA/CD] Node 1 senses channel: IDLE. Initiating transmission...`  
  `[CSMA/CD] !!! COLLISION DETECTED on medium!`  
  `[CSMA/CD] Broadcasting 32-bit JAM SIGNAL (0xAAAAAAAA)...`  
  `[CSMA/CD] Binary Exponential Backoff: k=1, waiting 45ms`
- **Hamming Codec Log**:
  `[Sender] Hamming(7,4) Codeword generated: [1][1]0[0]100`  
  `[Channel Noise] Simulated bit-flip at position 3!`  
  `[Receiver] Calculated Syndrome: 3 -> Single-bit error corrected!`
- **Go-Back-N Log**:
  `[Go-Back-N Receiver] Frame 2 corrupted! Discarding frame.`  
  `[Go-Back-N Sender] TIMEOUT on Frame 2! Retransmitting window [ 2 3 ]`  
  `[Receiver Final Output] Reassembled Message: "NETWORKS PROJECT 2026"`

---

### Slide 9: Work Breakdown Matrix

```
+--------------------------------------------------------------------------+
|                  TEAM WORK DIVISION & OWNERSHIP                          |
+-------------------+-----------------+------------------------------------+
| Roll Number       | Share           | Key Subsystems Owned               |
+-------------------+-----------------+------------------------------------+
| 24CSB1A39 (Lead)  | 40%             | GBN Engine, CSMA/CD Channel,       |
|                   |                 | System Integration & CLI Driver    |
+-------------------+-----------------+------------------------------------+
| 24CSB1A28         | 20%             | Hamming Codec, Parity Matrix Math, |
|                   |                 | Noise Injection & Unit Tests       |
+-------------------+-----------------+------------------------------------+
| 24CSB1A35         | 20%             | Winsock2 UDP Loopback, Framing,    |
|                   |                 | CRC16 FCS & PCAP Generator         |
+-------------------+-----------------+------------------------------------+
| 24CSB1A46         | 20%             | PyShark Sniffer Dissector, Hex     |
|                   |                 | Dump Engine & Presentation Docs    |
+-------------------+-----------------+------------------------------------+
```

---

### Slide 10: Conclusion & Technical Takeaways
- **Achievements**:
  - Successfully simulated all three Data Link Layer functions in C++: Multiple Access, Error Handling, and Flow Control.
  - Real network traffic captured over localhost sockets and verified using PyShark.
  - 100% automated test pass rate for error correction and flow control recovery.
- **Future Enhancements**: Extended Hamming SECDED (double error detection), Selective Repeat ARQ, and variable-length dynamic window scaling.
- **Speaker Notes**: *"Thank you for your time. We are now open for your questions and live demonstration."*

---

## 5. Frequently Asked Viva / Examination Questions

### Q1: Why did you choose Non-Persistent CSMA instead of 1-Persistent or p-Persistent?
**Answer**: In 1-Persistent CSMA, when the channel becomes idle, all waiting nodes transmit simultaneously with probability $p=1$, which almost guarantees a collision under moderate or high load. Non-persistent CSMA forces nodes that sense a busy medium to wait a randomized backoff period before sensing again, drastically reducing collision probability on shared channels.

### Q2: Why are parity bits placed at powers of 2 in Hamming Codes?
**Answer**: Powers of 2 ($1, 2, 4, 8, \dots$) each have a single unique bit set in their binary representation ($001_2, 010_2, 100_2$). This ensures that each parity bit is responsible for checking positions that have that specific bit set in their binary address. When the parity checks are recalculated at the receiver, the resulting syndrome directly forms the binary number representing the exact error position.

### Q3: How does Go-Back-N handle lost ACKs?
**Answer**: Go-Back-N uses **cumulative acknowledgements**. If ACK 1 is lost but ACK 2 arrives successfully, the sender knows that both Frame 0 and Frame 1 have been received in order, allowing the sliding window to advance to Frame 2 without retransmission. If all ACKs are lost, the sender timer expires, triggering retransmission of the entire window.

### Q4: How does PyShark intercept the simulated Data Link Layer frames?
**Answer**: Because standard operating systems do not allow users to inject arbitrary raw Layer-2 frames onto physical network cards without root/kernel privileges, our C++ engine encapsulates custom DLL frames inside standard UDP datagrams sent over `127.0.0.1`. PyShark sniffs these UDP datagrams and our dissector strips the transport headers to parse the custom DLL frame payload.

---

## 6. How to Run the Project (Step-by-Step for Demonstrator)

1. **One-Click Build and Run Everything**:
   ```cmd
   cd "D:\CN project"
   run_all.bat
   ```
2. **Manual C++ Compilation**:
   ```cmd
   g++ -std=c++14 -O2 src/main.cpp src/hamming.cpp src/csma_cd.cpp src/go_back_n.cpp src/udp_socket.cpp src/node.cpp -o dll_sim.exe -lws2_32
   .\dll_sim.exe
   ```
3. **Run PyShark Dissector**:
   ```cmd
   python sniffer/pyshark_sniffer.py capture.pcap
   ```
4. **Run Python Unit Tests**:
   ```cmd
   python python_sim/test_hamming.py
   python python_sim/dll_sim.py
   ```
