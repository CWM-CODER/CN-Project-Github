# System Architecture & Technical Specification

## Project: Data Link Layer Protocol Suite (CSMA/CD + Hamming Code + Go-Back-N)

```
+-------------------------------------------------------------------------------+
|                             APPLICATION LAYER                                 |
|                       String / Binary Message Data                            |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       DATA LINK LAYER (DLL) ENGINE                            |
|                                                                               |
|   +-----------------------------------------------------------------------+   |
|   |  Subsystem B: Error Control (Hamming SEC Codec)                       |   |
|   |  - Parity generation at powers of 2 (1, 2, 4, 8...)                   |   |
|   |  - Single Error Correction & Syndrome Calculation                     |   |
|   +-----------------------------------------------------------------------+   |
|                                     |                                         |
|   +-----------------------------------------------------------------------+   |
|   |  Subsystem C: Flow Control (Go-Back-N Sliding Window)                 |   |
|   |  - Sender: Window [base .. base+N-1], Retransmission Timers, Buffer   |   |
|   |  - Receiver: In-order sequence checking, Cumulative ACKs, Discards    |   |
|   +-----------------------------------------------------------------------+   |
|                                     |                                         |
|   +-----------------------------------------------------------------------+   |
|   |  Subsystem A: Medium Access Control (CSMA/CD Non-Persistent)          |   |
|   |  - Carrier sensing: IDLE -> transmit; BUSY -> random sleep & retry   |   |
|   |  - Collision detection within vulnerable propagation window tau       |   |
|   |  - 32-bit JAM broadcast (0xAAAAAAAA) & Binary Exponential Backoff     |   |
|   +-----------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       TRANSPORT & ENCAPSULATION LAYER                         |
|             Winsock2 UDP Datagrams over Loopback (127.0.0.1)                  |
|                   Port 9001 (Node 1) <---> Port 9002 (Node 2)                 |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       CAPTURE & PROTOCOL DISSECTION                           |
|       - Native Libpcap File Writer: writes 'capture.pcap'                     |
|       - PyShark Packet Dissector: parses layers, hex dumps, and syndromes     |
+-------------------------------------------------------------------------------+
```

---

## 1. DLL Frame Specification

The custom Data Link Layer frame is laid out in memory as a packed C++ structure:

```
Byte Offset   Field Name      Size (Bytes)   Description
-----------------------------------------------------------------------
0..1          preamble        2              Synchronization flags: 0xAA 0x7E
2             frameType       1              0x01: DATA, 0x02: ACK, 0x03: NAK, 0x04: JAM
3             srcNode         1              Transmitting Node ID (e.g., 1)
4             dstNode         1              Receiving Node ID (e.g., 2, 0xFF=Broadcast)
5..6          seqNum          2              Sequence Number (16-bit unsigned, little-endian)
7..8          ackNum          2              Acknowledgement Number (16-bit unsigned)
9             windowSize      1              Sender Window Size N
10..11        payloadLen      2              Length of payload in bytes
12..N         payload         Variable       Hamming-encoded binary payload
N+1..N+2      fcs             2              CRC16-CCITT Frame Check Sequence (Polynomial 0x1021)
```

---

## 2. Mathematical Formulations

### A. Hamming (7,4) Code Single Error Correction
- Let $m = 4$ data bits: $D_1, D_2, D_3, D_4$.
- Number of check bits $r = 3$ satisfies $2^r \ge m + r + 1 \implies 2^3 \ge 8$.
- Parity positions: $P_1$ at index 1, $P_2$ at index 2, $P_4$ at index 4.
- Data positions: $D_1$ at index 3, $D_2$ at index 5, $D_3$ at index 6, $D_4$ at index 7.
- Parity bit generation:
  $$P_1 = D_1 \oplus D_2 \oplus D_4$$
  $$P_2 = D_1 \oplus D_3 \oplus D_4$$
  $$P_4 = D_2 \oplus D_3 \oplus D_4$$
- Syndrome evaluation at receiver:
  $$C_1 = P_1 \oplus D_1 \oplus D_2 \oplus D_4$$
  $$C_2 = P_2 \oplus D_1 \oplus D_3 \oplus D_4$$
  $$C_4 = P_4 \oplus D_2 \oplus D_3 \oplus D_4$$
  $$\text{Syndrome} = C_4 \cdot 4 + C_2 \cdot 2 + C_1 \cdot 1$$
- Error Correction Rule:
  - If $\text{Syndrome} == 0$: Codeword received without error.
  - If $\text{Syndrome} \ne 0$: Bit at position $\text{Syndrome}$ was corrupted. Correct by bit flip:
    $$\text{Codeword}[\text{Syndrome} - 1] \leftarrow \text{Codeword}[\text{Syndrome} - 1] \oplus 1$$

---

### B. CSMA/CD Truncated Binary Exponential Backoff
- When a collision is detected during transmission within propagation delay $\tau$:
  1. Node stops transmission and broadcasts a 32-bit JAM pattern: `0xAAAAAAAA`.
  2. Increments collision counter $k \leftarrow \min(k + 1, 10)$.
  3. Draws a random integer $R$ uniformly from:
     $$R \in \{0, 1, 2, \dots, 2^k - 1\}$$
  4. Waits backoff time $T_b = R \times \text{SlotTime}$ before re-sensing the channel.
  5. Maximum attempts: 16. If $k > 16$, transmission aborts with channel overload status.

---

### C. Go-Back-N Protocol Window Invariants
- Sender maintains:
  $$\text{base} \le \text{next\_seq\_num} \le \text{base} + N$$
  - Unacknowledged frames: $[\text{base}, \dots, \text{next\_seq\_num} - 1]$.
  - Available window slots: $(\text{base} + N) - \text{next\_seq\_num}$.
- Cumulative ACK invariant:
  - Receiving $\text{ACK}(y)$ where $y > \text{base}$ acknowledges all frames $< y$.
  - Window advances: $\text{base} \leftarrow y$.
- Timeout condition:
  - If $\text{currentTime} - \text{timerStart} \ge \text{TimeoutInterval}$ for frame $\text{base}$:
    Retransmit all frames $f \in [\text{base}, \dots, \text{next\_seq\_num} - 1]$.
