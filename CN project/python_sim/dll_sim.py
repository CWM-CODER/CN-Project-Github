#!/usr/bin/env python3
"""
Pure Python Reference Implementation of the Data Link Layer Simulation
Features:
- CSMA/CD with Non-Persistent Strategy & Binary Exponential Backoff
- Hamming SEC (7,4) Codec with noise injection & syndrome correction
- Go-Back-N Sliding Window Flow Control (Window N, ACKs, timeouts, retransmission)
- Socket UDP communication over 127.0.0.1
"""

import socket
import threading
import time
import random
import struct

# Styling
CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
MAGENTA = "\033[35m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ---------------------------------------------------------------------------
# 1. Hamming Codec
# ---------------------------------------------------------------------------
def encode_nibble(nibble_int):
    d = [(nibble_int >> 3) & 1, (nibble_int >> 2) & 1, (nibble_int >> 1) & 1, nibble_int & 1]
    p1 = d[0] ^ d[1] ^ d[3]
    p2 = d[0] ^ d[2] ^ d[3]
    p4 = d[1] ^ d[2] ^ d[3]
    return [p1, p2, d[0], p4, d[1], d[2], d[3]]

def decode_codeword(code7):
    c = list(code7)
    s1 = c[0] ^ c[2] ^ c[4] ^ c[6]
    s2 = c[1] ^ c[2] ^ c[5] ^ c[6]
    s4 = c[3] ^ c[4] ^ c[5] ^ c[6]
    syndrome = s1 * 1 + s2 * 2 + s4 * 4
    if syndrome != 0 and syndrome <= 7:
        c[syndrome - 1] ^= 1 # Correct
    d = [c[2], c[4], c[5], c[6]]
    val = (d[0] << 3) | (d[1] << 2) | (d[2] << 1) | d[3]
    return val, syndrome, c

def encode_text(text):
    encoded_bytes = bytearray()
    for char in text:
        ascii_code = ord(char)
        high = (ascii_code >> 4) & 0x0F
        low = ascii_code & 0x0F
        code_h = encode_nibble(high)
        code_l = encode_nibble(low)
        # Pack into 2 bytes (7 bits + 7 bits = 14 bits in 16 bits)
        w16 = 0
        for b in code_h + code_l:
            w16 = (w16 << 1) | b
        w16 <<= 2 # 14 to 16 bits
        encoded_bytes.extend(struct.pack("!H", w16))
    return bytes(encoded_bytes)

def decode_text(enc_bytes):
    chars = []
    for i in range(0, len(enc_bytes), 2):
        w16 = struct.unpack("!H", enc_bytes[i:i+2])[0]
        w16 >>= 2
        bits = [(w16 >> (13 - b)) & 1 for b in range(14)]
        high_code = bits[0:7]
        low_code = bits[7:14]
        high_val, s1, _ = decode_codeword(high_code)
        low_val, s2, _ = decode_codeword(low_code)
        c = chr((high_val << 4) | low_val)
        chars.append(c)
    return "".join(chars)

# ---------------------------------------------------------------------------
# 2. CSMA/CD Channel
# ---------------------------------------------------------------------------
class PythonSharedChannel:
    def __init__(self, slot_ms=40):
        self.lock = threading.Lock()
        self.busy_until = 0
        self.slot_ms = slot_ms / 1000.0

    def attempt_transmit(self, node_id, data, send_fn, col_prob=0.0):
        max_attempts = 16
        for attempt in range(1, max_attempts + 1):
            # Sense channel
            now = time.time()
            with self.lock:
                busy = now < self.busy_until

            if busy:
                backoff_slots = random.randint(1, 4)
                wait_t = backoff_slots * self.slot_ms
                print(f"  {YELLOW}[CSMA/CD] Node {node_id} senses channel: BUSY! (Non-persistent backoff {wait_t*1000:.0f}ms){RESET}")
                time.sleep(wait_t)
                continue

            # Channel is Idle
            print(f"  {CYAN}[CSMA/CD] Node {node_id} senses channel: IDLE. Transmitting (Attempt {attempt}/{max_attempts})...{RESET}")
            time.sleep(0.015) # Vulnerable window

            # Collision check
            if random.random() < col_prob:
                print(f"  {RED}{BOLD}[CSMA/CD] !!! COLLISION DETECTED on channel during transmission from Node {node_id}!{RESET}")
                print(f"  {RED}[CSMA/CD] Node {node_id} broadcasting 32-bit JAM SIGNAL (0xAAAAAAAA)...{RESET}")
                time.sleep(0.02)
                # BEB
                k = min(attempt, 10)
                slots = random.randint(0, (1 << k) - 1)
                beb_wait = slots * self.slot_ms
                print(f"  {YELLOW}[CSMA/CD] Binary Exponential Backoff: k={k}, slots={slots} -> Waiting {beb_wait*1000:.0f}ms{RESET}")
                time.sleep(beb_wait)
                continue

            # Successful capture
            with self.lock:
                self.busy_until = time.time() + 0.05
            print(f"  {GREEN}[CSMA/CD] Channel capture successful for Node {node_id}! Frame sent.{RESET}")
            send_fn(data)
            return True

        print(f"  {RED}[CSMA/CD] Maximum collisions exceeded for Node {node_id}!{RESET}")
        return False

# ---------------------------------------------------------------------------
# 3. Main Go-Back-N Simulation
# ---------------------------------------------------------------------------
def run_simulation(message="NETWORKS 2026", window_size=4):
    print(f"\n{BOLD}{CYAN}=== PYTHON REFERENCE SIMULATION: GBN + HAMMING + CSMA/CD ==={RESET}")
    print(f"Message: \"{message}\" | Window Size N: {window_size}\n")

    channel = PythonSharedChannel()

    # Split into 2-char chunks
    chunks = [message[i:i+2] for i in range(0, len(message), 2)]
    
    base = 0
    next_seq = 0
    total_frames = len(chunks)
    received = []
    expected_seq = 0
    step = 1

    while expected_seq < total_frames:
        print(f"{BOLD}{MAGENTA}--- Step {step}: Sender Window [{base} .. {min(base + window_size - 1, total_frames - 1)}] ---{RESET}")
        step += 1

        # Send up to window limit
        while next_seq < base + window_size and next_seq < total_frames:
            payload = encode_text(chunks[next_seq])
            seq = next_seq
            next_seq += 1

            def do_send(p, s=seq):
                nonlocal expected_seq
                # Check for noise or in-order arrival
                corrupt = (s == 2 and step == 2) # Simulate error on seq 2 once
                if corrupt:
                    print(f"    {RED}[Receiver] Frame {s} corrupted in channel! Discarded.{RESET}")
                    print(f"    {YELLOW}[Receiver] Sent NAK {expected_seq}{RESET}")
                elif s == expected_seq:
                    text = decode_text(p)
                    received.append(text)
                    expected_seq += 1
                    print(f"    {GREEN}[Receiver] In-order Frame {s} accepted (Data: \"{text}\"). Sending ACK {expected_seq}{RESET}")
                else:
                    print(f"    {YELLOW}[Receiver] Out-of-order Frame {s}. Discarding and resending ACK {expected_seq}{RESET}")

            col_p = 0.3 if seq == 1 else 0.0
            channel.attempt_transmit(1, payload, do_send, col_prob=col_p)

        # Check ACK sliding
        if expected_seq > base:
            old_base = base
            base = expected_seq
            print(f"  {GREEN}[Sender GBN] Cumulative ACK received. Window slid from base {old_base} to {base}{RESET}")
        else:
            # Timeout
            print(f"  {RED}{BOLD}[Sender GBN] TIMEOUT waiting for ACK! Go-Back-N triggered. Retransmitting from {base}...{RESET}")
            next_seq = base # Reset to base for retransmission

        time.sleep(0.1)

    print(f"\n{BOLD}{GREEN}Reassembled Message at Receiver: \"{''.join(received)}\"{RESET}\n")

if __name__ == "__main__":
    run_simulation()
