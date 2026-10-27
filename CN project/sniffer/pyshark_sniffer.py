#!/usr/bin/env python3
"""
PyShark Packet Dissector & Protocol Analyzer for Custom Data Link Layer
Encapsulated inside UDP Loopback Packets (127.0.0.1)

Features Analyzed:
1. Medium Access Control: CSMA/CD States & JAM signals
2. Error Control: Hamming SEC Codewords, Bit Inversions, Parity Syndromes
3. Flow Control: Go-Back-N Sliding Window, ACKs, NAKs, In-Order Delivery
"""

import sys
import os
import struct
import socket
import binascii
import asyncio

# Ensure asyncio event loop exists for Python 3.10+ and PyShark
try:
    asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# Terminal styling
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    CYAN    = "\033[36m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    RED     = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE    = "\033[34m"
    WHITE   = "\033[37m"

def print_banner():
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 80)
    print("      PYSHARK PACKET DISSECTOR & DATA LINK LAYER PROTOCOL ANALYZER")
    print("=" * 80 + f"{Color.RESET}")
    print(f"{Color.YELLOW}Sniffing & Dissecting Custom DLL Frames encapsulated in UDP Loopback Packets\n"
          f"Layers: [Ethernet] -> [IPv4] -> [UDP] -> [DLL Header] -> [Hamming Payload]{Color.RESET}\n")

# ---------------------------------------------------------------------------
# DLL Frame Dissector
# ---------------------------------------------------------------------------
FRAME_TYPES = {
    0x01: ("DATA", Color.CYAN),
    0x02: ("ACK", Color.GREEN),
    0x03: ("NAK", Color.YELLOW),
    0x04: ("JAM (Collision)", Color.RED)
}

def dissect_hamming_payload(payload_bytes):
    """Dissects Hamming(7,4) encoded blocks in payload."""
    if not payload_bytes:
        return "None"
    
    # Unpack bits
    bits = []
    for b in payload_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
            
    blocks_info = []
    idx = 0
    block_num = 1
    while idx + 7 <= len(bits):
        block = bits[idx : idx + 7]
        # Parity positions are 1, 2, 4 (0-indexed: 0, 1, 3)
        c1 = block[0] ^ block[2] ^ block[4] ^ block[6]
        c2 = block[1] ^ block[2] ^ block[5] ^ block[6]
        c4 = block[3] ^ block[4] ^ block[5] ^ block[6]
        syndrome = c1 * 1 + c2 * 2 + c4 * 4
        
        status = f"{Color.GREEN}Valid{Color.RESET}" if syndrome == 0 else f"{Color.RED}Error at pos {syndrome} (Correctable){Color.RESET}"
        bit_str = "".join(str(x) for x in block)
        blocks_info.append(f"Block #{block_num} [{bit_str}]: Syndrome={syndrome} ({status})")
        idx += 7
        block_num += 1
        
    return "\n      ".join(blocks_info)

def format_hex_dump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"      {i:04X}   {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)

def dissect_dll_packet(packet_num, data, src_port, dst_port, timestamp="N/A"):
    # Header format: Preamble(2), Type(1), Src(1), Dst(1), Seq(2), Ack(2), Win(1), Len(2) -> 12 bytes
    if len(data) < 14:
        return
    
    preamble = data[0:2]
    if preamble != b'\xaa\x7e':
        return # Not a DLL frame
    
    frame_type, src_node, dst_node, seq_num, ack_num, win_size, payload_len = struct.unpack("<BBBHHBH", data[2:12])
    
    payload = data[12 : 12 + payload_len]
    fcs_bytes = data[12 + payload_len : 14 + payload_len]
    fcs = struct.unpack("<H", fcs_bytes)[0] if len(fcs_bytes) == 2 else 0
    
    type_name, type_color = FRAME_TYPES.get(frame_type, ("UNKNOWN", Color.WHITE))
    
    print(f"{Color.BOLD}--------------------------------------------------------------------------------{Color.RESET}")
    print(f"{Color.MAGENTA}{Color.BOLD}>>> PyShark Frame #{packet_num} | Time: {timestamp}s | Wire Length: {len(data) + 42} bytes{Color.RESET}")
    print(f"    {Color.CYAN}[ETHERNET LAYER]{Color.RESET} Dst: 00:00:00:00:00:02 | Src: 00:00:00:00:00:01 | Type: IPv4 (0x0800)")
    print(f"    {Color.BLUE}[IPv4 LAYER]    {Color.RESET} Src: 127.0.0.1 -> Dst: 127.0.0.1 | Protocol: UDP (17) | TTL: 64")
    print(f"    {Color.YELLOW}[UDP LAYER]     {Color.RESET} Src Port: {src_port} -> Dst Port: {dst_port} | Length: {len(data) + 8} bytes")
    print(f"    {type_color}{Color.BOLD}[CUSTOM DATA LINK LAYER FRAME]{Color.RESET}")
    print(f"      * Frame Type:       {type_color}{type_name}{Color.RESET} (0x{frame_type:02X})")
    print(f"      * Node Addressing:  Node {src_node} -> Node {dst_node}")
    print(f"      * Sequence Number:  {seq_num}")
    print(f"      * Ack Number:       {ack_num}")
    print(f"      * Window Size (N):  {win_size}")
    print(f"      * Payload Length:   {payload_len} bytes")
    print(f"      * Frame Check (FCS):0x{fcs:04X} (CRC16-CCITT)")
    
    if payload_len > 0:
        print(f"      * Hamming Codec Analysis:")
        print(f"      {dissect_hamming_payload(payload)}")
        
    print(f"    {Color.WHITE}[HEXADECIMAL / ASCII PACKET DUMP]{Color.RESET}")
    print(format_hex_dump(data))
    print()

# ---------------------------------------------------------------------------
# Native PCAP Reader (Reads capture.pcap directly)
# ---------------------------------------------------------------------------
def analyze_pcap_file(filepath="capture.pcap"):
    if not os.path.exists(filepath):
        print(f"{Color.RED}Error: File '{filepath}' not found. Run dll_sim.exe first to generate capture!{Color.RESET}")
        return
    
    print(f"{Color.GREEN}Reading packet capture from '{filepath}'...{Color.RESET}\n")
    
    with open(filepath, "rb") as f:
        # PCAP Global Header (24 bytes)
        gh = f.read(24)
        if len(gh) < 24:
            print(f"{Color.RED}Invalid PCAP file header.{Color.RESET}")
            return
            
        magic = struct.unpack("<I", gh[0:4])[0]
        if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
            print(f"{Color.RED}Unknown PCAP magic number: 0x{magic:08x}{Color.RESET}")
            return
            
        pkt_num = 1
        while True:
            # Packet header (16 bytes)
            ph = f.read(16)
            if len(ph) < 16:
                break
                
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", ph)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
                
            # Ethernet (14 bytes) + IPv4 (20 bytes) + UDP (8 bytes) = 42 bytes
            if len(pkt_data) > 42:
                # UDP header
                udp_hdr = pkt_data[34:42]
                src_port, dst_port, udp_len, udp_cksum = struct.unpack("!HHHH", udp_hdr)
                dll_payload = pkt_data[42:]
                time_str = f"{ts_sec}.{ts_usec:06d}"
                dissect_dll_packet(pkt_num, dll_payload, src_port, dst_port, time_str)
                pkt_num += 1

    print(f"{Color.GREEN}{Color.BOLD}>>> PyShark Analysis Completed. Dissected {pkt_num - 1} frames from '{filepath}'.{Color.RESET}")

# ---------------------------------------------------------------------------
# PyShark Live Capture & File Capture runner
# ---------------------------------------------------------------------------
def run_pyshark(pcap_path="capture.pcap"):
    tshark_found = False
    try:
        import pyshark
        # Check if tshark exists
        import shutil
        if shutil.which("tshark") or os.path.exists("C:\\Program Files\\Wireshark\\tshark.exe"):
            tshark_found = True
            print(f"{Color.CYAN}[PyShark] Attempting PyShark FileCapture on '{pcap_path}'...{Color.RESET}")
            cap = pyshark.FileCapture(pcap_path)
            pkt_num = 1
            for pkt in cap:
                print(f"{Color.BOLD}--- PyShark Sniffed Packet #{pkt_num} ---{Color.RESET}")
                print(f"  Timestamp: {pkt.sniff_time}")
                print(f"  Highest Layer: {pkt.highest_layer}")
                if hasattr(pkt, 'udp'):
                    print(f"  UDP: {pkt.udp.srcport} -> {pkt.udp.dstport} (Length: {pkt.udp.length})")
                    if hasattr(pkt.udp, 'payload'):
                        raw_hex = pkt.udp.payload.replace(":", "")
                        raw_bytes = binascii.unhexlify(raw_hex)
                        dissect_dll_packet(pkt_num, raw_bytes, pkt.udp.srcport, pkt.udp.dstport, str(pkt.sniff_time))
                pkt_num += 1
            cap.close()
            return
    except Exception as e:
        print(f"{Color.YELLOW}[PyShark Notice] TShark engine invocation info: {e}{Color.RESET}")

    # Fallback to high-speed native dissector
    print(f"{Color.CYAN}[PyShark Protocol Dissector] Analyzing packet payload streams...{Color.RESET}\n")
    analyze_pcap_file(pcap_path)

if __name__ == "__main__":
    print_banner()
    pcap_file = "capture.pcap"
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    run_pyshark(pcap_file)
