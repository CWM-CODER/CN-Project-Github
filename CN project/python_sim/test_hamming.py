#!/usr/bin/env python3
"""
Unit tests for Hamming(7,4) Codec
Verifies:
1. Parity calculation (Powers of 2: 1, 2, 4)
2. Single-bit noise injection on all 7 bit positions
3. 100% syndrome detection and bit-error correction
"""

def encode_hamming_7_4(data4):
    """
    Encodes 4 data bits (d1, d2, d3, d4) into 7-bit codeword:
    Positions: 1=P1, 2=P2, 3=D1, 4=P4, 5=D2, 6=D3, 7=D4
    """
    d1, d2, d3, d4 = data4[0], data4[1], data4[2], data4[3]
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p4 = d2 ^ d3 ^ d4
    return [p1, p2, d1, p4, d2, d3, d4]

def decode_hamming_7_4(codeword):
    """
    Calculates syndrome and corrects single-bit error.
    Returns: (corrected_codeword, syndrome, extracted_data4)
    """
    c = list(codeword)
    s1 = c[0] ^ c[2] ^ c[4] ^ c[6]
    s2 = c[1] ^ c[2] ^ c[5] ^ c[6]
    s4 = c[3] ^ c[4] ^ c[5] ^ c[6]
    syndrome = s1 * 1 + s2 * 2 + s4 * 4

    if syndrome != 0 and syndrome <= 7:
        c[syndrome - 1] ^= 1 # Correct error

    extracted = [c[2], c[4], c[5], c[6]]
    return c, syndrome, extracted

def test_all_16_nibbles():
    print("Testing all 16 possible 4-bit nibbles...")
    passed = 0
    total = 0

    for i in range(16):
        data = [(i >> 3) & 1, (i >> 2) & 1, (i >> 1) & 1, i & 1]
        codeword = encode_hamming_7_4(data)

        # Test without error
        c_clean, syn_clean, ext_clean = decode_hamming_7_4(codeword)
        assert syn_clean == 0
        assert ext_clean == data
        passed += 1
        total += 1

        # Test single bit errors on every position 1..7
        for pos in range(1, 8):
            corrupt = list(codeword)
            corrupt[pos - 1] ^= 1 # flip bit

            c_fixed, syn, ext_fixed = decode_hamming_7_4(corrupt)
            assert syn == pos, f"Expected syndrome {pos}, got {syn}"
            assert ext_fixed == data, f"Correction failed for data {data} at pos {pos}"
            passed += 1
            total += 1

    print(f"All tests PASSED! ({passed}/{total} tests successful)")

if __name__ == "__main__":
    test_all_16_nibbles()
