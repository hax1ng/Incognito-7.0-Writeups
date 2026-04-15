#!/usr/bin/env python3
# The Silent Handshake - Incognito 7.0 Forensics 500
# Exfil via TCP SYN flood to 198.51.100.45. Config hidden in DNS TXT record
# (XOR'd with server IP as ASCII). Each real SYN (66-byte, window=64240) encodes
# one flag byte in its TCP sequence number.
#
# Decoding: byte = ((seq & 0x00FFFFFF) * inverse(80211, 2^24)) & 0xFF
import subprocess

PCAP = "packet_capture.pcap"
MULT = 80211           # from DNS TXT config
MASK = 0x00FFFFFF      # 24-bit mask
CHK  = 0xAA            # (unused in final decode; was red herring for the port channel)

# 1. Decode DNS TXT config (for completeness)
txt_hex = "4a1b554f465a0c0b10121e4c05017f7e68737768131c100c59405d4d515e59584b43120a0e0c050308090215134d595b121414170141796f174c"
key = b"198.51.100.45"
cfg = bytes(b ^ key[i % len(key)] for i, b in enumerate(bytes.fromhex(txt_hex)))
print("[+] DNS TXT config:", cfg.decode())

# 2. Extract real SYN packets (window_size==64240 distinguishes them from flood noise)
r = subprocess.run(
    ["tshark", "-r", PCAP, "-o", "tcp.relative_sequence_numbers:false",
     "-Y", "ip.dst==198.51.100.45 and tcp.flags.syn==1 and frame.len==66",
     "-T", "fields", "-e", "tcp.seq"],
    capture_output=True, text=True,
)
seqs = [int(s) for s in r.stdout.strip().split("\n")]
print(f"[+] {len(seqs)} real SYN packets")

# 3. Decode: each seq's low 24 bits * mult^-1 (mod 2^24) gives the byte
inv = pow(MULT, -1, 1 << 24)
flag = bytes(((s & MASK) * inv) & 0xFF for s in seqs)
print("[+] Flag:", flag.decode())
