#!/usr/bin/env python3
"""
Look Out — Incognito 7.0 crypto
Each bird image in the PDF has StructElem /Alt text like "char(76)".
Joined: LOOKSLIKEAKEYTOME. The PDF /Subject field hides 320 bits of
ciphertext that XORs against the lowercase key to yield the flag.
"""
import fitz

doc = fitz.open("Untitled_document.pdf")

# Pull the per-figure Alt chars (ordered by struct tree)
chars = []
for i in range(1, doc.xref_length()):
    obj = doc.xref_object(i)
    if obj and "/Figure" in obj and "/Alt" in obj:
        start = obj.find("char\\(") + 6
        end = obj.find("\\)", start)
        chars.append(int(obj[start:end]))
key = "".join(chr(c) for c in chars).lower()
print("key:", key)

# Subject metadata = binary ciphertext
bits = doc.metadata["subject"]
ct = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

flag = bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(ct))
print(flag.decode())
