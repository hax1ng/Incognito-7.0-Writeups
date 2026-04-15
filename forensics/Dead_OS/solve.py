#!/usr/bin/env python3
"""
Dead OS — Incognito 7.0 forensics 400pt solve.

1. The VHD's MBR has a base64 blob stitched into the bootloader error text at
   offset 0x163 — 32 bytes of AES ciphertext sitting in plain sight.
2. The "hidden vault" is a password-protected zip at
   Users/You/AppData/Roaming/HiddenApp/key.zip (ZipCrypto, stored).
3. john + rockyou cracks the zip password: Passw0rd123.
4. The extracted key.txt is "ThisIsA32ByteKeyForAES256!!12345" — AES-256 key.
5. AES-ECB decrypt of the MBR blob with that key yields the flag.
"""
import base64
from Crypto.Cipher import AES

MBR_CIPHERTEXT_B64 = "iumuhAh5x1NWNh6Twkk9xDn0ZwlKn3yJ7C4FVZ1z/PY="
KEY = b"ThisIsA32ByteKeyForAES256!!12345"

ct = base64.b64decode(MBR_CIPHERTEXT_B64)
pt = AES.new(KEY, AES.MODE_ECB).decrypt(ct)
print(pt.rstrip(b"\x01").decode())
