#!/usr/bin/env python3
"""
Hodgepodge - Incognito 7.0 CTF
Misc challenge, 400pts

The challenge: POST encoded credentials to /api/auth at hodgepodge-rs6v.onrender.com
Credentials encoded via 12-step pipeline from the symatrix npm package.

Working credentials:
  username: uwillnotcomeback   (from symatrix _fromBlob() output)
  password: neverbedependentonuwillnotcomeback  (hinted by flag theme "dependence")
"""

import base64
import requests

# ── 12-step encoding pipeline ──────────────────────────────────────────────────

def xor_encode(s):
    """Step 1: XOR each char with 0x37, comma-separated decimals"""
    return ','.join(str(ord(c) ^ 0x37) for c in s)

def atbash(s):
    """Atbash cipher"""
    result = []
    for c in s:
        code = ord(c)
        if 97 <= code <= 122:
            result.append(chr(219 - code))
        elif 65 <= code <= 90:
            result.append(chr(155 - code))
        else:
            result.append(c)
    return ''.join(result)

def rot13(s):
    """ROT13"""
    result = []
    for c in s:
        code = ord(c)
        if 65 <= code <= 90:
            result.append(chr((code - 65 + 13) % 26 + 65))
        elif 97 <= code <= 122:
            result.append(chr((code - 97 + 13) % 26 + 97))
        else:
            result.append(c)
    return ''.join(result)

def rot47(s):
    """ROT47"""
    result = []
    for c in s:
        code = ord(c)
        if 33 <= code <= 126:
            result.append(chr(33 + (code - 33 + 47) % 94))
        else:
            result.append(c)
    return ''.join(result)

def hex_encode(s):
    """Hex encode"""
    return ''.join(f'{ord(c):02x}' for c in s)

SUB_TABLE = {
    'A':'H','B':'I','C':'J','D':'K','E':'L','F':'M','G':'N','H':'O','I':'P',
    'J':'Q','K':'R','L':'S','M':'T','N':'U','O':'V','P':'W','Q':'X','R':'Y',
    'S':'Z','T':'A','U':'B','V':'C','W':'D','X':'E','Y':'F','Z':'G',
    'a':'h','b':'i','c':'j','d':'k','e':'l','f':'m','g':'n','h':'o','i':'p',
    'j':'q','k':'r','l':'s','m':'t','n':'u','o':'v','p':'w','q':'x','r':'y',
    's':'z','t':'a','u':'b','v':'c','w':'d','x':'e','y':'f','z':'g',
    '0':'5','1':'6','2':'7','3':'8','4':'9',
    '5':'0','6':'1','7':'2','8':'3','9':'4',
    '+':'-','-':'+','/':'|','|':'/','=':'~','~':'='
}

def substitute(s):
    """Custom substitution table"""
    return ''.join(SUB_TABLE.get(c, c) for c in s)

def b32encode(s):
    """Base32 encode"""
    return base64.b32encode(s.encode()).decode()

def encode_credential(plaintext):
    """12-step encoding pipeline from encoding.js"""
    s = xor_encode(plaintext)                     # Step 1: XOR
    s = base64.b64encode(s.encode()).decode()      # Step 2: Base64
    s = s[::-1]                                    # Step 3: Reverse
    s = atbash(s)                                  # Step 4: Atbash
    s = b32encode(s)                               # Step 5: Base32
    s = rot13(s)                                   # Step 6: ROT13
    s = hex_encode(s)                              # Step 7: Hex
    s = base64.b64encode(s.encode()).decode()      # Step 8: Base64
    s = s[::-1]                                    # Step 9: Reverse
    s = rot47(s)                                   # Step 10: ROT47
    s = substitute(s)                              # Step 11: Substitute
    s = base64.b64encode(s.encode()).decode()      # Step 12: Base64
    return s

# ── Solve ──────────────────────────────────────────────────────────────────────

USERNAME = "uwillnotcomeback"
PASSWORD = "neverbedependentonuwillnotcomeback"
AUTH_URL = "https://hodgepodge-rs6v.onrender.com/api/auth"

eu = encode_credential(USERNAME)
ep = encode_credential(PASSWORD)

print(f"Encoded username: {eu[:60]}...")
print(f"Encoded password: {ep[:60]}...")

r = requests.post(AUTH_URL, json={"username": eu, "password": ep}, timeout=30)
print(f"Status: {r.status_code}")
print(f"Response: {r.text}")

if "flag" in r.text:
    import json
    data = r.json()
    flag = data.get("flag", "")
    print(f"\nFLAG: {flag}")
    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
    print("Saved to flag.txt")
