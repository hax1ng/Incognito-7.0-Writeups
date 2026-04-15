#!/usr/bin/env python3
import socket
import re
import sys
import time

HOST = '34.131.216.230'
PORT = 1339
MOD = 1000000007

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("[*] Connected", file=sys.stderr)

    # Read all data - server sends 100MB then waits
    data = b''
    s.settimeout(30)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            # Check if we've received the full stream (look for end of stream line)
            if b'[INCOMING STREAM]' in data and len(data) > 100_000_000:
                break
    except socket.timeout:
        pass

    print(f"[*] Received {len(data)} bytes", file=sys.stderr)

    text = data.decode('ascii', errors='replace')

    # Parse starting value
    m = re.search(r'Starting Value \(V\) = (\d+)', text)
    V = int(m.group(1))
    print(f"[*] Starting V = {V}", file=sys.stderr)

    # Parse rules dynamically
    m_add = re.search(r'@ : V = V \+ (\d+)', text)
    m_mul = re.search(r'# : V = V \* (\d+)', text)
    m_xor = re.search(r'\$ : V = V \^ (\d+)', text)

    add_val = int(m_add.group(1)) if m_add else 101
    mul_val = int(m_mul.group(1)) if m_mul else 3
    xor_val = int(m_xor.group(1)) if m_xor else 4242

    print(f"[*] Rules: add={add_val}, mul={mul_val}, xor={xor_val}", file=sys.stderr)

    # Find stream
    idx = text.find('[INCOMING STREAM]\n')
    if idx == -1:
        print("ERROR: no stream found!", file=sys.stderr)
        return
    stream = text[idx + len('[INCOMING STREAM]\n'):]
    # Take only the ops line
    ops_line = stream.split('\n')[0].strip()

    print(f"[*] Stream length: {len(ops_line)} ops", file=sys.stderr)

    # Process - use bytearray for speed
    ops = ops_line.encode('ascii')

    t0 = time.time()
    for op in ops:
        if op == ord('@'):
            V = (V + add_val) % MOD
        elif op == ord('#'):
            V = (V * mul_val) % MOD
        elif op == ord('$'):
            V = V ^ xor_val
        elif op == ord('%'):
            if V % 2 == 0:
                V = V // 2
            else:
                V = (V * 3 + 1) % MOD
        elif op == ord('&'):
            V = (~V) & 0xFFFFF

    t1 = time.time()
    print(f"[*] Computed in {t1-t0:.2f}s, V = {V}", file=sys.stderr)

    # Send answer
    answer = f"{V}\n".encode()
    print(f"[*] Sending: {answer}", file=sys.stderr)
    s.settimeout(10)
    s.sendall(answer)

    # Read response
    time.sleep(0.5)
    try:
        resp = s.recv(4096)
        print(f"[*] Response: {resp}", file=sys.stderr)
        print(resp.decode('ascii', errors='replace'))
    except:
        pass

    s.close()

solve()
