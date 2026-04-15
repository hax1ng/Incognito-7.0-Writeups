import socket
import re
import time
from collections import deque

def is_dark(n):
    return n < 100 or (232 <= n <= 240)

def parse_frame(data):
    """Parse the best (most complete) frame from data."""
    parts = data.split(b'\x1b[H')
    best_frame = None
    best_cells = 0
    for p in parts:
        if len(p) < 40000:
            continue
        pattern = rb'(?:\x1b\[5m)?\x1b\[48;5;(\d+)m(?:\x1b\[(?:[^m]*)m)*([0-9A-F]{2}|><|\xe2\x96\x93\xe2\x96\x93)\x1b\[0m'
        cells = [(int(m.group(1)), m.group(2)) for m in re.finditer(pattern, p)]
        if len(cells) > best_cells:
            best_cells = len(cells)
            best_frame = cells
    if not best_frame or len(best_frame) < 2601:
        return None, (-1,-1), (-1,-1), {}
    grid = []
    player = (-1,-1)
    target = (-1,-1)
    hex_map = {}  # (r,c) -> hex_value string
    for i, (color, content) in enumerate(best_frame[:2601]):
        r, c = i // 51, i % 51
        if content == b'><':
            player = (r, c)
            grid.append(1)
            hex_map[(r,c)] = None  # player cell
        elif content == b'\xe2\x96\x93\xe2\x96\x93':
            target = (r, c)
            grid.append(1)
            hex_map[(r,c)] = None  # target cell
        else:
            val = content.decode('ascii') if content else '00'
            hex_map[(r,c)] = val
            grid.append(0 if is_dark(color) else 1)
    return grid, player, target, hex_map

def bfs(grid, start, end):
    queue = deque([(start, [start])])
    visited = {start}
    while queue:
        (r,c), path = queue.popleft()
        if (r,c) == end:
            return path
        for dr,dc in [(-1,0),(1,0),(0,-1),(0,1)]:
            nr,nc = r+dr,c+dc
            idx = nr*51+nc
            if 0<=nr<51 and 0<=nc<51 and (nr,nc) not in visited and idx < len(grid) and grid[idx] == 1:
                visited.add((nr,nc))
                queue.append(((nr,nc), path+[(nr,nc)]))
    return None

def path_to_keys(path):
    keys = []
    for i in range(1, len(path)):
        pr, pc = path[i-1]
        cr, cc = path[i]
        dr, dc = cr - pr, cc - pc
        if dr == -1: keys.append(ord('w'))
        elif dr == 1: keys.append(ord('s'))
        elif dc == -1: keys.append(ord('a'))
        elif dc == 1: keys.append(ord('d'))
    return keys

def read_data(s, timeout=1.5):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    return b''.join(chunks)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('34.131.216.230', 1340))
    print("[*] Connected. Reading initial frame...")
    
    # Read initial state - wait longer to get full frame
    time.sleep(2.5)
    init_data = read_data(s, timeout=1.0)
    print(f"[*] Got {len(init_data)} bytes")
    
    grid, player, target, hex_map = parse_frame(init_data)
    if grid is None:
        print("[!] Failed to parse frame")
        s.close()
        return
    
    print(f"[*] Player at {player}, Target at {target}")
    
    # Check for flag in initial data
    flag_match = re.search(rb'ictf\{[^}]+\}', init_data)
    if flag_match:
        print(f"[FLAG] {flag_match.group().decode()}")
        s.close()
        return
    
    path = bfs(grid, player, target)
    if not path:
        print("[!] No path found!")
        s.close()
        return
    
    print(f"[*] Path length: {len(path)} steps")
    keys = path_to_keys(path)
    print(f"[*] Keys: {''.join(chr(k) for k in keys)}")
    
    # Collect hex values along the path (excluding start position)
    traversed_hex = []
    for pos in path:
        hv = hex_map.get(pos)
        if hv:  # skip None (player/target positions initially)
            traversed_hex.append(hv)
    
    print(f"[*] Pre-path hex values: {' '.join(traversed_hex[:10])}...")
    
    # Navigate step by step
    all_response = b''
    last_player = player
    
    print("[*] Navigating maze...")
    for i, key in enumerate(keys):
        s.send(bytes([key]))
        time.sleep(0.08)
        
        chunk = b''
        s.settimeout(0.4)
        try:
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunk += data
        except socket.timeout:
            pass
        
        all_response += chunk
        
        # Check for flag
        flag_match = re.search(rb'ictf\{[^}]+\}', chunk)
        if flag_match:
            print(f"\n[FLAG FOUND at step {i+1}] {flag_match.group().decode()}")
            break
        
        # Check if target disappeared (maze completed?)
        if b'\xe2\x96\x93\xe2\x96\x93' not in chunk and len(chunk) > 1000:
            print(f"\n[*] Target may have disappeared at step {i+1}!")
            # Parse this frame to check
            _, new_player, new_target, new_hex = parse_frame(chunk)
            if new_target == (-1, -1):
                print("[*] Target is GONE - checking for flag in all received data")
        
        if (i+1) % 10 == 0:
            print(f"  Step {i+1}/{len(keys)}...")
    
    print(f"\n[*] Navigation complete. Total response: {len(all_response)} bytes")
    
    # Search for flag in all data
    flag_match = re.search(rb'ictf\{[^}]+\}', all_response)
    if flag_match:
        print(f"[FLAG] {flag_match.group().decode()}")
    else:
        print("[*] No ictf{} flag found in raw data")
        
        # Try to find any printable text that looks like a flag
        printable = re.findall(rb'[a-zA-Z0-9_!@#$%^&*(){}\[\]]+', all_response)
        long_strings = [s for s in printable if len(s) > 10]
        print(f"[*] Long printable strings found: {long_strings[:20]}")
        
        # Try collecting hex bytes from the path cells
        print(f"\n[*] Hex values along path: {' '.join(traversed_hex)}")
        if traversed_hex:
            try:
                hex_bytes = bytes.fromhex(''.join(traversed_hex))
                print(f"[*] Path hex as bytes: {hex_bytes}")
                print(f"[*] Path hex as ascii: {hex_bytes.decode('latin-1', errors='replace')}")
                # Check for flag pattern
                if b'ictf' in hex_bytes or b'ICTF' in hex_bytes:
                    print(f"[*] FLAG PATTERN IN HEX BYTES!")
            except Exception as e:
                print(f"[*] Hex decode error: {e}")
    
    # Read any remaining data
    time.sleep(2)
    remaining = read_data(s, timeout=1.5)
    if remaining:
        print(f"[*] Additional {len(remaining)} bytes received")
        flag_match = re.search(rb'ictf\{[^}]+\}', remaining)
        if flag_match:
            print(f"[FLAG] {flag_match.group().decode()}")
        # Check for any readable text
        # Strip ANSI codes
        clean = re.sub(rb'\x1b\[[^m]*m', b'', remaining)
        clean = re.sub(rb'\x1b\[[^H]*H', b'', clean)
        readable = re.findall(rb'[a-zA-Z0-9_!@#$%^&*(){} ]+', clean)
        long_r = [r for r in readable if len(r) > 5]
        if long_r:
            print(f"[*] Readable text after nav: {long_r[:30]}")
    
    s.close()

if __name__ == '__main__':
    main()
