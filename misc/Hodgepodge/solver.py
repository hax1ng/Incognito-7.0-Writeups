#!/usr/bin/env python3
"""Fast ORACLE OF EQUALITY solver with pipelining."""
import socket, sys

HOST = '34.126.212.8'
PORT = 1338

class Oracle:
    def __init__(self):
        self.s = socket.socket()
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.settimeout(120)
        self.s.connect((HOST, PORT))
        self.buf = b''

    def _read_more(self):
        c = self.s.recv(65536)
        if not c:
            raise ConnectionError("closed")
        self.buf += c

    def read_line(self):
        while b'\n' not in self.buf:
            self._read_more()
        line, _, rest = self.buf.partition(b'\n')
        self.buf = rest
        return line.decode(errors='replace').rstrip('\r')

    def read_number(self):
        while True:
            line = self.read_line()
            s = line.strip()
            if s and s.lstrip('-').isdigit():
                return int(s)

    def send_raw(self, data):
        self.s.sendall(data)

    def send(self, msg):
        self.s.sendall((msg + "\n").encode())

    def pipeline_pairs(self, pairs):
        """Send all pair queries in a single sendall, then read all responses."""
        q_bytes = b''.join(f"? {a} {b}\n".encode() for (a, b) in pairs)
        self.s.sendall(q_bytes)
        results = []
        for _ in pairs:
            results.append(int(self.read_line().strip()))
        return results

    def query(self, i, j):
        self.send(f"? {i} {j}")
        return int(self.read_line().strip())

    def answer(self, k):
        self.send(f"! {k}")

def solve_tc(orc, n, verbose=False):
    N = 2 * n
    pairs = [(2*i-1, 2*i) for i in range(1, n+1)]
    results = orc.pipeline_pairs(pairs)
    if verbose:
        print(f"  pair results: {results[:20]}... (n={n})")
    # Find a pair that equals
    for i, r in enumerate(results):
        if r == 1:
            a = pairs[i][0]
            orc.answer(a)
            return a
    # All pairs differ. 1 extra query.
    if n >= 2:
        r = orc.query(1, 3)
        if verbose:
            print(f"  q(1,3) = {r}")
        if r == 1:
            orc.answer(1)
            return 1
    # Guess: 2 might be zero
    orc.answer(2)
    return 2

def main():
    orc = Oracle()
    n = orc.read_number()
    tc = 0
    while True:
        tc += 1
        print(f"TC {tc}: n={n}", flush=True)
        ans = solve_tc(orc, n, verbose=(tc <= 3 or n > 500))
        print(f"  -> ans={ans}", flush=True)
        # Read next n
        orc.s.settimeout(5)
        try:
            while b'\n' not in orc.buf:
                orc._read_more()
        except (socket.timeout, ConnectionError) as e:
            print(f"Done or timeout: {e}")
            # Read more if possible
            orc.s.settimeout(10)
            try:
                while True:
                    c = orc.s.recv(65536)
                    if not c: break
                    orc.buf += c
            except: pass
            print("FINAL BUF:", orc.buf.decode(errors='replace'))
            return
        line, _, rest = orc.buf.partition(b'\n')
        orc.buf = rest
        s = line.decode(errors='replace').strip()
        if not s.lstrip('-').isdigit():
            print(f"Got non-number: {s!r}")
            # Drain
            orc.s.settimeout(5)
            try:
                while True:
                    c = orc.s.recv(65536)
                    if not c: break
                    orc.buf += c
            except: pass
            print("BUF:", orc.buf.decode(errors='replace'))
            return
        n = int(s)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
