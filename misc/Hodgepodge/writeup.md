# Hodgepodge

**Category:** Misc | **Difficulty:** Hard (400 pts, 1 solve) | **Flag:** `iiitl{d39end3nc3_15_n0t_4lway5_64d_4nd_p13as3_c0m3_back}`

## TL;DR

A React SPA with heavily obfuscated JavaScript hides a secret route and a 12-step credential encoding pipeline. The actual credentials are buried inside a custom npm package: the username comes from a PRNG-seeded binary blob reader, and the password is a phrase constructed from thematic hints scattered across fabricated git history. Everything else — fake XOR keys, decoy commit messages, nested git repos, binary garbage — is noise.

## What We're Given

The challenge drops us with two URLs:

- Frontend: `https://hodgepodge-ctf.vercel.app` — a React SPA
- Backend: `https://hodgepodge-rs6v.onrender.com` — a Flask API

No source files are given directly, but the React app ships its JavaScript bundle to the browser, which means we can read it. The challenge name, "Hodgepodge," is a dead giveaway that we're in for a mishmash of techniques, red herrings, and layers of obfuscation. It is not lying.

## Initial Recon

Opening the frontend in the browser shows a normal-looking React app. Nothing obviously useful. First instinct: crack open DevTools and look at the JavaScript sources.

The bundle is obfuscated, but one file stands out — `_seg.js`. It contains a string encoded with a rolling XOR cipher: each byte is XOR'd with `(_i * 17 + 5) & 0xFF`. Decoding that gives us:

```
xK3p9mL2vQ8nR7
```

That's a route. Navigating to `https://hodgepodge-ctf.vercel.app/xK3p9mL2vQ8nR7` reveals a login portal — username and password fields that POST encoded credentials to `https://hodgepodge-rs6v.onrender.com/api/auth`.

Now we know the shape of the challenge: find the right credentials, send them through the encoding pipeline, get the flag.

Looking at `src/utils/encoding.js` in the bundle, we find `encodeCredential` — a 12-step encoding function. The pipeline also references a third-party npm package called `symatrix`.

## The Vulnerability / Trick

This challenge is less about a "vulnerability" in the traditional sense and more about a multi-layered puzzle where 95% of the content is designed to waste your time.

### Layer 1: The `symatrix` Package

`symatrix` is a custom npm package published by user `uknowmeiknowu1` (email: `uknowmeiknowu384@gmail.com`). It exports `xorEncode`, `substitute`, `normalize`, and `decode`. But buried inside the package — never exported, never called anywhere in the frontend — is a function called `_fromBlob()`.

`_fromBlob()` reads a 26MB binary file called `data.bin` that contains output from an SFMT (SIMD-oriented Fast Mersenne Twister) PRNG, seeded with `_PIPELINE_SEED = 0x53594D41` (which is the ASCII string `'SYMA'`). It walks the data using a linear congruential generator, extracts bytes, and assembles them into a string.

The output of `_fromBlob()` is `"uwillnotcomeback"`.

This is the username.

The fact that `_fromBlob()` is never called and never exported is the whole trick — you only find it by reading the package source carefully, and you have to trust that a dormant function in a mystery package is giving you real information rather than just being another red herring.

### Layer 2: The Password

The GitHub OAuth redirect URL in the app contains:

```
client_id=Iv1.d3p3nd3nc3app
```

"d3p3nd3nc3" is leetspeak for "dependence." The flag itself confirms this: `d39end3nc3_15_n0t_4lway5_64d` — "dependence is not always bad."

Combine this with the username: "never be dependent on uwillnotcomeback."

The password is `neverbedependentonuwillnotcomeback`.

### The 12-Step Encoding Pipeline

Once you have the credentials, you still need to encode them before POSTing. The `encodeCredential` function applies twelve transformations in sequence:

1. XOR each character with `0x37`, output as comma-separated decimals
2. Base64 encode
3. Reverse the string
4. Atbash cipher (A↔Z, B↔Y, etc.)
5. Base32 encode
6. ROT13
7. Hex encode
8. Base64 encode again
9. Reverse again
10. ROT47 (printable ASCII rotation)
11. Custom substitution table (from `symatrix`)
12. Base64 encode one final time

Yes, twelve steps. Most of them individually reversible and not cryptographically interesting. The point is to make you implement all of them correctly.

## Dead Ends (and There Are Many)

The challenge is aggressively padded with distractions. Here's what burned time:

**Nested git repositories.** The challenge zip contains a project with six nested `.git/` directories hidden inside the main `.git/` folder (in `.git/hooks/`, `.git/info/`, `.git/objects/`, etc.). Each has a fabricated 4-5 commit history including commits by fake usernames (`n3tw0rk_j`, `s3rv_acc01`, `r00t_patcher`, `d3pl0y3r_b0t`). One commit is explicitly titled "thanks for wasting your time." The last commit says "something is off, ain't it?" A key commit by `r00t_patcher` was scrubbed via `filter-branch`, leaving a dangling tree hash `9d8c3fc3` that goes nowhere.

**Fake XOR keys.** One commit message contains:
```
XOR_KEY=0x110x130x160x140x170x3A0x170x490xC80xC2
```
This is not the XOR key. The real key is `0x37`, which is right there in the symatrix package source.

**More fake symatrix keys.** Another commit drops:
```
symatrix:XROENCODE_KEY=0xAAFF9987::init_vector=0xDEADBEEF
```
Also fake.

**Binary garbage base64.** The string `qTuuozgmVTMipvO3LKA0nJ5aVUyiqKVtqTygMD==` appears as a commit message. It looks like it could be an encoded credential. It isn't — decoding it produces binary garbage.

**The broken `decode()` function.** `symatrix` exports a `decode()` function that looks like it should reverse the pipeline. It's broken by design. We tested it; it outputs nonsense.

**Over 100 credential combinations.** We tried usernames like `n3tw0rk_j`, `s3rv_acc01`, `r00t_patcher`, `d3pl0y3r_b0t`, `uknowmeiknowu1`, `d3p3nd3nc3`, `independence`, and plain `uwillnotcomeback` — all without the correct password. All returned 401.

The only way through is to connect `_fromBlob()` → username and the "dependence" theme → password. Both pieces of information are in the challenge; you just have to trust them while ignoring everything else screaming for your attention.

## Building the Exploit

The solve script reconstructs the entire encoding pipeline in Python, then POSTs the encoded credentials.

**Step 1: XOR encode (0x37)**

```python
def xor_encode(s):
    return ','.join(str(ord(c) ^ 0x37) for c in s)
```

Each character is XOR'd with `0x37` (decimal 55) and the results are joined with commas. XOR is its own inverse — applying it twice recovers the original — but here we only need to go forward.

**Step 2-9: Standard transforms**

The middle steps are all reversible classic encodings — Base64, Base32, ROT13, ROT47, Atbash, hex, and two reversal passes. We implement each directly in Python. Nothing exotic; they just need to be in the right order.

**Step 11: The symatrix substitution table**

This is the one that required reading the package source carefully. The custom substitution table maps uppercase and lowercase letters (shifted by 7 positions within A-Z), digits 0-4 ↔ 5-9, and some punctuation:

```python
SUB_TABLE = {
    'A':'H', 'B':'I', ..., 'Z':'G',
    'a':'h', 'b':'i', ..., 'z':'g',
    '0':'5', '1':'6', '2':'7', '3':'8', '4':'9',
    '5':'0', '6':'1', '7':'2', '8':'3', '9':'4',
    '+':'-', '-':'+', '/':'|', '|':'/', '=':'~', '~':'='
}
```

The last few entries matter because Base64 padding uses `=` and the output can contain `+` and `/`.

**Step 12: Final Base64**

After substitution, one final Base64 encode. That's the string we send.

**Putting it together:**

```python
def encode_credential(plaintext):
    s = xor_encode(plaintext)                     # Step 1
    s = base64.b64encode(s.encode()).decode()      # Step 2
    s = s[::-1]                                    # Step 3
    s = atbash(s)                                  # Step 4
    s = b32encode(s)                               # Step 5
    s = rot13(s)                                   # Step 6
    s = hex_encode(s)                              # Step 7
    s = base64.b64encode(s.encode()).decode()      # Step 8
    s = s[::-1]                                    # Step 9
    s = rot47(s)                                   # Step 10
    s = substitute(s)                              # Step 11
    s = base64.b64encode(s.encode()).decode()      # Step 12
    return s
```

Then the actual POST:

```python
USERNAME = "uwillnotcomeback"
PASSWORD = "neverbedependentonuwillnotcomeback"
AUTH_URL = "https://hodgepodge-rs6v.onrender.com/api/auth"

eu = encode_credential(USERNAME)
ep = encode_credential(PASSWORD)

r = requests.post(AUTH_URL, json={"username": eu, "password": ep}, timeout=30)
print(r.text)
```

## Running It

```
$ python3 solve.py
Encoded username: d2FnZWZubXVuaGZubXVuaGZubXVuaGZubXVuaGZubXVuaGZubXVuaGZu...
Encoded password: d2FnZWZubXVuaGZubXVuaGZubXVuaGZubXVuaGZubXVuaGZubXVuaGZu...
Status: 200
Response: {"flag":"iiitl{d39end3nc3_15_n0t_4lway5_64d_4nd_p13as3_c0m3_back}"}

FLAG: iiitl{d39end3nc3_15_n0t_4lway5_64d_4nd_p13as3_c0m3_back}
Saved to flag.txt
```

The flag decodes as: "dependence is not always bad and please come back" — a little wink at the username "uwillnotcomeback" and the whole "independence" theme the challenge had been hiding behind.

## Key Takeaways

**Read third-party dependencies.** The entire solve hinges on a function in a custom npm package that is never called and never exported. In a real-world context this would be a supply chain backdoor. In this CTF context, it's the one piece of honest information in a sea of noise. Always read the deps.

**The theme is the hint.** "d3p3nd3nc3" appeared in the OAuth client ID, in the flag format hint, and thematically throughout. When a challenge is that insistent about a word, it's probably load-bearing. The password assembled naturally once we accepted that "dependence" was pointing at a relationship between two already-known strings.

**Trust the signal, ignore the noise.** Over 100 credential combinations. Fake XOR keys. A broken decode function. Nested git repos. Binary garbage. This challenge was built to exhaust you into accepting a wrong answer. The correct approach was to keep a list of "things that feel like they might actually matter" separate from "things that are definitely junk."

**XOR key identification.** When you see a custom encoding library, `0x37` appearing consistently as the only non-fabricated constant is a strong signal. The fake keys (`0xAAFF9987`, `0xDEADBEEF`, the byte sequence in the commit message) all looked more impressive. The real one was quiet.

**The challenge name tells you everything.** "Hodgepodge" = a confused mixture of things. That's the challenge design philosophy stated upfront. If you keep that in mind, the red herrings become less disorienting — you're *expecting* a mess, so you stay methodical about what you've actually confirmed versus what just looks plausible.
