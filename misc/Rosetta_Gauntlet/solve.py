#!/usr/bin/env python3
"""
Rosetta Gauntlet Solver - Complete

Round structure (verified):
  Q1: base64-encoded geography trivia (answers all start with A)
  Q2: hex-encoded math/conversion questions (hex-encode the answer back)
  Q3: atbash-encoded Python/programming questions (atbash-encode answer back)
  Q4: morse-encoded "G" questions (morse-encode answer back)
  Q5: base64-encoded "U" questions (base64-encode answer back)
  Q6: hex-encoded unit conversion questions (hex-encode answer back)
  Q7: atbash-encoded function key question (atbash-encode answer back)
  Q8: morse-encoded Python underscore questions (morse-encode answer back)
  Q9+: unknown
"""

from pwn import *
import base64
import re
import time
import sys

# ======== MORSE ========
MORSE_MAP = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(',
    '-.--.-': ')', '---...': ':', '-.-.-.': ';', '-...-': '=',
    '.-.-.': '+', '-....-': '-', '..--.-': '_', '.-..-.': '"',
    '...-..-': '$', '.--.-.': '@',
}
MORSE_REVERSE = {v: k for k, v in MORSE_MAP.items()}

def decode_morse(s):
    words = s.strip().split(' / ')
    result = []
    for word in words:
        letters = word.strip().split(' ')
        decoded = ''.join(MORSE_MAP.get(l, '') for l in letters if l)
        result.append(decoded)
    return ' '.join(result)

def encode_morse(text):
    text = text.upper()
    words = text.split(' ')
    encoded_words = []
    for word in words:
        letters = [MORSE_REVERSE.get(c, '') for c in word if c in MORSE_REVERSE]
        if letters:
            encoded_words.append(' '.join(l for l in letters if l))
    return ' / '.join(encoded_words)

# ======== ATBASH ========
def atbash(s):
    result = []
    for c in s:
        if c.isupper():
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif c.islower():
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)

# ======== KNOWLEDGE BASES ========
Q1_ANSWERS = {
    'continent at the south pole': 'Antarctica',
    'sahara': 'Africa',
    'sydney opera house': 'Australia',
    'largest continent': 'Asia',
    'egyptian city': 'Alexandria',
    'great library': 'Alexandria',
    'llama': 'Alpaca',
    'letters for unknown': 'Algebra',
    'mathematics uses letters': 'Algebra',
    'nh3': 'Ammonia',
    'chemical formula nh3': 'Ammonia',
    'single-celled organism': 'Amoeba',
    'alters its shape': 'Amoeba',
    'amazon': 'Anaconda',
    'georgia': 'Atlanta',
    'root word for water': 'Aqua',
    'latin root': 'Aqua',
    'artery carrying blood': 'Aorta',
    'main artery': 'Aorta',
}

Q3_ANSWERS = {
    'throwaway': '_',
    'single character': '_',
    'double character': '__',
    'global dummy': '__',
    'initialization': '_init_',
    'dunder': '_init_',
    'entry point': '_main_',
    'primary entry': '_main_',
}

Q4_ANSWERS = {
    'son of gonzalo': 'Gonzalez',
    'gonzalo': 'Gonzalez',
    'selena': 'Gomez',
    'child actress': 'Gomez',
    'billion cycles': 'GHz',
    'three-letter abbreviation': 'GHz',
    'billions of hertz is fully': 'Gigahertz',
    'billions of hertz': 'Gigahertz',
    'processing frequencies': 'Gigahertz',
}

Q5_ANSWERS = {
    'undersea german': 'U-100',
    'triple digits': 'U-100',
    'unicode': 'U+0030',
    'digit zero': 'U+0030',
}

Q6_ANSWERS = {
    '1024 bytes': '1Kilobyte',
    '1024 kilobytes': '1Megabyte',
    '1024 megabytes': '1Gigabyte',
    '1024 gigabytes': '1Terabyte',
    '1024 terabytes': '1Petabyte',
    '1024 petabytes': '1Exabyte',
    'sixty seconds': '1Minute',
    '28.35 grams': '1Ounce',
    '6.022': '1Mole',
    'group of 8 bits': '1Byte',
    '5,280 feet': '1Mile',
    '5280 feet': '1Mile',
}

Q7_ANSWERS = {
    'function key': 'F3',
    'search feature': 'F3',
}

Q8_ANSWERS = {
    'name variables': '_',
    'alphabets and numbers': '_',
    'protected attribute': '_',
    'throwaway variable': '_',
}

# Q9 is dynamic - computed in handle_question

# ======== Q2 COMPUTATION ========
def compute_q2(decoded):
    """Compute answer for Q2 hex-encoded math questions."""
    q = decoded.lower().strip().rstrip('.?!')

    # Octal: "3 octal digits for the number X"
    m = re.search(r'octal digits? for (?:the number )?(\d+)', q)
    if m:
        n = int(m.group(1))
        # n>=64 produces 3-digit octal without leading zero -> server bug, skip
        if n >= 64:
            return None
        return format(n, '03o')

    # Division
    m = re.search(r'(\d+)\s+divided by\s+(\d+)', q)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        # 3/30 = 0.1 -> server rejects, skip
        if a == 3 and b == 30:
            return None
        res = a / b
        if res == int(res):
            return str(int(res))
        return str(res)

    # Currency subtraction: "N dollars minus N dollars"
    if 'dollars minus' in q:
        m2 = re.search(r'(\d+)\s+dollars minus\s+(\d+)', q)
        if m2:
            diff = int(m2.group(1)) - int(m2.group(2))
            return f'{diff:.2f}'

    # General subtraction with words between: "N <words> minus N"
    m = re.search(r'(\d+)\s+(?:\w+\s+)*minus\s+(\d+)', q)
    if m:
        return str(int(m.group(1)) - int(m.group(2)))

    # "minus" standalone
    m = re.search(r'(\d+)\s+minus\s+(\d+)', q)
    if m:
        return str(int(m.group(1)) - int(m.group(2)))

    # "zero in hex" - server expects '0'
    if 'zero in hex' in q:
        return None  # fails with '0', skip for now

    # Hex conversion
    m = re.search(r'what is (\d+) in hex(?:adecimal)?', q)
    if m:
        return hex(int(m.group(1)))[2:].upper()

    m = re.search(r'(\d+) (?:converted? to|in) hex(?:adecimal)?', q)
    if m:
        return hex(int(m.group(1)))[2:].upper()

    # Binary
    m = re.search(r'what is (\d+) in binary', q)
    if m:
        return bin(int(m.group(1)))[2:]

    # Square root
    import math as mathlib
    m = re.search(r'square root of (\d+)', q)
    if m:
        n = int(m.group(1))
        r = int(mathlib.sqrt(n))
        if r * r == n:
            return str(r)

    # Plus
    m = re.search(r'(\d+)\s+(?:\w+\s+)*plus\s+(\d+)', q)
    if m:
        return str(int(m.group(1)) + int(m.group(2)))

    return None


def lookup_answer(question, answer_map):
    """Look up answer from dict by checking if key is substring of question."""
    q_lower = question.lower()
    for key, answer in answer_map.items():
        if key in q_lower:
            return answer
    return None


def handle_question(qnum, raw):
    """
    Given question number and raw (encoded) message,
    returns (decoded_text, answer, encoded_answer) or (decoded, None, None) if unknown.
    """
    if qnum == 1:
        decoded = base64.b64decode(raw).decode()
        ans = lookup_answer(decoded, Q1_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, base64.b64encode(ans.encode()).decode()

    elif qnum == 2:
        decoded = bytes.fromhex(raw).decode()
        ans = compute_q2(decoded)
        if ans is None:
            return decoded, None, None
        return decoded, ans, ans.encode().hex()

    elif qnum == 3:
        decoded = atbash(raw)
        ans = lookup_answer(decoded, Q3_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, atbash(ans)

    elif qnum == 4:
        decoded = decode_morse(raw)
        ans = lookup_answer(decoded, Q4_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, encode_morse(ans)

    elif qnum == 5:
        decoded = base64.b64decode(raw).decode()
        ans = lookup_answer(decoded, Q5_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, base64.b64encode(ans.encode()).decode()

    elif qnum == 6:
        decoded = bytes.fromhex(raw).decode()
        ans = lookup_answer(decoded, Q6_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, ans.encode().hex()

    elif qnum == 7:
        decoded = atbash(raw)
        ans = lookup_answer(decoded, Q7_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, atbash(ans)

    elif qnum == 8:
        decoded = decode_morse(raw)
        ans = lookup_answer(decoded, Q8_ANSWERS)
        if ans is None:
            return decoded, None, None
        return decoded, ans, encode_morse(ans)

    elif qnum == 9:
        # base64-encoded: "Hexadecimal representation of the decimal number X?"
        decoded = base64.b64decode(raw).decode()
        m = re.search(r'decimal number (\d+)', decoded.lower())
        if m:
            n = int(m.group(1))
            ans = hex(n)[2:].upper()
            return decoded, ans, base64.b64encode(ans.encode()).decode()
        return decoded, None, None

    elif qnum == 10:
        # hex-encoded: "_ is a character in keyboard. Pressing Shift + which function key in MS Word changes text case?"
        decoded = bytes.fromhex(raw).decode()
        dl = decoded.lower()
        if 'text case' in dl or 'changes the text' in dl:
            ans = 'F3'
        elif 'function key' in dl and 'word' in dl:
            ans = 'F3'
        else:
            return decoded, None, None
        return decoded, ans, ans.encode().hex()

    elif qnum == 11:
        # atbash-encoded: questions about words starting/ending with specific letters
        decoded = atbash(raw)
        dl = decoded.lower()
        ans = None
        if 'music' in dl:
            ans = '_pop'
        elif 'bird' in dl or 'sound of a bird' in dl:
            # Tried: _chirp, _cheep, _peep, _tweet, _pip, _chirrup, _whoop, _beep, _chip, _swoop, chirp(no_), _CHIRP, _CHEEP - all wrong
            ans = '_chirp'  # retrying with direct send - may be timing issue
        if ans is None:
            return decoded, None, None
        return decoded, ans, atbash(ans)

    elif qnum == 12:
        # Morse-encoded general trivia
        decoded = decode_morse(raw)
        dl = decoded.lower()
        Q12_ANSWERS = {
            'elongated': 'Snake',
            'legless': 'Snake',
            'carnivorous reptile': 'Snake',
            'four equal straight sides': 'Square',
            'geometric shape has four': 'Square',
            'systematic study': 'Science',
            'physical and natural world': 'Science',
            'numerical representation of points': 'Score',
            'points in a game': 'Score',
            'study of living organisms': 'Biology',
            'study of the universe': 'Astronomy',
            'largest planet': 'Jupiter',
            'closest planet to the sun': 'Mercury',
            'planet known for its rings': 'Saturn',
            'chemical symbol for gold': 'Au',
            'chemical symbol for silver': 'Ag',
            'chemical symbol for iron': 'Fe',
            'number of sides in a hexagon': 'Six',
            'number of sides in a pentagon': 'Five',
            'number of sides in an octagon': 'Eight',
            'external form or outline': 'Shape',
            'form or outline of a specific object': 'Shape',
            'outline of a specific': 'Shape',
            'raised platform': 'Stage',
            'theatrical performances': 'Stage',
            'all points equidistant from a center': 'Sphere',
            '3d shape': 'Sphere',
            'void beyond earth': 'Space',
            'beyond earths atmosphere': 'Space',
            'seemingly infinite void': 'Space',
        }
        ans = None
        for k, v in Q12_ANSWERS.items():
            if k in dl:
                ans = v
                break
        if ans is None:
            return decoded, None, None
        return decoded, ans, encode_morse(ans)

    elif qnum == 13:
        # base64-encoded math: "7 multiplied by 0 plus N equals?"
        decoded = base64.b64decode(raw).decode()
        dl = decoded.lower()
        # "N multiplied by M plus K equals?" - N is prefix decoration, answer is just M*K? or N*M+K?
        # When M=0: N*0+K=K works. When M≠0: N*M+K fails. Try: answer = just K (the last constant)
        m = re.search(r'(\d+)\s+multiplied by\s+(\d+)\s+plus\s+(\d+)', dl)
        if m:
            a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if b == 0:
                ans = str(c)  # a*0+c = c
            else:
                # When b!=0, tried a*b+c (wrong). Try just c:
                ans = str(c)
            return decoded, ans, base64.b64encode(ans.encode()).decode()
        # "N times M plus K"
        m = re.search(r'(\d+)\s+times\s+(\d+)\s+plus\s+(\d+)', dl)
        if m:
            a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3))
            ans = str(a * b + c)
            return decoded, ans, base64.b64encode(ans.encode()).decode()
        # "N subtracted from M gives what number?"
        m = re.search(r'(\d+)\s+subtracted from\s+(\d+)', dl)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            ans = str(b - a)
            return decoded, ans, base64.b64encode(ans.encode()).decode()
        # "N minus M"
        m = re.search(r'(\d+)\s+minus\s+(\d+)', dl)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            ans = str(a - b)
            return decoded, ans, base64.b64encode(ans.encode()).decode()
        # "N plus M"
        m = re.search(r'(\d+)\s+plus\s+(\d+)', dl)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            ans = str(a + b)
            return decoded, ans, base64.b64encode(ans.encode()).decode()
        # HTTP status codes: "what 3-digit HTTP status code represents X?"
        HTTP_CODES = {
            'forbidden': '403',
            'not found': '404',
            'ok': '200',
            'internal server error': '500',
            'unauthorized': '401',
            'bad request': '400',
            'created': '201',
            'no content': '204',
            'moved permanently': '301',
            'not modified': '304',
            'method not allowed': '405',
            'conflict': '409',
            'service unavailable': '503',
            'locked': '423',
            'gone': '410',
            'request timeout': '408',
            'too many requests': '429',
            'gateway timeout': '504',
            'payload too large': '413',
            'request entity too large': '413',
            'unprocessable entity': '422',
            'precondition failed': '412',
            'length required': '411',
        }
        # "N plus this HTTP code gives M" pattern
        m = re.search(r'(\d+)\s+plus\s+this\s+http\s+code\s+gives\s+(\d+)', dl)
        if m:
            prefix = int(m.group(1))
            total = int(m.group(2))
            code = str(total - prefix)
            return decoded, code, base64.b64encode(code.encode()).decode()
        for k, v in HTTP_CODES.items():
            if k in dl:
                return decoded, v, base64.b64encode(v.encode()).decode()
        return decoded, None, None

    elif qnum == 15:
        # atbash-encoded math questions; answer is atbash-encoded number
        decoded = atbash(raw)
        dl = decoded.lower()
        ans = None
        # "X degrees, add Y and you get?" or "subtract Y"
        m = re.search(r'(\d+)\s+degrees,\s+add\s+(\d+)', dl)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            ans = str(a + b)
        if ans is None:
            m = re.search(r'(\d+)\s+degrees,\s+subtract\s+(\d+)', dl)
            if m:
                a, b = int(m.group(1)), int(m.group(2))
                ans = str(a - b)
        # "A number X thousand and Y is written as?"
        if ans is None:
            m = re.search(r'number\s+(\w+)\s+thousand\s+and\s+(\w+)\s+is\s+written', dl)
            if m:
                thousands = m.group(1)
                ones = m.group(2)
                num_map = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5,
                           'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10,
                           'zero': 0}
                t = num_map.get(thousands, None)
                o = num_map.get(ones, None)
                if t is not None and o is not None:
                    ans = str(t * 1000 + o)
        # Generic: "X add Y", "X plus Y", "X minus Y", "X subtracted from Y"
        if ans is None:
            m = re.search(r'(\d+)\s+(?:add|plus)\s+(\d+)', dl)
            if m:
                ans = str(int(m.group(1)) + int(m.group(2)))
        if ans is None:
            m = re.search(r'(\d+)\s+subtracted from\s+(\d+)', dl)
            if m:
                ans = str(int(m.group(2)) - int(m.group(1)))
        if ans is None:
            m = re.search(r'(\d+)\s+minus\s+(\d+)', dl)
            if m:
                ans = str(int(m.group(1)) - int(m.group(2)))
        # Pi approximations
        if ans is None:
            if 'pi' in dl and 'four decimal' in dl:
                ans = '3.1415'  # 3.1416 was wrong, trying truncated
            elif 'pi' in dl and 'two decimal' in dl:
                ans = '3.14'
            elif 'pi' in dl and 'five decimal' in dl:
                ans = '3.14159'
            elif 'pi' in dl and ('rounded' in dl or 'approximat' in dl):
                ans = '3.14'
        # Year length
        if ans is None:
            if 'leap year' in dl and 'regular' in dl:
                ans = '365'
            elif 'regular year' in dl or ('year has' in dl and 'regular' in dl):
                ans = '365'
        # Powers: "X to the Y power"
        if ans is None:
            m = re.search(r'(\w+)\s+to\s+the\s+(\w+)\s+power', dl)
            if m:
                num_map = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5,
                           'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10}
                base = num_map.get(m.group(1), None)
                exp = num_map.get(m.group(2), None)
                if base is not None and exp is not None:
                    ans = str(base ** exp)
        # Chemical element atomic numbers
        ATOMIC_NUMBERS = {
            'bromine': '35', 'hydrogen': '1', 'helium': '2', 'carbon': '6',
            'nitrogen': '7', 'oxygen': '8', 'fluorine': '9', 'sodium': '11',
            'magnesium': '12', 'silicon': '14', 'phosphorus': '15', 'sulfur': '16',
            'chlorine': '17', 'potassium': '19', 'calcium': '20', 'iron': '26',
            'copper': '29', 'zinc': '30', 'gold': '79', 'silver': '47',
            'mercury': '80', 'lead': '82', 'uranium': '92',
        }
        if ans is None:
            for elem, num in ATOMIC_NUMBERS.items():
                if elem in dl and 'atomic number' in dl:
                    ans = num
                    break
        # Fraction conversions
        if ans is None:
            import fractions
            m = re.search(r'(\d+\.?\d*)\s+(?:can be represented as|as)\s+(?:a )?fraci?on\s+in\s+simplest\s+form', dl)
            if m:
                f = fractions.Fraction(m.group(1)).limit_denominator(1000)
                ans = f'{f.numerator}/{f.denominator}'
        # "N can be represented as fraction in simplest form"
        if ans is None:
            m = re.search(r'(\d+\.?\d*)\s+can be represented as frac', dl)
            if m:
                import fractions
                f = fractions.Fraction(m.group(1)).limit_denominator(1000)
                ans = f'{f.numerator}/{f.denominator}'
        if ans is None:
            return decoded, None, None
        return decoded, ans, atbash(ans)

    elif qnum == 18:
        # hex-encoded questions (same cycle as Q14 but 18 = 14+4)
        try:
            decoded = bytes.fromhex(raw).decode()
        except Exception:
            return raw, None, None
        dl = decoded.lower()
        Q18_ANSWERS = {
            'repeats the previous command': '!!',
            'previous command': '!!',
            'repeat last command': '!!',
            'two-character command': '!!',
            'mathematical operation when placed after an integer': 'Factorial',
            'factorial': 'Factorial',
            'logical not operator': '!',
            'single character is used as the logical not': '!',
            'logical not': '!',
        }
        ans = None
        for k, v in Q18_ANSWERS.items():
            if k in dl:
                ans = v
                break
        if ans is None:
            return decoded, None, None
        return decoded, ans, ans.encode().hex()

    elif qnum == 17:
        # base64-encoded Bash/programming questions
        decoded = base64.b64decode(raw).decode()
        dl = decoded.lower()
        Q17_ANSWERS = {
            'repeats the previous command': '!!',
            'previous command': '!!',
            'repeat last command': '!!',
            'history expansion': '!!',
            'mathematical operation when placed after an integer': '!',  # send ! not Factorial
            'denotes what mathematical operation': '!',
            'logical not operator': '!',
            'single character is used as the logical not': '!',
            'logical not': '!',
        }
        ans = None
        for k, v in Q17_ANSWERS.items():
            if k in dl:
                ans = v
                break
        if ans is None:
            return decoded, None, None
        return decoded, ans, base64.b64encode(ans.encode()).decode()

    elif qnum == 16:
        # Morse-encoded programming questions
        decoded = decode_morse(raw)
        dl = decoded.lower()
        Q16_ANSWERS = {
            'logical not operator': '!',
            'logical not': '!',
            'not operator': '!',
            'bang character': '!',
            'exclamation mark': '!',
            'mathematical operation when placed after an integer': '!',  # symbol for factorial
            'factorial': '!',
            'repeats the previous command': '!!',
            'previous command': '!!',
            'repeat last command': '!!',
            'two-character command': '!!',
        }
        ans = None
        for k, v in Q16_ANSWERS.items():
            if k in dl:
                ans = v
                break
        if ans is None:
            return decoded, None, None
        return decoded, ans, encode_morse(ans)

    elif qnum == 14:
        # hex-encoded questions; answers start with 'X' (or similar)
        try:
            decoded = bytes.fromhex(raw).decode()
        except Exception:
            return raw, None, None
        dl = decoded.lower()
        Q14_ANSWERS = {
            'autonomous region': 'Xinjiang',
            'nw china': 'Xinjiang',
            'provinces in nw': 'Xinjiang',
            'x window system display server': 'Xorg',
            'open-source implementation of the x window': 'Xorg',
            'x window system': 'Xorg',
        }
        ans = None
        for k, v in Q14_ANSWERS.items():
            if k in dl:
                ans = v
                break
        if ans is None:
            return decoded, None, None
        return decoded, ans, ans.encode().hex()

    else:
        return raw, None, None


# ======== MAIN SOLVE ========
def solve_once():
    """Single attempt at the gauntlet. Returns True if flag found, False otherwise."""
    r = remote('34.131.41.57', 1337)
    r.recvuntil(b'begin...')
    r.sendline(b'')
    r.recvline()  # empty line

    flag_found = False
    for i in range(30):
        try:
            data = r.recvuntil(b'Answer > ', timeout=10)
        except EOFError:
            log.info("Connection ended")
            try:
                remaining = r.recvall(timeout=3)
                out = remaining.decode(errors='replace')
                print(out)
                if 'ictf{' in out:
                    m = re.search(r'ictf\{[^}]+\}', out)
                    if m:
                        flag = m.group(0)
                        log.success(f"FLAG: {flag}")
                        with open('flag.txt', 'w') as f:
                            f.write(flag + '\n')
                        flag_found = True
            except:
                pass
            break

        data_str = data.decode(errors='replace')

        m_round = re.search(r'Question (\d+)', data_str)
        m_msg = re.search(r'Message: (.+?)(?:\r?\n|$)', data_str)

        if not m_msg:
            r.sendline(b'')
            continue

        raw_message = m_msg.group(1).strip()
        qnum = int(m_round.group(1)) if m_round else 0

        decoded, answer, encoded_answer = handle_question(qnum, raw_message)

        log.info(f"Q{qnum}: {decoded!r} -> {answer!r}")

        if answer is None:
            log.warning(f"Q{qnum} UNKNOWN/SKIP: {decoded!r}")
            r.close()
            return False

        r.sendline(encoded_answer.encode())

        # Quick feedback check - don't wait too long
        try:
            feedback = r.clean(0.2)
            if feedback:
                fb = feedback.decode(errors='replace').strip()
                if fb:
                    log.info(f"  feedback: {fb!r}")
                if 'WRONG' in fb or 'DROPPED' in fb or 'TIME IS UP' in fb:
                    log.error(f"Q{qnum} WRONG: {decoded!r} -> {answer!r}")
                    r.close()
                    return False
                if 'ictf{' in fb:
                    m = re.search(r'ictf\{[^}]+\}', fb)
                    if m:
                        flag = m.group(0)
                        log.success(f"FLAG: {flag}")
                        with open('flag.txt', 'w') as f:
                            f.write(flag + '\n')
                        flag_found = True
                    # Try to get more
                    try:
                        more = r.clean(5)
                        print(more.decode(errors='replace'))
                    except:
                        pass
                    r.close()
                    return True
        except:
            pass

    try:
        r.close()
    except:
        pass
    return flag_found


def solve():
    context.log_level = 'info'

    max_attempts = 50
    for attempt in range(max_attempts):
        log.info(f"Attempt {attempt + 1}/{max_attempts}")
        try:
            result = solve_once()
            if result:
                log.success("Flag captured!")
                break
        except Exception as e:
            log.warning(f"Exception: {e}")

        # Small backoff between attempts
        time.sleep(0.5)


if __name__ == '__main__':
    solve()
