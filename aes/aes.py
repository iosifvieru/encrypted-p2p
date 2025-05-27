"""
Documentatia oficiala se poate gasi accesand linkul de mai jos.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
"""

from aes.aes_constants import s_box, Rcon

def get_nr(key_length):
    """
    Returneaza numarul de runde in fct. de lungimea cheii.
    cheie de 128 biti -> 10 runde
    cheie de 192 biti -> 12 runde
    cheie de 256 biti -> 14 runde
    """
    match key_length:
        case 128:
            return 10
        case 192:
            return 12
        case 256:
            return 14
        case _:
            return 0

def state_from_bytes(input: bytes) -> list[list[int]]:
    assert len(input) == 16, "Inputul trebuie sa aiba exact 16 bytes"

    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = input[c * 4 + r]
    return state


def sub_word(word):
    s_word = []
    for byte in word:
        s_word.append(s_box[byte])

    return s_word

def rot_word(word):
    return word[1:] + word[:1]

def rcon(i: int) -> bytes:
    return Rcon[i-1]

def xor_b(a, b):
    assert len(a) == len(b)

    res = []
    for i in range(len(a)):
        res.append(a[i] ^ b[i])

    return res

def split_key_to_words(key: bytes) -> list[list[int]]:
    assert len(key) % 4 == 0
    return [list(key[i:i+4]) for i in range(0, len(key), 4)]


def key_expansion(key):
    """
    Genereaza round keys -> sunt utilizate in criptare.

    pseudocod preluat:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    
    pagina 18 (26 of 46)
    """

    # Nk -> numarul de cuvinte (word) care alcatuiesc cheia initiala.
    # de notat: word -> 4 bytes (32 biti pe romaneste)
    Nk = len(key) // 4

    # calculam lungimea cheii in biti pt. a afla nr de runde.
    key_length = len(key)*8
    nr = get_nr(key_length)

    # convertim cheia initiala intr-un vector de words (4 bytes fiecare)
    w = split_key_to_words(key)

    # generam cheile de runda.
    for i in range(Nk, 4*(nr+1)):
        # cuvantul anterior
        tmp = w[i - 1]

        # aplicam rotatia, substitutie, adaugarea valorii constante (RCON) si facem xor.
        # pentru a obtine un nou cuvant.
        if i % Nk == 0:
            tmp = xor_b(sub_word(rot_word(tmp)), rcon(i // Nk))
        # daca lungimea cheii > 128 biti si pozitia e multiplu de 4 at. aplicam substitutie cu S_BOX
        elif Nk > 6 and i % Nk == 4:
            tmp = sub_word(tmp)
        
        # aici iar xor sa generam noul cuvant (n am prea inteles exact)
        w.append(xor_b(w[i - Nk], tmp))

    return w 

def add_round_key(state, key_schedule):
    res = []
    for i, line in enumerate(state):
        xor_res_line = xor_b(line, key_schedule[i])
        res.append(xor_res_line)

    return res

def from_byte_to_sbox(byte):
    upper_nibble = byte >> 4
    lower_nibble = byte & 0xF
    return s_box[16 * upper_nibble + lower_nibble]

def sub_bytes(state):
    new_state = []
    for line in range(0, len(state)):
        new_state_line = []
        for col in range(0, len(state[line])):
            byte = state[line][col]
            byte_from_sbox = from_byte_to_sbox(byte)

            new_state_line.append(byte_from_sbox)
        new_state.append(new_state_line)

    return new_state

def shift_rows(state):
    new_state = []
    for i in range(0, len(state)):
        new_state_line = state[i][i:] + state[i][:i]
        new_state.append(new_state_line)

    return new_state

def xTimes(byte):
    if byte & (2 ** 7) == 0:
        byte = (byte << 1) & 0xFF
    else:
        byte = ((byte << 1) ^ 27) & 0xFF

    return byte

def mul_gf8(byte, mul_byte):
    if mul_byte == 1:
        return byte
    if mul_byte == 2:
        byte = xTimes(byte)
        return byte
    if mul_byte == 3:
        byte = xTimes(byte) ^ byte
        return byte
    return 0

def extract_column(state, col):
    extracted_col = []
    for line in range(0, len(state)):
        extracted_col.append(state[line][col])

    return extracted_col

def multiply_column(col):
    elem0 = mul_gf8(col[0], 2) ^ mul_gf8(col[1], 3) ^ mul_gf8(col[2], 1) ^ mul_gf8(col[3], 1)
    elem1 = mul_gf8(col[0], 1) ^ mul_gf8(col[1], 2) ^ mul_gf8(col[2], 3) ^ mul_gf8(col[3], 1)
    elem2 = mul_gf8(col[0], 1) ^ mul_gf8(col[1], 1) ^ mul_gf8(col[2], 2) ^ mul_gf8(col[3], 3)
    elem3 = mul_gf8(col[0], 3) ^ mul_gf8(col[1], 1) ^ mul_gf8(col[2], 1) ^ mul_gf8(col[3], 2)

    return [elem0, elem1, elem2, elem3]

def mix_columns(state):
    new_state = []
    for line in range(0, len(state)):
        new_state.append([])

    for col in range(0, len(state[0])):
        extracted_col = extract_column(state, col)
        res_col = multiply_column(extracted_col)
        for line in range(0, len(state)):
            new_state[line].append(res_col[line])

    return new_state

def bytes_from_state(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def round_key_matrix(key_words):
    return [[key_words[c][r] for c in range(4)] for r in range(4)]

def aes_encryption(input: bytes, key: bytes):
    """
    Criptare AES.

    Pseudocod preluat:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    Pagina 12 (20 of 46)
    """
    state = state_from_bytes(input)
    key_schedule = key_expansion(key)

    key_length = len(key) * 8
    nr = get_nr(key_length)

    state = add_round_key(state, round_key_matrix(key_schedule[0:4]))

    for round in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_key_matrix(key_schedule[ 4 * round : 4 * (round + 1) ]))

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key_matrix(key_schedule[4 * nr :  4 * (nr + 1) ]))

    cipher = bytes_from_state(state)
    return cipher