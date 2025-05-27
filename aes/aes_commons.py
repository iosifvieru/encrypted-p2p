from aes.aes_constants import Rcon, s_box

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

def xTimes(byte):
    if byte & (2 ** 7) == 0:
        byte = (byte << 1) & 0xFF
    else:
        byte = ((byte << 1) ^ 27) & 0xFF

    return byte

# function was inspired from here:
# https://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns
def mul_gf8(byte, mul_byte):
    if mul_byte == 1:
        return byte
    if mul_byte == 2:
        byte = xTimes(byte)
        return byte
    if mul_byte == 3:
        byte = xTimes(byte) ^ byte
        return byte
    if mul_byte == 9:
        byte = (xTimes(xTimes(xTimes(byte)))) ^ byte
        return byte
    if mul_byte == 11:
        byte = xTimes(xTimes(xTimes(byte)) ^ byte) ^ byte
        return byte
    if mul_byte == 13:
        byte = ( xTimes( xTimes( ( xTimes(byte) ) ^ byte ) ) ) ^ byte
        return byte
    if mul_byte == 14:
        byte = xTimes(    (xTimes(    (xTimes (byte)) ^ byte) ) ^ byte )
        return byte
    return 0


def add_round_key(state, key_schedule):
    res = []
    for i, line in enumerate(state):
        xor_res_line = xor_b(line, key_schedule[i])
        res.append(xor_res_line)

    return res

def bytes_from_state(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def split_key_to_words(key: bytes) -> list[list[int]]:
    assert len(key) % 4 == 0
    return [list(key[i:i+4]) for i in range(0, len(key), 4)]

def extract_column(state, col):
    extracted_col = []
    for line in range(0, len(state)):
        extracted_col.append(state[line][col])

    return extracted_col

def multiply_column(col, mul_mat):
    elem0 = mul_gf8(col[0], mul_mat[0][0]) ^ mul_gf8(col[1], mul_mat[0][1]) ^ mul_gf8(col[2], mul_mat[0][2]) ^ mul_gf8(col[3], mul_mat[0][3])
    elem1 = mul_gf8(col[0], mul_mat[1][0]) ^ mul_gf8(col[1], mul_mat[1][1]) ^ mul_gf8(col[2], mul_mat[1][2]) ^ mul_gf8(col[3], mul_mat[1][3])
    elem2 = mul_gf8(col[0], mul_mat[2][0]) ^ mul_gf8(col[1], mul_mat[2][1]) ^ mul_gf8(col[2], mul_mat[2][2]) ^ mul_gf8(col[3], mul_mat[2][3])
    elem3 = mul_gf8(col[0], mul_mat[3][0]) ^ mul_gf8(col[1], mul_mat[3][1]) ^ mul_gf8(col[2], mul_mat[3][2]) ^ mul_gf8(col[3], mul_mat[3][3])

    return [elem0, elem1, elem2, elem3]

def mix_columns(state, mul_mat):
    new_state = []
    for line in range(0, len(state)):
        new_state.append([])

    for col in range(0, len(state[0])):
        extracted_col = extract_column(state, col)
        res_col = multiply_column(extracted_col, mul_mat)
        for line in range(0, len(state)):
            new_state[line].append(res_col[line])

    return new_state

def sub_word(word):
    s_word = []
    for byte in word:
        s_word.append(s_box[byte])

    return s_word

def round_key_matrix(key_words):
    return [[key_words[c][r] for c in range(4)] for r in range(4)]

