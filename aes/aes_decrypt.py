from aes import state_from_bytes
from aes.aes_constants import inv_s_box, mul_mat_decrypt
from aes.aes_commons import get_nr, xor_b, sub_word, rot_word, rcon, mix_columns, split_key_to_words, add_round_key, \
    round_key_matrix, bytes_from_state


def inv_shift_rows(state):
    new_state = []
    for i in range(0, len(state)):
        new_state_line = state[i][-i:] + state[i][:-i]
        new_state.append(new_state_line)

    return new_state

def from_byte_to_inv_sbox(byte):
    upper_nibble = byte >> 4
    lower_nibble = byte & 0xF
    return inv_s_box[16 * upper_nibble + lower_nibble]

def inv_sub_bytes(state):
    new_state = []
    for line in range(0, len(state)):
        new_state_line = []
        for col in range(0, len(state[line])):
            byte = state[line][col]
            byte_from_sbox = from_byte_to_inv_sbox(byte)

            new_state_line.append(byte_from_sbox)
        new_state.append(new_state_line)

    return new_state


def key_expansion_eic(key):
    """
    Genereaza round keys -> sunt utilizate in criptare.

    pseudocod preluat:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

    pagina 18 (26 of 46)
    """

    Nk = len(key) // 4

    key_length = len(key) * 8
    nr = get_nr(key_length)

    w = split_key_to_words(key)

    for i in range(Nk, 4 * (nr + 1)):
        tmp = w[i - 1]

        if i % Nk == 0:
            tmp = xor_b(sub_word(rot_word(tmp)), rcon(i // Nk))

        elif Nk > 6 and i % Nk == 4:
            tmp = sub_word(tmp)

        w.append(xor_b(w[i - Nk], tmp))

    for round in range(1, nr):
        i = 4 * round
        mixed = mix_columns(round_key_matrix(w[i: i + 4]), mul_mat_decrypt)
        w[i:i + 4] = [[mixed[c][r] for c in range(4)] for r in range(4)]

    return w


def aes_decryption(input: bytes, key: bytes):
    """
    Criptare AES.

    Pseudocod preluat:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    Pagina 12 (20 of 46)
    """
    state = state_from_bytes(input)
    key_schedule = key_expansion_eic(key)

    key_length = len(key) * 8
    nr = get_nr(key_length)

    state = add_round_key(state, round_key_matrix(key_schedule[4 * nr : 4 * (nr + 1)]))

    for round in range(nr-1, 0, -1):
        state = inv_sub_bytes(state)
        state = inv_shift_rows(state)
        state = mix_columns(state, mul_mat_decrypt)
        state = add_round_key(state, round_key_matrix(key_schedule[ 4 * round : 4 * (round + 1) ]))

    state = inv_sub_bytes(state)
    state = inv_shift_rows(state)
    state = add_round_key(state, round_key_matrix(key_schedule[0:4]))

    cipher = bytes_from_state(state)
    return cipher