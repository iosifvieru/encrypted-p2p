"""
Documentatia oficiala se poate gasi accesand linkul de mai jos.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
"""
from aes.aes_commons import (get_nr, xor_b, rot_word, rcon,
                             state_from_bytes, add_round_key,
                             split_key_to_words, bytes_from_state,
                             mix_columns, round_key_matrix, sub_word)
from aes.aes_constants import s_box, mul_mat_crypt


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
        state = mix_columns(state, mul_mat_crypt)
        state = add_round_key(state, round_key_matrix(key_schedule[ 4 * round : 4 * (round + 1) ]))

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key_matrix(key_schedule[4 * nr :  4 * (nr + 1) ]))

    cipher = bytes_from_state(state)
    return cipher