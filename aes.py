"""
Documentatia oficiala se poate gasi accesand linkul de mai jos.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
"""

from aes_constants import s_box

def get_nr(key_length):
    """
    Returneaza numarul de runde in fct. de lungimea cheii.
    10 runde -> cheie de 128 biti.
    12 runde -> cheie de 192 biti.
    14 runde -> cheie de 256 biti.
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

def state_from_bytes(input: bytes) -> list[int]:
    """
    Imparte cheia / inputul in 4-byte chunk.
    ex:
    01234556789ABCDEF -> 
        [
            [0, 1, 2, 3],
            [4, 5, 6, 7],
            [8, 9, A, B],
            [C, D, E, F]
        ]
    """

    state = []
    
    for r in range(4):
        slice = input[r*4: (r+1)*4]
        
        l = []
        for i in slice:
            l.append(int(i))
                        
        state.append(l)

    return state

def sub_word(word) -> bytes:
    """
    Primeste un cuvant (array de 4 bytes), itereaza prin fiecare byte si aplica
    substitutia AES S-BOX (inlocuieste i cu valoarea din s_box)
    """
    return bytes(s_box[i] for i in word)

def rot_word(word):
    """
    Primeste o lista de intregi si face o shiftare la stanga prin rotatie.
    """
    return word[1:] + word[:1]

def rcon(i: int) -> bytes:
    """
    RCON -> Round Constant.
    """
    pass

def xor_b(a, b):
    pass

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
    w = state_from_bytes(key)

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

def add_round_key(state, key_schedule, round):
    pass
        
def sub_bytes(state):
    pass

def shift_rows(state):
    pass

def mix_columns(state):
    pass

def bytes_from_state(state: list[int]):
    cipher = bytes(state[0] + state[1] + state[2] + state[3])
    return cipher

def aes_encryption(input: bytes, key: bytes):
    """
    Criptare AES.

    Pseudocod preluat:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    Pagina 12 (20 of 46)
    """
    state = state_from_bytes(input)
    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule, round=0)

    key_length = len(key) * 8
    nr = get_nr(key_length)

    for round in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    cipher = bytes_from_state(state)
    return cipher