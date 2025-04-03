"""
RFC8017: RSA Cryptography Specifications Version 2.2
https://datatracker.ietf.org/doc/html/rfc8017
"""

from Cryptodome.Util import number
import math

def alg_euclid_extins(a, b):
    """
    Algoritmul lui Euclid extins -> determina CMMDC al doua numere si coef x si y a.i:
        ax + by = cmmdc(a,b)
    """
    if b == 0:
        return a, 1, 0
    
    gcd, x1, y1 = alg_euclid_extins(b, a % b)
    x = y1
    y = x1 - (a // b) * y1;
    return gcd, x, y

# """
# Functie ce calculeaza CMMDC(Algoritmul lui Euclid) prin impartiri repetate.
# """
# def cmmdc(a, b):
#     while b != 0:
#         a, b = b, a % b
#     return a

def rsa_generate_keys(no_bits: int):
    """
    Functie de genereaza un set de key folosind alg. RSA
        no_bits: intreg -> nr de biti pentru generarea numerelor prime p si q.
        returneaza o lista (public key, private_key)
        
    Pasii necesari in generarea cheilor:
    1. Se genereaza doua numere prime.
    2. Se calculeaza n = p * q si phi = (p - 1) * (q - 1)
    3. Se alege un nr. aleator e  a.i 1 < e < phi(n) si cmmdc(e, phi) = 1.
    4. Se calculeaza intregul a.i d*e == 1 mod phi.

    public key: (n, e)
    private key: (n, d)
    """
    
    # 1. generam doua numere prime (de preferat mari.)
    p = number.getPrime(no_bits)
    q = number.getPrime(no_bits)

    # 2. calculam n = p * q si phi = (p-1) * (q - 1)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # 3. alegem un e, a.i 1 < e < phi(n) si cmmdc(e, phi) = 1."
    # Perechea (n,e) este cheia publica.
    e = 2**16 + 1
    cmmdc, _, _ = alg_euclid_extins(e, phi)
    if cmmdc != 1:
        for e in range(2, phi):
            cmmdc, _, _ = alg_euclid_extins(e, phi)
            if cmmdc == 1:
                break
        
    # 4. calculam d a.i e * d == 1 % phi
    _, d, _ = alg_euclid_extins(e, phi)
    if d < 0:
        d += phi

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key

def rsa_encrypt(message, public_key):
    n, e = public_key

    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)

def string_to_int(string: str):
    # string_int = int.from_bytes(string.encode("utf-8"), byteorder="big")
    # return string_int
    return int.from_bytes(string.encode("utf-8"), byteorder="big")

def int_to_string(integer: int):
    length = math.ceil(integer.bit_length() / 8)
    message_bytes = integer.to_bytes(length, byteorder="big")
    return message_bytes.decode()

if __name__ == "__main__":
    public_key, private_key = rsa_generate_keys(512)

    print("cheie publica:", public_key)
    print("cheie_privata:", private_key)

    mesaj = input("Introdu textul: ")
    print("mesaj original:", mesaj)

    mesaj_int = string_to_int(mesaj)

    cipher = rsa_encrypt(mesaj_int, public_key)
    print("mesaj criptat:", cipher)

    plain_decrypt = rsa_decrypt(cipher, private_key)
    plain_decrypt = int_to_string(plain_decrypt)
    print("mesaj decriptat:", plain_decrypt)