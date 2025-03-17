from Cryptodome.Util import number
import base64


"""
Algoritmul lui Euclid extins -> determina CMMDC al doua numere si coef x si y a.i:
    ax + by = cmmdc(a,b)
"""
def alg_euclid_extins(a, b):
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
    1. Generam doua numere prime (de preferat mari.)
    """
    p = number.getPrime(no_bits)
    q = number.getPrime(no_bits)

    #print("p: ", p)
    #print("q: ", q)

    """
    2. Calculam n = p * q si phi = (p-1) * (q - 1)
    """
    n = p * q
    #print("n: ", n)
    phi = (p - 1) * (q - 1)
    #print("phi: ", phi)

    """
    3. Alegem un e, a.i 1 < e < phi(n) si cmmdc(e, phi) = 1."
    
    Perechea (n,e) este cheia publica.
    """
    e = 0
    for e in range(2, phi):
        cmmdc, _, _ = alg_euclid_extins(e, phi)
        if cmmdc == 1:
            break
    
    """
    4. Calculam d a.i e * d == 1 % phi
    """
    _, d, _ = alg_euclid_extins(e, phi)
    if d < 0:
        d += phi

    #print("d:", d)
    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key

def rsa_encrypt(message, public_key):
    n, e = public_key

    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)

if __name__ == "__main__":
    public_key, private_key = rsa_generate_keys(10)

    print("cheie publica:", public_key)
    print("cheie_privata:", private_key)

    mesaj = 65 # A -> ascii
    print("mesaj original:", mesaj)

    cipher = rsa_encrypt(mesaj, public_key)
    print("mesaj criptat:", cipher)

    plain_decrypt = rsa_decrypt(cipher, private_key)
    print("mesaj decriptat:", plain_decrypt)