from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


### call bruteLog with p = PARAM_P and g = PARAM_G

def bruteLog(g, c, p):
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

def EG_generate_keys(p:hex = PARAM_P, g: hex =PARAM_G) -> tuple[int,int]:
    """
    ElGamal Key Generation (Multiplicative version)
    
    Returns:
        x (int): secret key (1 <= x <= p-2)
        y (int): public key = g^x mod p
    """
    # Private key
    x = randint(1, p-2)
    # Public key
    y = pow(g, x, p)
    return x, y



## multiplicative version
def EGM_encrypt(M: int, y: int, p=PARAM_P, g=PARAM_G)->tuple[int,int]: 
    """
    Multiplicative ElGamal Encryption
    Inputs:
        M (int): message, in [1, p-1]
        y (int): the recipient's public key
    Returns:
        (c1, c2): the ciphertext (each in [1, p-1])
    """
    # Generate an ephemeral key k
    k = randint(1, p-2)
    
    # c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # c2 = M * (y^k mod p) mod p
    s = pow(y, k, p)  # shared secret
    c2 = (M * s) % p
    
    return c1, c2


## additive version
def EGA_encrypt(M: int, y: int, p=PARAM_P, g=PARAM_G) -> tuple[int,int]:
    """
    (Optional) Additive version of ElGamal Encryption
    If you want an additive homomorphic scheme, you'd define a different group operation.
    We'll just put a placeholder to illustrate.
    """
    # For an additive version, you'd have a different group law, but let's keep
    # the same pattern. This is just a placeholder.
    
    k = randint(1, p-2)
    c1 = pow(g, k, p)  # or "g*k mod p" for an additive group
    s = pow(y, k, p)
    # c2 = (M + s) mod p for an additive scheme, for instance
    c2 = (g^M+ s) % p
    return c1, c2


def EG_decrypt(c1: int, c2: int, x: int, p=PARAM_P) -> int:
    """
    ElGamal Decryption (Multiplicative version)
    Inputs:
        c1, c2: ciphertext
        x (int): private key
    Returns:
        M (int): plaintext in [1, p-1]
    """
    # s = c1^x mod p
    s = pow(c1, x, p)
    
    # M = c2 * s^-1 mod p
    s_inv = mod_inv(s, p)
    M = (c2 * s_inv) % p
    return M



if __name__ == "__main__":
    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

    x,y = EG_generate_keys()

    r1,c1 = EGM_encrypt(m1,y)
    r2,c2 = EGM_encrypt(m2,y)

    r3,c3 = r1*r2, c1*c2
    
    m3 = EG_decrypt(r3,c3,x)
    print(m3)
    print(m1*m2)