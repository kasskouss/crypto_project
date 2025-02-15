from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from typing import Tuple
# from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)


# Generate EC ElGamal key pair.
#     - Returns: private key (x), public key (P = x * BasePoint).
def ECEG_generate_keys() -> Tuple[int, Tuple[int, int]]:
    x = randint(1, ORDER - 1)  # Private key
    P = mult(x, BaseU, BaseV, p)  # Public key: P = x * BasePoint
    return x, P


# Encrypt a message using EC ElGamal.
#     - message: The message to encrypt (0 or 1).
#     - P: The public key of the recipient (tuple of two integers).
#     - Returns: (R, C), where:
#         - R = k * BasePoint
#         - C = M + k * P
def ECEG_encrypt(message: int, P: Tuple[int, int]) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    M = EGencode(message)
    # Step 2: Generate a random ephemeral key k
    k = randint(1, ORDER - 1)
    # Step 3: Compute R = k * BasePoint
    R = mult(k, BaseU, BaseV, p)
    # Step 4: Compute C = M + k * P
    kP = mult(k, P[0], P[1], p)
    C = add(M[0], M[1], kP[0], kP[1], p)
    return R, C


#    Decrypt an EC ElGamal ciphertext.
#    - R: The R component of the ciphertext (tuple of two integers).
#    - C: The C component of the ciphertext (tuple of two integers).
#    - x: The private key of the recipient.
#    - Returns: The decoded message (0 or 1).
def ECEG_decrypt(R: Tuple[int, int], C: Tuple[int, int], x: int) -> int:
    # Step 1: Compute S = x * R
    S = mult(x, R[0], R[1], p)
    # Step 2: Compute M = C - S
    M = sub(C[0], C[1], S[0], S[1], p)
    # Step 3: Use brute force to find the original message
    message = bruteECLog(M[0], M[1], ORDER)
    return message

# Test Case
def test_ecelgamal():
    # Step 1: Generate key pair
    private_key, public_key = ECEG_generate_keys()
    print(f"Private key: {private_key}")
    print(f"Public key: {public_key}")

    # Step 2: Encrypt messages
    messages = [1, 0, 1, 1, 0]
    ciphertexts = []
    for m in messages:
        R, C = ECEG_encrypt(m, public_key)
        ciphertexts.append((R, C))
        print(f"Encrypted {m} -> R: {R}, C: {C}")

    # Step 3: Decrypt messages
    decrypted_messages = []
    for R, C in ciphertexts:
        decrypted_m = ECEG_decrypt(R, C, private_key)
        decrypted_messages.append(decrypted_m)
        print(f"Decrypted R: {R}, C: {C} -> {decrypted_m}")

    # Step 4: Check homomorphic property
    # Compute (r, c) = sum of ciphertexts
    r_sum, c_sum = (1, 0), (1, 0)  # Start with point at infinity
    for R, C in ciphertexts:
        r_sum = add(r_sum[0], r_sum[1], R[0], R[1], p)
        c_sum = add(c_sum[0], c_sum[1], C[0], C[1], p)
    decrypted_sum = ECEG_decrypt(r_sum, c_sum, private_key)
    print(f"Homomorphic decryption result: {decrypted_sum} (Expected: 3)")

# Run test
test_ecelgamal()