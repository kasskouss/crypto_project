from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from typing import Tuple
# from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, max_attempts):
    """Find k such that k * BasePoint = (C1, C2) by brute-forcing up to max_attempts."""
    current = (1, 0)  # Start with 0 votes (point at infinity)
    for k in range(0, max_attempts + 1):
        if current[0] == C1 and current[1] == C2:
            return k
        current = add(current[0], current[1], BaseU, BaseV, p)
    raise ValueError(f"Total votes exceed {max_attempts}")

def ECEG_decrypt_tally(R: Tuple[int, int], C: Tuple[int, int], x: int, max_voters: int) -> int:
    """Decrypt for tallying by brute-forcing up to max_voters."""
    S = mult(x, R[0], R[1], p)
    M = sub(C[0], C[1], S[0], S[1], p)
    return bruteECLog(M[0], M[1], max_voters)

def EGencode(message: int) -> Tuple[int, int]:
    if message == 0:
        return (1, 0)  # Point at infinity for 0
    elif message == 1:
        return (BaseU, BaseV)  # Base point for 1
    else:
        raise ValueError("Invalid message (must be 0 or 1)")

def EGdecode(M: Tuple[int, int]) -> int:
    if M == (1, 0):
        return 0
    elif M == (BaseU, BaseV):
        return 1
    else:
        raise ValueError("Decrypted point does not represent 0 or 1")


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
    k = randint(1, ORDER - 1)
    R = mult(k, BaseU, BaseV, p)
    kP = mult(k, P[0], P[1], p)
    C = add(M[0], M[1], kP[0], kP[1], p)
    return R, C


#    Decrypt an EC ElGamal ciphertext.
#    - R: The R component of the ciphertext (tuple of two integers).
#    - C: The C component of the ciphertext (tuple of two integers).
#    - x: The private key of the recipient.
#    - Returns: The decoded message (0 or 1).
def ECEG_decrypt(R: Tuple[int, int], C: Tuple[int, int], x: int) -> int:
    # Compute S = x * R
    S = mult(x, R[0], R[1], p)
    # Compute M = C - S
    M = sub(C[0], C[1], S[0], S[1], p)
    # Directly decode M to 0 or 1
    return EGdecode(M)

# Test Case
if __name__ == "__main__":
# def test():
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

# test()
