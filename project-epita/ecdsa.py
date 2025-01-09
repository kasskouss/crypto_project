from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv
from typing import Tuple

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

# Generate a random nonce k such that 1 <= k < ORDER.S
def ECDSA_generate_nonce() -> int:
    return randint(1, ORDER - 1)

# Generate ECDSA key pair (private key x, public key P).
def ECDSA_generate_keys() -> Tuple[int, Tuple[int, int]]:
    x = randint(1, ORDER - 1)  # Private key
    # Use mult to compute the public key: P = x * BasePoint
    P = mult(x, BaseU, BaseV, p)  # Pass BaseU, BaseV, and p
    return x, P


# Sign a message using the private key x.
# - message: The message to sign (string).
# - x: The private key (integer).
# Returns the signature (r, s).
def ECDSA_sign(message: bytes, x: int) -> Tuple[int, int]:
    # Step 1: Generate a random nonce k
    k = ECDSA_generate_nonce()
    # Step 2: Compute R = k * BasePoint
    R = mult(k, BaseU, BaseV, p)  # Pass BaseU, BaseV, and p
    r = R[0] % ORDER  # r = x-coordinate of R modulo ORDER
    if r == 0:
        return ECDSA_sign(message, x)  # Retry if r == 0
    # Step 3: Compute s = k^(-1) * (H(m) + r * x) mod ORDER
    k_inv = mod_inv(k, ORDER)
    h = H(message)
    s = (k_inv * (h + r * x)) % ORDER
    if s == 0:
        return ECDSA_sign(message, x)  # Retry if s == 0
    return r, s    

# Verify an ECDSA signature.
#    - message: The signed message (string).
#    - r, s: The signature components (integers).
#    - P: The public key (tuple of two integers).
#    Returns True if the signature is valid, False otherwise.
def ECDSA_verify(message: bytes, r: int, s: int, P: Tuple[int, int]) -> bool:
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False  # Invalid signature
    # Step 1: Compute w = s^(-1) mod ORDER
    w = mod_inv(s, ORDER)
    # Step 2: Compute u1 = H(m) * w mod ORDER and u2 = r * w mod ORDER
    h = H(message)
    u1 = (h * w) % ORDER
    u2 = (r * w) % ORDER
    # Step 3: Compute R' = u1 * BasePoint + u2 * P
    u1_x, u1_y = mult(u1, BaseU, BaseV, p)  # Compute u1 * BasePoint
    u2_x, u2_y = mult(u2, P[0], P[1], p)   # Compute u2 * P
    R_prime_x, R_prime_y = add(u1_x, u1_y, u2_x, u2_y, p)  # Add the two points
    if (R_prime_x, R_prime_y) == (1, 0):  # Point at infinity
        return False
    # Step 4: Check if r == x-coordinate of R' mod ORDER
    return r == (R_prime_x % ORDER)


if __name__ == "__main__":
    # TEST
    m = b"A very very important message !"  # Message to sign
    k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6  # Fixed nonce for test
    x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8  # Private key

    # Override the nonce generator for testing
    def ECDSA_generate_nonce():
        return k

    # Generate public key
    P = mult(x, BaseU, BaseV, p)  # Public key

    # Sign the message
    r, s = ECDSA_sign(m, x)
    print(f"Signature:\n r = {hex(r)},\n s = {hex(s)}\n")

    # Verify the signature
    valid = ECDSA_verify(m, r, s, P)
    print(f"Signature valid:\n {valid}")