from enum import Enum
from typing import Tuple, Union
import dsa
import elgamal
import ecdsa
import ecelgamal

class Method(Enum):
    Default = 0
    Elliptique = 1

class VoteEncryption:
    def __init__(self, sign_method: str, elgamal_method: str, eg_pu_key: Union[int, Tuple[int, int]]):
        self.sign_method = Method.Default
        self.elgamal_method = Method.Default
        self.eg_pu_key = eg_pu_key

        if sign_method == "el":
            self.sign_method = Method.Elliptique
        if elgamal_method == "el":
            self.elgamal_method = Method.Elliptique

    def encrypt_votes(self, vote_list: list[int]) -> str:
        msg = ""
        for vote in vote_list:
            if self.elgamal_method == Method.Elliptique:
                R, C = ecelgamal.ECEG_encrypt(vote, self.eg_pu_key)
                msg += f"{R[0]}_{R[1]}_{C[0]}_{C[1]}\n"
            else:
                c1, c2 = elgamal.EGA_encrypt(vote, self.eg_pu_key)
                msg += f"{c1}_{c2}\n"
        return msg

    def sign_message(self, msg: str, sign_key_x: int) -> Tuple[int, int]:
        if self.sign_method == Method.Elliptique:
            return ecdsa.ECDSA_sign(msg.encode(), sign_key_x)
        else:
            return dsa.DSA_sign(msg.encode(), sign_key_x)

    def create_encrypted_msg(self, vote_list: list[int], sign_key_x: int) -> dict:
        encrypted_vote = self.encrypt_votes(vote_list)
        signature = self.sign_message(encrypted_vote, sign_key_x)
        return {"msg": encrypted_vote, "signature": signature}