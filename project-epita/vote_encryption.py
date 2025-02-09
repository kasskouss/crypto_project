import dsa
import elgamal
from enum import Enum



class method(Enum):
    Default = 0
    Elliptique = 1

class VoteEncryption:
    
    def __init__(self,sign_method: str, elgammal_method: str,eg_pu_key: int):
        self.sign_method: method = method.Default
        self.elgammal_method: method = method.Default
        self.eg_pu_key: int = eg_pu_key

        if sign_method == "el":
            self.sign_method = method.Elliptique
        if elgammal_method == "el":
            self.elgammal_method = method.Elliptique


    # We need a method to encrypt and sign the message

    # def encrypt_votes(self,vote_list: list[int])->str:
    #     msg = ""
    #     for vote in vote_list:
    #         c1,c2 = elgamal.EGA_encrypt(vote,self.eg_pu_key)
    #         msg+=str(c1)+"_"+str(c2)
    #         msg+"\n"
    #     ###returns this :
    #     ###
    #     ### 3123123_12321312
    #     ### 3123123_123213213
    #     ### ... 
    #     ### ... 
    #     ###
    #     return msg

    def encrypt_votes(self, vote_list: list[int]) -> str:
        encrypted_votes = []
        for vote in vote_list:
            c1, c2 = elgamal.EGA_encrypt(vote, self.eg_pu_key)
            encrypted_votes.append(f"{c1}_{c2}")
        # Join all encrypted votes with a delimiter (e.g., '|')
        return "|".join(encrypted_votes)

    def sign_message(self,msg:str,sign_key_x:int):
        r,s = dsa.DSA_sign(msg,sign_key_x)
        return r,s
    
    
    def create_encrypted_msg(self,vote_list: list[int], sign_key_x:int) -> dict:
        """
        return: msg, r,s
        """
        encrypted_vote = self.encrypt_votes(vote_list)
        return {"msg":encrypted_vote,"signature":self.sign_message(encrypted_vote,sign_key_x)}


        

