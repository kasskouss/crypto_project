import dsa
import elgamal
from voters import Voter
from vote_encryption import VoteEncryption

class  VoteSystem:

    def __init__(self,sign_method:str,elgammal_method:str):
        self.eg_x, self.eg_y = elgamal.EG_generate_keys()
        self.vote_ecnryption: VoteEncryption = VoteEncryption(sign_method,elgammal_method,self.eg_y) 
        self.voters_map: dict[Voter,int] =  None

    def add_voter(self,name:str,)

        



    #List[Voters]
    
    #List[Candidate]