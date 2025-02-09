import dsa
import elgamal
from voters import Voter
from candidate import Candidates
from vote_encryption import VoteEncryption

class  VoteSystem:

    def __init__(self,sign_method:str,elgammal_method:str):
        self.eg_x, self.eg_y = elgamal.EG_generate_keys()
        self.vote_encryption: VoteEncryption = VoteEncryption(sign_method,elgammal_method,self.eg_y) 
        self.voters_map: dict[Voter, int] = {}
        self.candidates: Candidates = None

    def add_voter(self, name: str, sign_key_x: int):
        voter = Voter(name, self.candidates, sign_key_x)
        self.voters_map[voter] = sign_key_x

    def set_candidates(self, candidate_list: list[str]):
        self.candidates = Candidates(candidate_list)

    def collect_votes(self):
        # Collect and process votes from all voters
        encrypted_votes = []
        for voter in self.voters_map:
            if voter.votes:
                encrypted_vote = self.vote_encryption.create_encrypted_msg(voter.votes, voter.sign_key_x)
                encrypted_votes.append(encrypted_vote)
        return encrypted_votes

    def tally_votes(self, encrypted_votes):
        # Initialize totals for r and c
        r_total = 1
        c_total = 1

        for vote in encrypted_votes:
            # Split the message into individual encrypted votes using the delimiter (e.g., '|')
            encrypted_vote_list = vote['msg'].split('|')
            
            for encrypted_vote in encrypted_vote_list:
                # Split each encrypted vote into r and c
                r, c = encrypted_vote.split('_')
                r_total *= int(r)
                c_total *= int(c)
        
        # Decrypt the total
        decrypted_total = elgamal.EG_decrypt(r_total, c_total, self.eg_x)
        return decrypted_total

    #List[Voters]
    
    #List[Candidate]