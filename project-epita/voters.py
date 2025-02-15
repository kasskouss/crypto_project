from candidate import Candidates

# class Voter:

#     def __init__(self,name:str,candidates: Candidates,sign_key_x : int):
#         self.name : str= name
#         self.candidates:Candidates = candidates
#         self.votes: list[int] = None
#         self.sign_key_x = sign_key_x
    
#     def create_vote(self,voting_list: list[int]) -> str:
#         if len(voting_list != self.candidates.candidate_number):
#             raise Exception("Chose a correct number of people to vote to!")
#         if voting_list.count == 0:
#             raise Exception(f"{self.name} need to vote to at least one candidate")
        
#         self.votes = voting_list


#     def send_vote(self,voting_list: list[int]) -> str:
#         self.create_vote(voting_list) 
#         return self.votes
        
        
from candidate import Candidates

class Voter:
    def __init__(self, name: str, candidates: Candidates, sign_key_x: int, sign_key_y: int):
        """
        sign_key_x: private signing key (dummy value for DSA)
        sign_key_y: public signing key (dummy value for DSA)
        """
        self.name = name
        self.candidates = candidates
        self.sign_key_x = sign_key_x
        self.sign_key_y = sign_key_y
        self.votes = None

    def create_vote(self, voting_list: list[int]) -> list[int]:
        if len(voting_list) != self.candidates.candidate_number:
            raise Exception("Choose a correct number of candidates!")
        if voting_list.count(1) != 1:
            raise Exception(f"{self.name} must vote for exactly one candidate!")
        self.votes = voting_list
        return self.votes
