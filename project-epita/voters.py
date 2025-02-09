from candidate import Candidates

class Voter:

    def __init__(self,name:str,candidates: Candidates,sign_key_x : int):
        self.name : str= name
        self.candidates:Candidates = candidates
        self.votes: list[int] = None
        self.sign_key_x = sign_key_x
    
    def create_vote(self,voting_list: list[int]) -> str:
        if len(voting_list) != self.candidates.candidate_number:
            raise Exception("Chose a correct number of people to vote to!")
        if voting_list.count == 0:
            raise Exception(f"{self.name} need to vote to at least one candidate")
        
        self.votes = voting_list


    def send_vote(self,voting_list: list[int]) -> str:
        self.create_vote(voting_list) 
        return self.votes
        
        