class Candidates:

    def __init__(self,candidate_list: list[str]):
        self.candidate_number = len(candidate_list)
        self.candidate_list = candidate_list
    

    def add_candidate(self,name: str):
        self.candidate_list.append(name)
        self.candidate_number += 1