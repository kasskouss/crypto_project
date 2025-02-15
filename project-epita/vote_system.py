import dsa
import elgamal
from voters import Voter
from vote_encryption import VoteEncryption
from candidate import Candidates

class VoteSystem:
    def __init__(self, candidates: Candidates, sign_method: str, elgammal_method: str):
        self.eg_x, self.eg_y = elgamal.EG_generate_keys()
        self.vote_encryption = VoteEncryption(sign_method, elgammal_method, self.eg_y)
        self.candidates = candidates
        self.voters_map = {}    # maps voter names to Voter objects
        self.ballots = []       # list of ballots (each is a dict)

    def add_voter(self, voter: Voter):
        if voter.name in self.voters_map:
            raise Exception("Voter already exists!")
        self.voters_map[voter.name] = voter

    def cast_vote(self, voter_name: str, vote_list: list[int]):
        if voter_name not in self.voters_map:
            raise Exception("Voter not registered!")
        voter = self.voters_map[voter_name]
        voter.create_vote(vote_list)
        ballot = self.vote_encryption.create_encrypted_msg(vote_list, voter.sign_key_x)
        self.ballots.append({"voter": voter_name, "ballot": ballot})
        print(f"Ballot from {voter_name} recorded.")

    def tally_votes(self) -> dict:
        # For each candidate, aggregate the ciphertexts from all ballots.
        num_candidates = self.candidates.candidate_number
        aggregated_ciphertexts = [(1, 1) for _ in range(num_candidates)]
        for ballot_entry in self.ballots:
            ballot = ballot_entry["ballot"]
            # Each ballot's "msg" contains 5 lines, one per candidate.
            encrypted_lines = ballot["msg"].strip().split("\n")
            if len(encrypted_lines) != num_candidates:
                raise Exception("Ballot has an incorrect number of encrypted votes.")
            for i in range(num_candidates):
                c1_str, c2_str = encrypted_lines[i].split("_")
                r_i = int(c1_str)
                c_i = int(c2_str)
                agg_r, agg_c = aggregated_ciphertexts[i]
                agg_r = (agg_r * r_i) % elgamal.PARAM_P
                agg_c = (agg_c * c_i) % elgamal.PARAM_P
                aggregated_ciphertexts[i] = (agg_r, agg_c)
        results = {}
        for i in range(num_candidates):
            agg_r, agg_c = aggregated_ciphertexts[i]
            decrypted = elgamal.EG_decrypt(agg_r, agg_c, self.eg_x)
            total_votes = elgamal.bruteLog(elgamal.PARAM_G, decrypted, elgamal.PARAM_P)
            candidate_name = self.candidates.candidate_list[i]
            results[candidate_name] = total_votes
        return results
