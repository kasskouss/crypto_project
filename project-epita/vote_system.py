# vote_system.py
from candidate import Candidates
from voters import Voter
from vote_encryption import VoteEncryption
import dsa
import elgamal
import ecdsa
import ecelgamal
from rfc7748 import add as ec_add  # Import ec_add for elliptic curve addition
from ecelgamal import p as ec_p, ECEG_decrypt  # Import EC ElGamal parameters
from ecelgamal import ECEG_decrypt_tally


class VoteSystem:
    def __init__(self, candidates: Candidates, sign_method: str, elgamal_method: str):
        self.candidates = candidates
        self.sign_method = sign_method
        self.elgamal_method = elgamal_method
        self.voters_map = {}
        self.ballots = []

        # Generate keys based on the selected encryption method
        if elgamal_method == "el":
            from ecelgamal import ECEG_generate_keys
            self.eg_x, self.eg_pu = ECEG_generate_keys()
            self.eg_pu_key = self.eg_pu
        else:
            from elgamal import EG_generate_keys
            self.eg_x, self.eg_y = EG_generate_keys()
            self.eg_pu_key = self.eg_y

        # Initialize VoteEncryption
        self.vote_encryption = VoteEncryption(sign_method, elgamal_method, self.eg_pu_key)

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
        num_candidates = self.candidates.candidate_number
        # Initialize aggregated ciphertexts based on encryption method
        if self.elgamal_method == "el":
            aggregated = [((1, 0), (1, 0)) for _ in range(num_candidates)]
        else:
            aggregated = [(1, 1) for _ in range(num_candidates)]
        

        # Aggregate votes
        for ballot in self.ballots:
            encrypted_lines = ballot["ballot"]["msg"].strip().split("\n")
            for i, line in enumerate(encrypted_lines):
                if self.elgamal_method == "el":
                    parts = list(map(int, line.split("_")))
                    R, C = ((parts[0], parts[1]), (parts[2], parts[3]))
                    agg_R, agg_C = aggregated[i]
                    aggregated[i] = (
                        ec_add(agg_R[0], agg_R[1], R[0], R[1], ec_p),
                        ec_add(agg_C[0], agg_C[1], C[0], C[1], ec_p)
                    )
                else:
                    # Classic ElGamal: split into c1 and c2
                    c1, c2 = map(int, line.split("_"))
                    aggregated[i] = (
                        (aggregated[i][0] * c1) % elgamal.PARAM_P,
                        (aggregated[i][1] * c2) % elgamal.PARAM_P
                    )

        # Decrypt totals
        results = {}
        for i in range(num_candidates):
            if self.elgamal_method == "el":
                R_total, C_total = aggregated[i]
                total = ECEG_decrypt_tally(R_total, C_total, self.eg_x, 10)  # 10 voters max
            else:
                c1_total, c2_total = aggregated[i]
                decrypted = elgamal.EG_decrypt(c1_total, c2_total, self.eg_x)
                total = elgamal.bruteLog(elgamal.PARAM_G, decrypted, elgamal.PARAM_P)
            results[self.candidates.candidate_list[i]] = total

        return results