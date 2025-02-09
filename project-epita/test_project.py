# test_vote_system.py
from vote_system import VoteSystem

# Initialize the voting system
vote_system = VoteSystem(sign_method="dsa", elgammal_method="elgamal")

# Set candidates
candidates = ["Candidate A", "Candidate B", "Candidate C", "Candidate D", "Candidate E"]
vote_system.set_candidates(candidates)

# Add voters
vote_system.add_voter("Voter 1", sign_key_x=12345)
vote_system.add_voter("Voter 2", sign_key_x=67890)

# Simulate voting
voter1 = list(vote_system.voters_map.keys())[0]
voter1.create_vote([1, 0, 0, 0, 0])  # Vote for Candidate A

voter2 = list(vote_system.voters_map.keys())[1]
voter2.create_vote([0, 1, 0, 0, 0])  # Vote for Candidate B

# Collect and tally votes
encrypted_votes = vote_system.collect_votes()
result = vote_system.tally_votes(encrypted_votes)

print("Tally Result:", result)