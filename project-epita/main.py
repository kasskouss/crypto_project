from candidate import Candidates
from voters import Voter
from vote_system import VoteSystem
import random

def main():
    print("Welcome to the Electronic Voting System\n")
    
    # Setup candidates (five candidates: C1,...,C5)
    candidate_names = ["C1", "C2", "C3", "C4", "C5"]
    candidates = Candidates(candidate_names)
    
    # Choose signature and encryption methods.
    print("Select Signature method:")
    print("1. DSA")
    print("2. ECDSA")
    sig_choice = input("Enter choice (default=1): ")
    sig_method = "el" if sig_choice == "2" else "default"
    
    print("\nSelect Encryption method:")
    print("1. ElGamal")
    print("2. EC ElGamal")
    enc_choice = input("Enter choice (default=1): ")
    enc_method = "el" if enc_choice == "2" else "default"
    
    # Initialize the voting system.
    vote_system = VoteSystem(candidates, sig_method, enc_method)  # Initialize the VoteSystem object
    
    # Register voters.
    num_voters = 10
    print(f"\nRegistering {num_voters} voters.")
    for i in range(1, num_voters + 1):
        name = input(f"Enter name for voter {i}: ").strip()
        if sig_method == "el":
            from ecdsa import ECDSA_generate_keys
            x, y = ECDSA_generate_keys()
        else:
            from dsa import DSA_generate_keys
            x, y = DSA_generate_keys()
        voter = Voter(name, candidates, x, y)
        vote_system.add_voter(voter)  # Add the voter to the vote_system
    
    # Voting phase.
    print("\n--- Voting Phase ---")
    for voter_name in vote_system.voters_map:
        print(f"\nVoter: {voter_name}")
        print("Candidates:")
        for idx, cand in enumerate(candidate_names, start=1):
            print(f"  {idx}. {cand}")
        try:
            choice = int(input("Enter the candidate number you wish to vote for: "))
        except ValueError:
            print("Invalid input, defaulting to candidate 1.")
            choice = 1
        if choice < 1 or choice > len(candidate_names):
            print("Invalid candidate number, defaulting to candidate 1.")
            choice = 1
        # Build the vote list: a 1 for the chosen candidate and 0 for all others.
        vote_list = [0] * len(candidate_names)
        vote_list[choice - 1] = 1
        vote_system.cast_vote(voter_name, vote_list)
    
    # Tally votes.
    print("\nTallying votes...\n")
    results = vote_system.tally_votes()
    print("Election Results:")
    for candidate, count in results.items():
        print(f"  {candidate}: {count} vote(s)")

if __name__ == "__main__":
    main()