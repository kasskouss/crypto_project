# test_main.py
import pytest
from unittest.mock import patch
from main import main

def simulate_inputs(inputs):
    """Helper to simulate sequential user inputs."""
    input_generator = (i for i in inputs)
    return lambda *args, **kwargs: next(input_generator)

@patch('builtins.input', simulate_inputs([
    '1',  # Signature method: DSA
    '1',  # Encryption method: ElGamal
    'voter1', 'voter2', 'voter3', 'voter4', 'voter5',  # Voter names
    'voter6', 'voter7', 'voter8', 'voter9', 'voter10',
    '1', '2', '1', '3', '4',  # Votes for C1, C2, C1, C3, C4
    '5', '1', '2', '3', '4'   # Votes for C5, C1, C2, C3, C4
]))
def test_main_classic_elgamal_dsa(capsys):
    main()
    captured = capsys.readouterr()
    assert "C1: 3 vote(s)" in captured.out
    assert "C2: 2 vote(s)" in captured.out
    assert "C3: 2 vote(s)" in captured.out
    assert "C4: 2 vote(s)" in captured.out
    assert "C5: 1 vote(s)" in captured.out

@patch('builtins.input', simulate_inputs([
    '2',  # Signature method: ECDSA
    '2',  # Encryption method: EC ElGamal
    'voter1', 'voter2', 'voter3', 'voter4', 'voter5',  # Voter names
    'voter6', 'voter7', 'voter8', 'voter9', 'voter10',
    '1', 'invalid', '2', '3', '4',  # Votes: 1, invalid→1, 2, 3, 4
    '5', '1', '2', '3', '4'         # Votes: 5, 1, 2, 3, 4
]))
def test_main_ecelgamal_ecdsa(capsys):
    main()
    captured = capsys.readouterr()
    assert "C1: 3 vote(s)" in captured.out  # 2 valid + 1 invalid→1
    assert "C2: 2 vote(s)" in captured.out
    assert "C3: 2 vote(s)" in captured.out
    assert "C4: 2 vote(s)" in captured.out
    assert "C5: 1 vote(s)" in captured.out

@patch('builtins.input', simulate_inputs([
    '',  # Default to DSA
    '',  # Default to ElGamal
    'v1', 'v2', 'v3', 'v4', 'v5',  # Voter names
    'v6', 'v7', 'v8', 'v9', 'v10',
    '5', 'invalid', '2', '3', '4',  # Votes: 5→1, invalid→1, 2, 3, 4
    '1', '2', '3', '4', '5'         # Votes: 1, 2, 3, 4, 5
]))
def test_main_defaults(capsys):
    main()
    captured = capsys.readouterr()
    assert "C1: 2 vote(s)" in captured.out  # 1 valid + 1 invalid→1
    assert "C2: 2 vote(s)" in captured.out
    assert "C3: 2 vote(s)" in captured.out
    assert "C4: 2 vote(s)" in captured.out
    assert "C5: 2 vote(s)" in captured.out