# Rapport sur le système de vote électronique

## 0. Membres du groupe

Teo HALLE et Brian CHALLITA

## 1. Introduction

Ce projet vise à mettre en œuvre un système de vote électronique simple en utilisant divers mécanismes cryptographiques. Les principaux objectifs sont d'assurer la confidentialité des votes, l'éligibilité des électeurs (chaque électeur signe son bulletin de vote) et la possibilité d'effectuer un décompte homomorphe des votes. Le projet a été développé dans le cadre d'un cours de cryptographie appliquée.

## 2. Architecture générale et choix cryptographiques

Le système est conçu pour prendre en charge deux familles d'algorithmes en parallèle :

### Signature :
- **DSA** (avec les paramètres du groupe MODP 24) pour la version "par défaut".
- **ECDSA** (basé sur Curve25519 et les fonctions d'addition/doublement de RFC 7748) pour la version elliptique.
- La signature garantit l'éligibilité des électeurs.

### Chiffrement :
- **ElGamal classique** (multiplicatif) sur le groupe multiplicatif des entiers modulo un grand nombre (groupe MODP 24).
- **EC ElGamal** sur la courbe Curve25519, où le message (0 ou 1) est mappé à un point (le point à l'infini ou le point de base).
- Ces schémas offrent une propriété homomorphe qui permet d'agréger les votes sans les décrypter individuellement.

## 3. Détails des modules

### a. `algebra.py`
Ce module fournit des fonctions d'arithmétique modulaire essentielles pour les algorithmes cryptographiques :
- Conversion d'entier en octets.
- Calcul de l'inverse modulaire (`mod_inv`).
- Calcul de la racine carrée modulaire (`mod_sqrt`).
- Ces fonctions sont utilisées par DSA, ElGamal et d'autres modules pour effectuer des opérations sur de grands entiers.

### b. `rfc7748.py`
Ce module implémente des fonctions pour effectuer des calculs sur la courbe Curve25519, telles que :
- L'addition et le doublement de points.
- La multiplication scalaire (non optimisée pour l'ECDSA).
- Des fonctions d'encodage/décodage.
- Le calcul de la coordonnée `v` à partir de `u`.
- Ces fonctions servent de base aux implémentations de l'ECDSA et de l'EC ElGamal.

### c. Modules de signature

#### `dsa.py` :
- Implémente la génération de clés, la signature et la vérification en utilisant DSA basé sur les paramètres du groupe MODP 24 et SHA256.
- La fonction `DSA_sign` calcule la paire `(r, s)`, et `DSA_verify` valide la signature.

#### `ecdsa.py` :
- Implémente l'ECDSA en utilisant les fonctions de courbe (via `rfc7748.py`), SHA256 et les calculs d'inverse modulaire.
- La clé publique est obtenue par multiplication scalaire sur le point de base, et la signature est calculée de manière similaire à DSA, mais adaptée à l'arithmétique elliptique.

### d. Modules de chiffrement

#### `elgamal.py` :
- Implémente le chiffrement ElGamal classique (versions multiplicative et additive pour le vote).
- Le chiffrement utilise un exposant aléatoire `k`, et le déchiffrement utilise l'inverse modulaire et une recherche par force brute (`bruteLog`) pour récupérer le message dans la version additive.

#### `ecelgamal.py` :
- Implémente le chiffrement ElGamal sur les courbes elliptiques (Curve25519).
- Le message `0` est encodé comme le point à l'infini `(1, 0)`, et `1` est encodé comme le point de base.
- L'addition de points fournit une propriété homomorphe native.
- Le déchiffrement consiste à soustraire un point (en calculant `S = x·R`) et à effectuer une recherche par force brute (`bruteECLog`) pour récupérer le total des votes.

### e. `candidate.py`
- Contient une classe simple qui gère la liste des candidats et le nombre total de candidats.
- Chaque vote est exprimé comme une liste de `0` et un unique `1` indiquant le choix (par exemple, `[1, 0, 0, 0, 0]` pour le candidat C1).

### f. `voters.py`
- Définit la classe `Voter`, qui représente un électeur.
- Chaque électeur possède :
  - Un nom.
  - Une référence à la liste des candidats.
  - Une paire de clés de signature (privée et publique).
  - Une méthode `create_vote` qui s'assure que l'électeur sélectionne exactement un candidat, évitant ainsi plusieurs sélections ou aucune sélection.

### g. `vote_encryption.py`
- Regroupe les opérations de chiffrement et de signature pour un bulletin de vote.
- La classe `VoteEncryption` :
  - Sélectionne les méthodes de signature (DSA ou ECDSA) et de chiffrement (ElGamal classique ou EC ElGamal) en fonction des paramètres.
  - Chiffre chaque élément de la liste de votes en utilisant `encrypt_votes`.
  - Signe le message chiffré avec la clé privée de l'électeur en utilisant `sign_message`.
  - Renvoie un dictionnaire contenant le message chiffré et sa signature, garantissant à la fois la confidentialité et l'éligibilité.

### h. `vote_system.py`
- Le cœur du système de vote.
- La classe `VoteSystem` :
  - Initialise la liste des candidats, génère les clés de chiffrement et initialise un objet `VoteEncryption`.
  - Gère l'inscription des électeurs dans une table de hachage (`voters_map`).
  - Permet aux électeurs de soumettre leurs bulletins via `cast_vote`, qui valide, chiffre et signe le vote avant de le stocker.
  - Agrège les bulletins à l'aide de `tally_votes`. Pour chaque candidat, les composantes du texte chiffré sont accumulées (par multiplication pour l'ElGamal classique ou par addition pour l'EC ElGamal). Le résultat agrégé est déchiffré pour obtenir le total des votes par candidat, en tirant parti de la propriété homomorphe.

### i. `main.py`
- L'interface utilisateur (console) :
  - Invite l'utilisateur à choisir les méthodes de signature et de chiffrement.
  - Crée une liste de candidats (C1 à C5) et enregistre 10 électeurs en leur demandant leurs noms.
  - Chaque électeur sélectionne un candidat (le vote est transformé en une liste de `0` et `1`).
  - Après le vote, `tally_votes` est appelé pour afficher les résultats finaux.
  - Ordonne l'ensemble du processus de vote.

## 4. Processus de vote et propriétés homomorphes

Le système assure la confidentialité des votes en chiffrant individuellement chaque composante du bulletin. Chaque électeur génère un bulletin contenant cinq messages chiffrés (un par candidat). Grâce à la propriété homomorphe :

- Pour l'ElGamal classique, la multiplication des composantes chiffrées correspond à la multiplication des messages. Dans la version additive, une recherche par force brute est utilisée pour récupérer la somme des votes.
- Pour l'EC ElGamal, l'addition de points (des composantes du texte chiffré) permet de récupérer la somme des votes après déchiffrement (via une recherche par force brute).

De plus, chaque bulletin est signé par l'électeur (via DSA ou ECDSA) pour s'assurer qu'il provient d'un électeur enregistré, garantissant ainsi l'éligibilité.

## 5. Explication des tests

Le module `test_project.py` utilise le framework `pytest` et des simulations (mocking) pour simuler l'entrée utilisateur. Points clés :

### Simulation des entrées :
- La fonction `simulate_inputs` crée un générateur qui fournit des réponses séquentielles aux appels de `input()`. Cela simule le comportement de l'utilisateur dans divers scénarios, tels que le choix de la méthode de signature, la méthode de chiffrement, l'inscription des électeurs et le vote.

### Scénarios de test :
1. **ElGamal classique et DSA** :
   - Simule 10 électeurs et des votes pour différents candidats.
   - Vérifie que le résultat final affiche le nombre de votes attendu par candidat (par exemple, "C1 : 3 vote(s)", "C2 : 2 vote(s)", etc.).

2. **EC ElGamal et ECDSA** :
   - Simule des votes, y compris une entrée invalide (par défaut le candidat 1).
   - Vérifie que la répartition finale des votes correspond aux attentes, même avec des entrées invalides.

3. **Valeurs par défaut** :
   - Lorsque l'utilisateur ne fournit aucune entrée, le système utilise par défaut DSA pour la signature et ElGamal pour le chiffrement.
   - Vérifie que les résultats finaux sont cohérents.

Ces tests automatisés garantissent que le système fonctionne correctement pour les deux combinaisons d'algorithmes et que le processus de vote, l'inscription des électeurs, la génération des bulletins et le décompte homomorphe se déroulent comme prévu.

## 6. Conclusion

Le système de vote électronique implémente une chaîne complète, de l'inscription des électeurs à la publication des résultats, en sécurisant les bulletins par le biais du chiffrement et de la signature. Chaque module est conçu pour être interchangeable (DSA vs ECDSA, ElGamal vs EC ElGamal), offrant ainsi une flexibilité dans les mécanismes cryptographiques.

Les tests automatisés, simulant divers scénarios utilisateur, confirment que le système répond aux exigences de confidentialité, d'éligibilité et de décompte homomorphe telles qu'énoncées dans les spécifications du projet.

Ce rapport fournit un aperçu complet de l'implémentation en Python du système de vote et de la stratégie de test adoptée.
