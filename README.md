# Password-strength-analyzer

A lightweight, terminal-based Python tool designed to evaluate password security using modern cryptographic principles. This tool checks passwords for length, character complexity, structural patterns, and history reuse while calculating true information entropy.

Features

Strength & Complexity Check: Evaluates passwords based on length, casing, numbers, and special characters.

Entropy Calculation: Computes the mathematical randomness (in bits) of a password using Shannon Entropy.

Pattern Recognition: Flags obvious, easily hackable sequential or repeating character patterns.

History Reuse Prevention: Integrates a local SQLite database to track previously used passwords and block their reuse.

Secure Suggestions: Generates cryptographically secure alternative passwords using Python's secrets module.

Made by Yuvraj 
