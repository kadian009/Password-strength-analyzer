# Password-strength-analyzer

A lightweight, terminal-based Python tool designed to evaluate password security using modern cryptographic principles. This tool checks passwords for length, character complexity, structural patterns, and history reuse while calculating true information entropy.

Features

Strength & Complexity Check: Evaluates passwords based on length, casing, numbers, and special characters.

Entropy Calculation: Computes the mathematical randomness (in bits) of a password using Shannon Entropy.

Pattern Recognition: Flags obvious, easily hackable sequential or repeating character patterns.

History Reuse Prevention: Integrates a local SQLite database to track previously used passwords and block their reuse.

Secure Suggestions: Generates cryptographically secure alternative passwords using Python's secrets module.

=========================================
      PASSWORD STRENGTH ANALYZER         
=========================================

Enter a password to test (or type 'exit' to quit): Password123!

--- ANALYSIS RESULTS ---
Overall Rating : REUSED (UNSAFE)

Password Length: 12 characters

Visual Entropy : 78.61 bits

Suggestions to Improve:
• Rejected: You have used this password before! Reuse is prohibited.

--- SECURE ALTERNATIVE ---
Suggested Alternative: k#9X_mP2vF!aLq9}


Made by Yuvraj 
