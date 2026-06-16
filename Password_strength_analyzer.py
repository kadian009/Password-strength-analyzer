import math 
import re
import secrets
import sqlite3
import string


class PasswordAnalyzer:

    def __init__(self, db_name="password_history.db"):
        """Initializes the analyzer and sets up a local SQLite database for history."""
        self.db_name = db_name
        self._init_db()

    def _init_db(self):
        """Creates the database table if it doesn't exist."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT NOT NULL UNIQUE
                )
            """
            )
            conn.commit()

    def _mock_hash(self, password):
        """Simulates a secure hash function for database lookup.

        In a real app, use bcrypt or argon2. Do NOT use SHA256 directly for
        passwords.
        """
        import hashlib

        # Simple salt simulation for demonstration
        return hashlib.sha256(password.encode()).hexdigest()

    def check_history(self, password):
        """Checks if the password exists in the 'old passwords' database."""
        target_hash = self._mock_hash(password)
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM password_history WHERE password_hash = ?",
                (target_hash,),
            )
            return cursor.fetchone() is not None

    def add_to_history(self, password):
        """Saves a password hash to the database history."""
        target_hash = self._mock_hash(password)
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO password_history (password_hash) VALUES (?)",
                    (target_hash,),
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Already exists

    def calculate_entropy(self, password):
        """Calculates information entropy to measure password strength in bits."""
        if not password:
            return 0

        pool_size = 0
        if any(c in string.ascii_lowercase for c in password):
            pool_size += 26
        if any(c in string.ascii_uppercase for c in password):
            pool_size += 26
        if any(c in string.digits for c in password):
            pool_size += 10
        if any(c in string.punctuation for c in password):
            pool_size += len(string.punctuation)
        # For any other characters (like spaces or emojis)
        if any(
            c not in (string.ascii_letters + string.digits + string.punctuation)
            for c in password
        ):
            pool_size += 20

        # Entropy formula: E = L * log2(R)
        entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
        return round(entropy, 2)

    def analyze(self, password):
        """Evaluates length, complexity, uniqueness, and history."""
        metrics = {
            "length": len(password),
            "has_upper": bool(re.search(r"[A-Z]", password)),
            "has_lower": bool(re.search(r"[a-z]", password)),
            "has_digit": bool(re.search(r"\d", password)),
            "has_special": bool(re.search(r"[" + re.escape(string.punctuation) + r"]", password)),
            "is_repeated_pattern": bool(re.search(r"(.+)\1{2,}", password)),
            "in_history": self.check_history(password),
            "entropy": self.calculate_entropy(password),
        }

        # Determine Score and Feedback
        score = 0
        feedback = []

        if metrics["length"] >= 12:
            score += 2
        elif metrics["length"] >= 8:
            score += 1
        else:
            feedback.append("• Critical: Password is too short (Minimum 12 characters recommended).")

        complexity_count = sum(
            [
                metrics["has_upper"],
                metrics["has_lower"],
                metrics["has_digit"],
                metrics["has_special"],
            ]
        )
        score += complexity_count

        if complexity_count < 4:
            feedback.append("• Fix: Mix uppercase, lowercase, numbers, and symbols.")
        if metrics["is_repeated_pattern"]:
            score -= 1
            feedback.append("• Warning: Avoid repeating patterns (e.g., 'abcabc' or '1111').")
        if metrics["in_history"]:
            score = 0
            feedback.append("• Rejected: You have used this password before! Reuse is prohibited.")

        # Map score to a rating
        if metrics["in_history"]:
            rating = "REUSED (UNSAFE)"
        elif score <= 2:
            rating = "Very Weak ❌"
        elif score <= 4:
            rating = "Weak ⚠️"
        elif score <= 5:
            rating = "Moderate 🟡"
        else:
            rating = "Strong ✅"

        return rating, metrics, feedback

    @staticmethod
    def generate_alternative(length=16):
        """Generates a cryptographically secure alternative password."""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            # Ensure it meets basic criteria
            if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)
            ):
                return password


# --- Interactive UI/CLI Execution ---
if __name__ == "__main__":
    analyzer = PasswordAnalyzer()

    print("=========================================")
    print("      PASSWORD STRENGTH ANALYZER         ")
    print("=========================================\n")

    # Seed the mock database with a couple of "old" passwords for demonstration
    analyzer.add_to_history("Password123!")
    analyzer.add_to_history("LetMeIn2025$")

    while True:
        user_input = input("Enter a password to test (or type 'exit' to quit): ").strip()
        if user_input.lower() == "exit":
            print("Stay safe! Goodbye.")
            break

        if not user_input:
            print("Password cannot be empty.\n")
            continue

        rating, stats, warnings = analyzer.analyze(user_input)

        print("\n--- ANALYSIS RESULTS ---")
        print(f"Overall Rating : {rating}")
        print(f"Password Length: {stats['length']} characters")
        print(f"Visual Entropy : {stats['entropy']} bits")

        if warnings:
            print("\nSuggestions to Improve:")
            for note in warnings:
                print(note)
        else:
            print("\n✨ Excellent! Your password meets modern safety requirements.")

        # Suggest an alternative anyway, or if theirs is weak
        print("\n--- SECURE ALTERNATIVE ---")
        print(f"Suggested Alternative: {analyzer.generate_alternative()}")

        # Option to save to database if it wasn't already a duplicate
        if not stats["in_history"] and rating not in ["Very Weak ❌", "Weak ⚠️"]:
            save_opt = input("\nWould you like to 'save' this to history? (y/n): ").lower()
            if save_opt == "y":
                analyzer.add_to_history(user_input)
                print("Password successfully committed to history database.")

        print("\n" + "=" * 41 + "\n")
