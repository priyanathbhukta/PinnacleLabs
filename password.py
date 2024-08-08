#-------------------------------------------------------------------------------
# Name:        Password Analyzer
# Purpose:
#
# Author:      Priyanath
#
# Created:     07/08/2024
# Copyright:   (c) Priyanath 2024
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import re
import math
import secrets
import string

def password_analyzer(password):
    """Analyzes a password's strength and provides feedback.

    Args:
        password (str): The password to analyze.

    Returns:
        tuple: A tuple containing the password score (float) and feedback list (list).
    """

    score = 0
    feedback = []

    # Minimum length check
    if len(password) < 8:
        feedback.append("Password is too short. Minimum length is 8 characters.")
        return 0, feedback

    # Character complexity checks
    uppercase_check = re.search("[A-Z]", password)
    lowercase_check = re.search("[a-z]", password)
    number_check = re.search("[0-9]", password)
    special_check = re.search("[^a-zA-Z0-9]", password)

    # Provide specific feedback and score deductions for missing complexity
    if not uppercase_check:
        feedback.append("Missing uppercase letter.")
        score -= 0.1
    else:
        score += 0.2

    if not lowercase_check:
        feedback.append("Missing lowercase letter.")
        score -= 0.1
    else:
        score += 0.2

    if not number_check:
        feedback.append("Missing number.")
        score -= 0.1
    else:
        score += 0.2

    if not special_check:
        feedback.append("Missing special character.")
        score -= 0.1
    else:
        score += 0.2

    # Common password check
    common_passwords = ["password123", "qwerty", "letmein"]
    if password.lower() in common_passwords:
        feedback.append("Password is too common. Choose a unique password.")
        score -= 0.2

    # Weak password checks (dictionary words, sequential characters)
    names = ["john", "jane", "bob", "alice"]
    for name in names:
        if name in password.lower():
            feedback.append(f"Password contains a common name ({name}). Avoid using names.")
            score -= 0.1

    sequential_chars = ["abc", "def", "ghi", "jkl", "mno", "pqr", "stu", "vwx", "yz"]
    for chars in sequential_chars:
        if chars in password.lower():
            feedback.append(f"Password contains sequential characters ({chars}). Avoid sequences.")
            score -= 0.1

    # Entropy check
    entropy = len(set(password)) * math.log(len(set(password)), 2)
    if entropy < 30:
        feedback.append("Password is too predictable. Use a more random password.")
        score -= 0.1

    # Ensure score doesn't exceed 0.92
    score = min(score, 0.92)

    return score, feedback

def suggest_stronger_passwords(min_score=0.7):
    """Suggests stronger passwords based on a minimum score threshold.

    Args:
        min_score (float, optional): The minimum score for stronger suggestions. Defaults to 0.7.

    Returns:
        list: A list containing 3 strong password suggestions.
    """

    suggestions = []
    for _ in range(3):
        suggestion = ""

        # Include all character types and shuffle for randomness
        suggestion += secrets.choice(string.ascii_uppercase)
        suggestion += secrets.choice(string.ascii_lowercase)
        suggestion += secrets.choice(string.digits)
        suggestion += secrets.choice(string.punctuation)

        for _ in range(max(7, int((1 - min_score) * 10))):  # Adjust length based on score
            suggestion += secrets.choice(string.ascii_letters + string.digits + string.punctuation)

        suggestion_list = list(suggestion)
        secrets.SystemRandom().shuffle(suggestion_list)
        suggestion = ''.join(suggestion_list)

        suggestions.append(suggestion)
    return suggestions

def generate_perfect_passwords():
    """Suggests very strong passwords with all character types."""

    suggestions = []
    for _ in range(3):
        suggestion = ""

        suggestion += secrets.choice(string.ascii_uppercase)
        suggestion += secrets.choice(string.ascii_uppercase)
        suggestion += secrets.choice(string.ascii_lowercase)
        suggestion += secrets.choice(string.ascii_lowercase)
        suggestion += secrets.choice(string.digits)
        suggestion += secrets.choice(string.digits)
        suggestion += secrets.choice(string.punctuation)
        suggestion += secrets.choice(string.punctuation)

        for _ in range(4):
            suggestion += secrets.choice(string.ascii_letters + string.digits + string.punctuation)

        suggestion_list = list(suggestion)
        secrets.SystemRandom().shuffle(suggestion_list)
        suggestion = ''.join(suggestion_list)

        suggestions.append(suggestion)
    return suggestions

while True:
    # Get user input
    password = input("Enter a password: ")

    # Analyze the password
    score, feedback = password_analyzer(password)

    # Display the results
    print(f"Password score: {score:.2f}/1.0")
    if feedback:
        print("Feedback:")
        for item in feedback:
            print(item)

    # Check for missing uppercase or special characters and prompt retry
    if "Missing uppercase letter." in feedback or "Missing special character." in feedback:
        print("Please try again with at least one uppercase and one special character.")
        continue

    # Provide appropriate message based on score
    if score >= 0.8:
        print("Your password is strong enough.")
    else:
        print("Your password is not up to the security level.")

    # Suggest stronger passwords if score is below or equal to 0.7
    if score <= 0.7:
        print("Here are some stronger password suggestions:")
        suggestions = suggest_stronger_passwords()
        for suggestion in suggestions:
            print(suggestion)

    # If score is above or equal to 0.7, no need to try again
    if score >= 0.7:
        break

