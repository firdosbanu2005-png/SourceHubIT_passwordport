import re

def check_password_strength(password):
    suggestions = []
    strength_points = 0

    # Check length
    if len(password) >= 8:
        strength_points += 1
    else:
        suggestions.append("Use at least 8 characters")

    # Check uppercase and lowercase
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        strength_points += 1
    else:
        suggestions.append("Include both uppercase and lowercase letters")

    # Check digits
    if re.search(r'\d', password):
        strength_points += 1
    else:
        suggestions.append("Add at least one number")

    # Check special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength_points += 1
    else:
        suggestions.append("Add at least one special character (!@#$ etc.)")

    # Determine strength
    if strength_points == 4:
        strength = "Strong"
    elif strength_points == 2 or strength_points == 3:
        strength = "Medium"
    else:
        strength = "Weak"

    return strength, suggestions


# Main Program
password = input("1. Enter your password: ")
strength, suggestions = check_password_strength(password)

print("\n2. Password Strength:", strength)
if suggestions:
    print("3. Suggestions:")
    for s in suggestions:
        print("-", s)
else:
    print("3. Suggestions: Your password looks great! 👍")
