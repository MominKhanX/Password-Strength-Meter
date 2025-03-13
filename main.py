import re
import streamlit as st

def check_password_strength(password):
    score = 0
    feedback = []

    # Length Check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long.")

    # Upper & Lowercase Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Include both uppercase and lowercase letters.")

    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")

    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")

    return score, feedback

# Streamlit UI
def main():
    st.title("🔐 Password Strength Meter")
    st.write("Enter a password to check its strength:")

    password = st.text_input("🔑 Enter your password", type="password")

    if st.button("Check Strength"):
        if password:
            score, feedback = check_password_strength(password)

            # Strength Rating
            if score == 4:
                st.success("✅ Strong Password! Your password is secure. 🎉")
            elif score == 3:
                st.warning("⚠️ Moderate Password - Consider adding more security features.")
            else:
                st.error("❌ Weak Password - Improve it using the suggestions below.")
            
            # Show suggestions
            if feedback:
                for tip in feedback:
                    st.write(tip)
        else:
            st.error("❌ Please enter a password.")

# Run the app
if __name__ == "__main__":
    main()
