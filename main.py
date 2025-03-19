import streamlit as st
import re
import requests
import hashlib
import random
import string
import time

# Streamlit Page Config
st.set_page_config(page_title="🔐 Ultimate Password Strength Tool", layout="centered")

# --- FUNCTIONS ---
def check_password_strength(password):
    """Analyzes password strength based on multiple factors."""
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password must be at least 8 characters long.")

    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Include both uppercase and lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")

    if re.search(r"[!@#$%^&*()_+=-]", password):
        score += 1
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")

    return score, feedback

def check_password_leak(password):
    """Checks if password is in leaked databases."""
    sha1_pass = hashlib.sha1(password.encode()).hexdigest().upper()
    first5, rest = sha1_pass[:5], sha1_pass[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)

    return rest in response.text  # True if password found in leaks

def generate_password(length=12, use_upper=True, use_numbers=True, use_special=True):
    """Generates a strong password with customizable options."""
    characters = string.ascii_lowercase
    if use_upper:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special:
        characters += "!@#$%^&*()-_"

    return "".join(random.choice(characters) for _ in range(length))

def generate_passphrase(num_words=4):
    """Generates an easy-to-remember passphrase."""
    words = ["Dragon", "Rocket", "Quantum", "Storm", "Echo", "Shadow", "Phoenix", "Nebula", "Cyber", "Matrix"]
    return "-".join(random.choices(words, k=num_words))

# --- UI DESIGN ---
st.markdown("<h1 style='text-align: center;'>🔐 Ultimate Password Strength Tool</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align: center;'>Analyze, Generate, and Improve Your Passwords!</h4>", unsafe_allow_html=True)

st.divider()  # Adds a visual divider

# --- PASSWORD CHECKER ---
password = st.text_input("Enter your password:", type="password", help="Type a password to check its strength")

if password:
    score, feedback = check_password_strength(password)

    # Dynamic Progress Bar for Strength
    st.subheader(f"🔍 Password Strength: {['Weak', 'Moderate', 'Strong'][min(score, 2)]}")
    st.progress(score / 5)

    # Show suggestions
    for msg in feedback:
        st.warning(msg)

    if score >= 5:
        st.success("🎉 Your password is strong! Keep it secure.")
    elif score >= 3:
        st.info("🛠 Consider improving it.")
    else:
        st.error("⚠️ Your password is weak! Strengthen it.")

    # Check if password is leaked
    if st.button("🔎 Check if Password is Leaked"):
        with st.spinner("Checking database..."):
            time.sleep(1.5)
            if check_password_leak(password):
                st.error("❌ This password has been leaked! Change it immediately.")
            else:
                st.success("✅ This password is safe.")

st.divider()

# --- PASSWORD GENERATOR ---
st.subheader("🔑 Need a Strong Password?")
length = st.slider("Select Password Length", 8, 32, 12)
use_upper = st.checkbox("Include Uppercase Letters", value=True)
use_numbers = st.checkbox("Include Numbers", value=True)
use_special = st.checkbox("Include Special Characters (!@#$%^&*)", value=True)

if st.button("Generate Secure Password"):
    new_password = generate_password(length, use_upper, use_numbers, use_special)
    st.code(new_password, language="python")

    # Save password to history
    if "password_history" not in st.session_state:
        st.session_state.password_history = []
    st.session_state.password_history.append(new_password)

# --- PASSPHRASE GENERATOR ---
st.subheader("🎭 Need a Memorable Passphrase?")
num_words = st.slider("Select Number of Words", 3, 6, 4)

if st.button("Generate Passphrase"):
    passphrase = generate_passphrase(num_words)
    st.code(passphrase, language="python")

st.divider()

# --- PASSWORD HISTORY ---
if "password_history" in st.session_state and st.session_state.password_history:
    st.subheader("📜 Password History")
    for i, past_pass in enumerate(st.session_state.password_history[-5:]):
        st.text(f"{i+1}. {past_pass}")
