import subprocess, sys, os

# This runs before app.py on Streamlit Cloud
# Regenerates data and models since they're excluded from git

def ensure_data():
    """Generate data and models if they don't exist."""
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)

    if not os.path.exists("data/attackers.json"):
        print("Generating dataset...")
        subprocess.run([sys.executable, "data/generate_data.py"], check=True)

    if not os.path.exists("models/models.pkl"):
        print("Training models...")
        subprocess.run([sys.executable, "models/train.py"], check=True)

ensure_data()
