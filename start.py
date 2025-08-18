import os, sys, subprocess
from pathlib import Path

ART_DIR = Path("artifacts")
CLS = ART_DIR / "phishing_url_detector.pkl"
CLU = ART_DIR / "threat_actor_profiler.pkl"
MAP = ART_DIR / "cluster_profile_map.json"

def ensure_trained():
    ART_DIR.mkdir(parents=True, exist_ok=True)
    if not (CLS.exists() and CLU.exists() and MAP.exists()):
        env = os.environ.copy()
        env.setdefault("FAST_TRAIN", "1")
        env.setdefault("N_PER_CLASS", "600")
        print("Training models (one-time)...")
        subprocess.run([sys.executable, "train_model.py"], check=True, env=env)
    else:
        print("Artifacts found; skipping training.")

def run_streamlit():
    port = os.environ.get("PORT", "8501")
    env = os.environ.copy()
    env["STREAMLIT_SERVER_PORT"] = port
    env["STREAMLIT_SERVER_ADDRESS"] = "0.0.0.0"
    cmd = [sys.executable, "-m", "streamlit", "run", "app/app.py"]
    subprocess.run(cmd, env=env, check=True)

if __name__ == "__main__":
    ensure_trained()
    run_streamlit()