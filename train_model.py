"""
train_model.py

Trains two models:
1) A supervised classifier for malicious vs benign URL detection.
2) An unsupervised clustering model for threat attribution.

Stack: Python, PyCaret 3.x, scikit-learn.
"""

import os
import json
from pathlib import Path
import numpy as np
import pandas as pd

# --- PyCaret imports (classification & clustering) ---
from pycaret.classification import (
    setup as cls_setup,
    compare_models,
    create_model as create_cls_model,
    finalize_model,
    save_model as save_cls_model,
)
from pycaret.clustering import (
    setup as clu_setup,
    create_model as create_clu_model,
    save_model as save_clu_model,
    assign_model,
)

RANDOM_STATE = 42
ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
PROFILE_MAP_PATH = ARTIFACT_DIR / "cluster_profile_map.json"


def generate_synthetic_data(n_per_class: int = 1500, benign_ratio: float = 0.5) -> pd.DataFrame:
    """
    Create synthetic URL feature data for three malicious actor profiles + benign.

    Malicious profiles:
      - STATE_SPONSORED: valid SSL (SSLfinal_State=1), subtle deception (Prefix_Suffix=1)
      - ORG_CRIME: shorteners, raw IP, abnormal/long URLs
      - HACKTIVIST: political keywords, mixed tactics

    Returns: DataFrame with features + 'label' + 'actor_profile'
    """
    rng = np.random.default_rng(RANDOM_STATE)

    columns = [
        "SSLfinal_State",
        "Prefix_Suffix",
        "Shortining_Service",
        "having_IP_Address",
        "Abnormal_URL",
        "HTTPS_token",
        "URL_Length",
        "URL_of_Anchor",
        "Page_Rank",
        "Request_URL",
        "has_political_keyword",
    ]

    def clip01(x):
        return np.clip(x, 0, 1)

    rows = []

    # --- Malicious: State-Sponsored ---
    for _ in range(n_per_class):
        rows.append([
            1,                                  # SSLfinal_State
            rng.choice([0, 1], p=[0.3, 0.7]),   # Prefix_Suffix
            0,                                  # Shortining_Service
            0,                                  # having_IP_Address
            rng.choice([0, 1], p=[0.8, 0.2]),   # Abnormal_URL
            rng.choice([0, 1], p=[0.85, 0.15]), # HTTPS_token
            int(rng.normal(75, 10)),            # URL_Length
            clip01(rng.normal(0.25, 0.1)),      # URL_of_Anchor
            clip01(rng.normal(0.45, 0.1)),      # Page_Rank
            clip01(rng.normal(0.35, 0.1)),      # Request_URL
            rng.choice([0, 1], p=[0.85, 0.15]), # has_political_keyword
            "MALICIOUS",
            "STATE_SPONSORED"
        ])

    # --- Malicious: Organized Cybercrime ---
    for _ in range(n_per_class):
        rows.append([
            rng.choice([0, 1], p=[0.7, 0.3]),
            rng.choice([0, 1], p=[0.4, 0.6]),
            rng.choice([0, 1], p=[0.2, 0.8]),
            rng.choice([0, 1], p=[0.25, 0.75]),
            rng.choice([0, 1], p=[0.3, 0.7]),
            rng.choice([0, 1], p=[0.5, 0.5]),
            int(rng.normal(105, 20)),
            clip01(rng.normal(0.6, 0.15)),
            clip01(rng.normal(0.2, 0.1)),
            clip01(rng.normal(0.65, 0.15)),
            rng.choice([0, 1], p=[0.95, 0.05]),
            "MALICIOUS",
            "ORG_CRIME"
        ])

    # --- Malicious: Hacktivist ---
    for _ in range(n_per_class):
        rows.append([
            rng.choice([0, 1], p=[0.5, 0.5]),
            rng.choice([0, 1], p=[0.55, 0.45]),
            rng.choice([0, 1], p=[0.5, 0.5]),
            rng.choice([0, 1], p=[0.7, 0.3]),
            rng.choice([0, 1], p=[0.5, 0.5]),
            rng.choice([0, 1], p=[0.6, 0.4]),
            int(rng.normal(85, 15)),
            clip01(rng.normal(0.45, 0.15)),
            clip01(rng.normal(0.3, 0.1)),
            clip01(rng.normal(0.5, 0.15)),
            rng.choice([0, 1], p=[0.35, 0.65]),
            "MALICIOUS",
            "HACKTIVIST"
        ])

    # --- Benign ---
    n_benign = int(benign_ratio * 3 * n_per_class)
    for _ in range(n_benign):
        rows.append([
            rng.choice([0, 1], p=[0.2, 0.8]),
            rng.choice([0, 1], p=[0.9, 0.1]),
            rng.choice([0, 1], p=[0.9, 0.1]),
            rng.choice([0, 1], p=[0.95, 0.05]),
            rng.choice([0, 1], p=[0.9, 0.1]),
            rng.choice([0, 1], p=[0.9, 0.1]),
            int(rng.normal(65, 10)),
            clip01(rng.normal(0.2, 0.1)),
            clip01(rng.normal(0.7, 0.1)),
            clip01(rng.normal(0.25, 0.1)),
            rng.choice([0, 1], p=[0.98, 0.02]),
            "BENIGN",
            "BENIGN"
        ])

    df = pd.DataFrame(rows, columns=columns + ["label", "actor_profile"])
    return df


def build_and_save_models(df: pd.DataFrame):
    # --- Supervised classification ---
    cls_setup(
        data=df.drop(columns=["actor_profile"]),   # avoid leakage
        target="label",
        session_id=RANDOM_STATE,
        verbose=False
    )
    fast = os.environ.get("FAST_TRAIN", "0") == "1"
    if fast:
        model = create_cls_model("lr")
    else:
        model = compare_models(sort="F1", turbo=True)

    final_clf = finalize_model(model)
    save_cls_model(final_clf, str(ARTIFACT_DIR / "phishing_url_detector"))

    # --- Unsupervised clustering on features only ---
    feature_df = df.drop(columns=["label", "actor_profile"])
    feature_df = feature_df.astype("float64")

    clu_setup(
        data=feature_df,
        session_id=RANDOM_STATE,
        verbose=False
    )
    kmeans = create_clu_model("kmeans", num_clusters=3, random_state=RANDOM_STATE)
    save_clu_model(kmeans, str(ARTIFACT_DIR / "threat_actor_profiler"))

    # --- Cluster → Profile mapping by majority (ignore BENIGN)
    assigned = assign_model(kmeans)  # adds 'Cluster'
    tmp = feature_df.copy()
    tmp["Cluster"] = assigned["Cluster"].values
    tmp["actor_profile"] = df["actor_profile"].values

    mapping = {}
    for cluster_id, grp in tmp.groupby("Cluster"):
        malicious_only = grp[grp["actor_profile"] != "BENIGN"]
        majority = "BENIGNISH" if malicious_only.empty else malicious_only["actor_profile"].value_counts().idxmax()
        cid = int(str(cluster_id).split()[-1]) if isinstance(cluster_id, str) else int(cluster_id)
        mapping[cid] = majority

    with open(PROFILE_MAP_PATH, "w") as f:
        json.dump(mapping, f, indent=2)

    print("Saved artifacts:")
    print(f" - {ARTIFACT_DIR / 'phishing_url_detector.pkl'}")
    print(f" - {ARTIFACT_DIR / 'threat_actor_profiler.pkl'}")
    print(f" - {PROFILE_MAP_PATH}")


def main():
    n = int(os.environ.get("N_PER_CLASS", "1500"))
    benign_ratio = float(os.environ.get("BENIGN_RATIO", "0.5"))
    df = generate_synthetic_data(n_per_class=n, benign_ratio=benign_ratio)
    build_and_save_models(df)


if __name__ == "__main__":
    main()
