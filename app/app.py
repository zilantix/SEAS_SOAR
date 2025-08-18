"""
app.py

Streamlit app that:
1) Predicts MALICIOUS vs BENIGN via classification model.
2) If MALICIOUS, performs threat attribution using clustering model.
Includes confidence heuristic and suggested playbooks.
"""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st
from pycaret.classification import load_model as load_cls_model, predict_model as predict_cls
from pycaret.clustering import load_model as load_clu_model, predict_model as predict_clu

ARTIFACT_DIR = Path("artifacts")
PROFILE_MAP_PATH = ARTIFACT_DIR / "cluster_profile_map.json"

# Static profile descriptions for UI
PROFILE_DESCRIPTIONS = {
    "STATE_SPONSORED": "Typically well-resourced and patient. Likely to use valid SSL, subtle domain tricks (e.g., hyphenated prefixes), and low-noise infrastructure to evade reputation-based defenses.",
    "ORG_CRIME": "Economically motivated, high-volume campaigns. Often leverage URL shorteners, raw IP hosts, long/abnormal URLs, and high external content ratios to scale operations.",
    "HACKTIVIST": "Cause-driven, opportunistic activity with mixed tradecraft. Political keywords and social engineering hooks are common, with varying levels of technical sophistication.",
}

# Short playbook suggestions shown in the UI
PLAYBOOKS = {
    "STATE_SPONSORED": [
        "Immediate IR escalation (Tier-3/lead) and legal/compliance notification",
        "Preserve forensics (disk, memory, key logs); maintain chain of custody",
        "Block domains/IPs, revoke suspicious certs, and rotate keys/tokens",
        "Hunt for lateral movement and long-dwell persistence (scheduled tasks, service creation)",
        "Increase monitoring thresholds and deploy high-fidelity detections",
    ],
    "ORG_CRIME": [
        "Reset impacted credentials and enforce MFA",
        "Block indicators (domains, IPs, shortener patterns) at email/web proxies",
        "Review payment/fraud workflows; coordinate with anti-abuse teams",
        "Scan for large-volume exfil attempts and commodity malware beacons",
        "Ticket similar events into an automated containment playbook",
    ],
    "HACKTIVIST": [
        "Activate comms plan with PR/leadership for potential public messaging",
        "Harden web/WAF rules (rate-limit, block abusive user-agents/IPs)",
        "Increase logging and detect content defacement and social engineering probes",
        "Monitor social platforms and paste sites for coordination/leaks",
        "Review DDoS readiness (CDN, surge capacity) and throttle risky endpoints",
    ],
}


@st.cache_resource
def load_artifacts():
    # Guard: ensure pre-baked artifacts exist
    cls_p = ARTIFACT_DIR / "phishing_url_detector.pkl"
    clu_p = ARTIFACT_DIR / "threat_actor_profiler.pkl"
    map_p = PROFILE_MAP_PATH
    missing = [p for p in (cls_p, clu_p, map_p) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing model artifacts. Please run `python train_model.py` locally and commit files in artifacts/:\n"
            + "\n".join(str(p) for p in missing)
        )

    clf = load_cls_model(ARTIFACT_DIR / "phishing_url_detector")
    clu = load_clu_model(ARTIFACT_DIR / "threat_actor_profiler")
    # JSON keys are strings; normalize to int for convenience
    with open(PROFILE_MAP_PATH) as f:
        raw_map = json.load(f)
    cluster_map = {int(re.search(r"(\d+)$", str(k)).group(1)) if re.search(r"(\d+)$", str(k)) else int(k): v
                   for k, v in raw_map.items()}
    return clf, clu, cluster_map


def compute_cluster_confidence(pipeline, X: pd.DataFrame):
    """
    Heuristic: use distance margin between nearest and 2nd-nearest centroids
    after applying the same preprocessing as the PyCaret pipeline.
    Returns (confidence_float_0_1, distances_list) or (None, None) on fallback.
    """
    try:
        pre = pipeline[:-1]  # preprocessing steps
        kmeans = pipeline.named_steps.get("trained_model", None)
        if kmeans is None or not hasattr(kmeans, "transform"):
            return None, None
        # Try float64 first; if sklearn compiled kernel expects float32, retry below
        try:
            Xt = pre.transform(X.astype("float64"))
            dists = kmeans.transform(Xt)[0]
        except ValueError:
            Xt = pre.transform(X.astype("float32"))
            dists = kmeans.transform(Xt)[0]
        order = np.argsort(dists)
        d1, d2 = float(dists[order[0]]), float(dists[order[1]])
        conf = max(0.0, min(1.0, (d2 - d1) / (d1 + d2 + 1e-9)))
        return conf, dists.tolist()
    except Exception:
        return None, None


def input_form():
    st.sidebar.header("URL Features")
    features = {
        "SSLfinal_State": st.sidebar.selectbox("Valid SSL?", [0, 1], index=1),
        "Prefix_Suffix": st.sidebar.selectbox("Hyphenated domain (prefix/suffix)?", [0, 1], index=0),
        "Shortining_Service": st.sidebar.selectbox("Shortening service used?", [0, 1], index=0),
        "having_IP_Address": st.sidebar.selectbox("Raw IP in host?", [0, 1], index=0),
        "Abnormal_URL": st.sidebar.selectbox("Abnormal URL?", [0, 1], index=0),
        "HTTPS_token": st.sidebar.selectbox("'https' token in host?", [0, 1], index=0),
        "URL_Length": st.sidebar.slider("URL length (chars)", 10, 200, 80),
        "URL_of_Anchor": st.sidebar.slider("Suspicious anchors ratio", 0.0, 1.0, 0.3, 0.01),
        "Page_Rank": st.sidebar.slider("Page rank (0=low,1=high)", 0.0, 1.0, 0.5, 0.01),
        "Request_URL": st.sidebar.slider("External objects ratio", 0.0, 1.0, 0.35, 0.01),
        "has_political_keyword": st.sidebar.selectbox("Contains political keyword?", [0, 1], index=0),
    }
    return pd.DataFrame([features])


def _parse_cluster_id(val) -> int:
    """Accept 'Cluster 1' or 1 and return 1."""
    s = str(val)
    m = re.search(r"(\d+)$", s)
    if m:
        return int(m.group(1))
    # last resort: numeric coercion
    return int(pd.to_numeric(s, errors="coerce"))


def _predict_cluster_robust(clu_pipeline, X: pd.DataFrame):
    """Call PyCaret predict_model with dtype robustness (float64 → float32 fallback)."""
    try:
        return predict_clu(clu_pipeline, X.astype("float64"))
    except ValueError:
        return predict_clu(clu_pipeline, X.astype("float32"))


def main():
    st.set_page_config(page_title="Cognitive SOAR: From Prediction to Attribution", layout="wide")
    st.title("🧠 Cognitive SOAR — From Prediction to Attribution")
    st.caption("Binary detection + clustering-based attribution to enrich SOAR triage.")

    tabs = st.tabs(["Prediction", "Threat Attribution", "About"])

    # -------- Prediction tab --------
    with tabs[0]:
        st.subheader("Prediction")
        X = input_form()
        st.write("**Current feature vector:**")
        st.dataframe(X, use_container_width=True)

        if st.button("Analyze"):
            clf, _, _ = load_artifacts()
            pred = predict_cls(clf, X.copy())
            verdict = pred.loc[0, "prediction_label"] if "prediction_label" in pred.columns else pred.loc[0, "Label"]
            st.metric("Verdict", verdict)
            st.caption("Attribution is available in the next tab if the verdict is MALICIOUS.")
            st.session_state["verdict"] = verdict
            st.session_state["features"] = X.to_dict(orient="records")[0]

    # -------- Threat Attribution tab --------
    with tabs[1]:
        st.subheader("Threat Attribution")
        if st.session_state.get("verdict") == "MALICIOUS":
            X = pd.DataFrame([st.session_state["features"]])
            _, clu, cluster_map = load_artifacts()

            clu_pred = _predict_cluster_robust(clu, X.copy())
            raw_cluster = clu_pred.loc[0, "Cluster"]
            cluster_id = _parse_cluster_id(raw_cluster)
            profile = cluster_map.get(cluster_id, "UNKNOWN")

            st.write(f"**Cluster**: {cluster_id}")
            st.write(f"**Attributed Profile**: {profile}")
            st.info(PROFILE_DESCRIPTIONS.get(profile, "No description available for this cluster."))

            st.subheader("Attribution details")
            conf, dists = compute_cluster_confidence(clu, X.copy())
            if conf is not None:
                st.metric("Attribution confidence", f"{int(conf * 100)}%")
                st.caption("Confidence based on K-Means distance margin after preprocessing.")
                st.dataframe(
                    pd.DataFrame({"cluster": list(range(len(dists))), "distance": dists}),
                    use_container_width=True,
                )
            else:
                st.info("Confidence not available for this model/pipeline version.")

            with st.expander("Suggested playbook"):
                for step in PLAYBOOKS.get(profile, []):
                    st.write(f"- {step}")
        else:
            st.warning("Attribution is only performed for MALICIOUS predictions. Use the Prediction tab first.")

    # -------- About tab --------
    with tabs[2]:
        st.subheader("About")
        st.markdown(
            """
This mini-app demonstrates a dual-model SOAR enrichment pattern:

1) A **supervised classifier** flags a URL as BENIGN/MALICIOUS.  
2) An **unsupervised clustering model** attributes malicious samples to a likely **threat actor profile**.

Under the hood, clusters are mapped to human-readable profiles using centroid/mode heuristics on synthetic training data.
"""
        )


if __name__ == "__main__":
    main()