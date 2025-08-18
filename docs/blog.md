# From Prediction to Attribution: Integrating Unsupervised Learning for Enhanced SOAR Triage

**TL;DR** – Binary "malicious vs benign" alerts are not enough for a modern SOC. This project augments a Mini-SOAR detector with an *attribution* layer powered by unsupervised clustering. When a URL is flagged as malicious, a second model infers the **likely threat actor profile** (State-Sponsored, Organized Cybercrime, or Hacktivist), giving analysts faster context for triage and response.

## Why move beyond binary alerts?

Binary classifiers answer *"Is this bad?"* They do not answer *"What kind of bad is it?"* or *"Who is likely behind it?"* In practice, SOC workflows require **context**: playbooks differ if the activity looks like **financially motivated** crimeware versus a **state-sponsored** operation with strategic objectives. The difference guides escalation, evidence preservation, and which external partners to notify. A purely binary outcome tends to produce the same generic workflow for every malicious event—slowing teams down or causing misprioritization.

## System overview

Our enhancement adds an **Enrichment** step to the existing Mini-SOAR application. The pipeline becomes:

1. **Supervised URL classification (PyCaret)** – Flags a submission as **BENIGN** or **MALICIOUS**.
2. **Unsupervised clustering (PyCaret)** – If *MALICIOUS*, we embed the feature vector into a clustering model trained to discover **three archetypes** of adversary behavior.
3. **Profile mapping** – Each discovered cluster is mapped to a human-readable **threat actor profile** with a short description used in the UI and downstream playbooks.

This dual-model architecture transforms raw detection into **actionable attribution** that analysts can act on immediately.

## Feature engineering: encoding tradecraft as signals

To make clustering meaningful, we engineered features that reflect real-world tactics, techniques, and procedures (TTPs) commonly observable in URL telemetry. We simulate three profiles:

- **State-Sponsored** – *Subtle, quality tradecraft*. Often uses **valid SSL** (`SSLfinal_State=1`) and **hyphenated domains** (`Prefix_Suffix=1`) to mimic legitimate brands. URLs have **moderate length**, **fewer suspicious anchors**, and **middling page rank**—consistent with bespoke infrastructure intended to pass reputation checks.
- **Organized Cybercrime** – *High-volume, noisy campaigns*. Frequent **URL shorteners** (`Shortining_Service=1`), **raw IP hosts** (`having_IP_Address=1`), **abnormal structures** (`Abnormal_URL=1`), **very long URLs**, **high external object ratios**, and **low page rank**—consistent with scalable kit and constant churn.
- **Hacktivist** – *Cause-driven and opportunistic*. Mixed tradecraft with a higher rate of **political keywords** (`has_political_keyword=1`). Length and structure sit between state and crime profiles, reflecting heterogeneity across loose-knit operations.

Benign samples are drawn near "normal" values (valid SSL more common, short URLs, higher page rank, low abnormality). The goal is **clear but plausible** separation in feature space so the clustering model can reliably discover three groups.

## Algorithm selection: why K-Means fits this data

We intentionally synthesize **three compact, roughly spherical clusters** of malicious behavior. Given that design, **K-Means** is a strong choice:

- It assumes clusters are separable by Euclidean distance around centroids—appropriate for our engineered, continuous features (after PyCaret's standard scaling/encoding).
- It is **fast and stable** for real-time enrichment and easy to operationalize.
- It produces **centroids** that are simple to interpret (e.g., the "crimeware" centroid shows high shortening/IP usage and long URLs).

Alternatives considered:

- **DBSCAN** excels at discovering arbitrarily shaped clusters and outliers. In our synthetic setting, classes are well-formed without substantial noise—DBSCAN’s strengths aren’t essential and it can be sensitive to `eps` in mixed-scale spaces.
- **Gaussian Mixture Models (GMM)** provide soft assignments and can model unequal covariances. That flexibility is unnecessary given our design goals and adds runtime/maintenance complexity.

Because the **data generation strategy** manufactures well-separated, nearly convex regions, *K-Means* is the pragmatic, justifiable choice.

## Implementation details

The repository splits training and inference:

- **`train_model.py`** builds both models.
  - Generates synthetic data for three malicious profiles plus benign.
  - **Classification workflow**: `pycaret.classification.setup()` with `label` target → `compare_models()` (or `lr` in fast mode) → `finalize_model()` → save as `artifacts/phishing_url_detector.pkl`.
  - **Clustering workflow**: Drop `label` and `actor_profile` → `pycaret.clustering.setup()` → `create_model("kmeans", num_clusters=3)` → optional `tune_model()` → save as `artifacts/threat_actor_profiler.pkl`.
  - **Profile mapping**: Assign training points to clusters and compute the **majority malicious profile** within each cluster (ignoring benign). The resulting `cluster_id → profile` map is saved to `artifacts/cluster_profile_map.json`.
- **`app/app.py`** serves the Streamlit UI.
  - On submit, the classifier predicts **BENIGN/MALICIOUS**.
  - If **MALICIOUS**, the clustering model predicts a **Cluster** ID for the same feature vector. We then look up the human-readable profile and display a concise description in a **Threat Attribution** tab.
  - A **confidence** indicator (distance margin) and **playbook suggestions** are included.

**Critical note:** PyCaret requires **two separate `setup()` calls**—one for classification (with a target), one for clustering (features only). Mixing them will produce errors.

## Results and analyst workflow impact

On the synthetic dataset, the clustering step reliably separates the three malicious styles. During demo runs:

- "Crimeware-like" inputs (shortener=1, IP=1, long URLs, abnormal patterns) map to an **Organized Cybercrime** cluster.
- "State-like" inputs (valid SSL, hyphenated domain, fewer anomalies) map to **State-Sponsored**.
- Political-keyword-heavy mixes map to **Hacktivist**.

### Benefits for SOAR

- **Faster triage** – Tickets open with **context**: the suspected actor profile and a one-line rationale, enabling the right playbook and escalation path.
- **Prioritization** – Strategic cases (possible state activity) can route to IR leadership, while crimeware can move through containment automation.
- **Metrics & threat intel** – Over time, cluster proportions and centroid drift provide **operational telemetry** about your organization’s threat mix.

### Risks and considerations

- **Misattribution** – Clustering is **not identity**. It infers style, not a specific group. Treat attribution as **probabilistic enrichment**, not ground truth.
- **Concept drift** – As attacker tradecraft evolves, clusters and mappings may shift. Retrain periodically and monitor cluster cohesion.
- **Feature bias** – URL-only signals are limited. For production, augment with **host telemetry, passive DNS, TLS, and content analysis** to strengthen separation.

## How to validate

- **Manual test cases** (included in `TESTING.md`) cover one benign and one malicious example for each profile.
- Inspect cluster **centroids** to ensure they match the engineered expectations (e.g., crimeware centroid has high `Shortining_Service` and `having_IP_Address`).

## Deployment notes

- The Docker image packages PyCaret and Streamlit; a `docker-compose.yml` launches training followed by the app.
- Artifacts live under `/app/artifacts`. In CI, you can cache or publish them as build artifacts as part of promotion to staging/prod.

## Conclusion

By pairing a fast, accurate **binary detector** with a lightweight **clustering-based attribution layer**, SOCs gain decisive context with minimal runtime cost. This pattern upgrades alerts from *"malicious"* to *"malicious and likely {state/crime/hacktivist}"*, closing the gap between detection and response. The approach is transparent, tunable, and ready to extend with richer features as your telemetry matures.

## References

- PyCaret Documentation – *Classification* and *Clustering* modules.
- Bishop, C. M. (2006). *Pattern Recognition and Machine Learning*. Springer.
- Chandola, V., Banerjee, A., & Kumar, V. (2009). *Anomaly detection: A survey*. CSUR.
- NIST SP 800-61r2. *Computer Security Incident Handling Guide*.