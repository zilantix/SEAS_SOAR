<<<<<<< HEAD
# Cognitive SOAR — From Prediction to Attribution

Enhances a Mini-SOAR demo by adding **threat attribution** via **unsupervised clustering**.
- **Classification** (PyCaret): MALICIOUS vs BENIGN.
- **Clustering** (PyCaret): Map malicious samples to **STATE_SPONSORED**, **ORG_CRIME**, or **HACKTIVIST**.

## Architecture

```
[User Features] --> [Classifier] --BENIGN--> [Stop]
                               \-MALICIOUS-> [Clustering] -> [Profile Mapping] -> [Attribution]
```

Artifacts are saved to `artifacts/`:
- `phishing_url_detector.pkl`
- `threat_actor_profiler.pkl`
- `cluster_profile_map.json` (discovered cluster → profile mapping)

## Quickstart

```bash
# local
make setup
make train
make run

# Docker
docker compose up --build
```
Then open http://localhost:8501

## Streamlit Cloud
- Recommended: run `make train` locally and commit `artifacts/` to repo.
- Or keep the auto-train in `app/app.py` (`ensure_artifacts()`) for first launch on cloud.

## Replit
- Add `.replit` and `start.py` (included) to train on first run and launch automatically.

## Repo Layout

- `train_model.py` – synthetic data + training pipelines (classification & clustering)
- `app/app.py` – Streamlit UI (Prediction + Threat Attribution, confidence, playbooks)
- `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `Makefile`
- `docs/` – blog article draft
- `.github/workflows/lint.yml`
- `INSTALL.md`, `TESTING.md`

## Notes
- Two **separate** PyCaret `setup()` calls are used (classification vs clustering).
- Clusters are mapped to actor profiles from synthetic-data majority labels and saved to `artifacts/cluster_profile_map.json`.

## Pre-baked Artifacts
This build expects pre-baked artifacts in `artifacts/`. If they are missing, run `python train_model.py` locally and commit the generated files before deploying to Streamlit Cloud.
=======
# SEAS_SOAR
>>>>>>> 5fc182e3a2c14d3b514851e0696c42f0dbaa382d
