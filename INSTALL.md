# INSTALL

## Local (Python 3.11 recommended)
```bash
python -m venv .venv
source .venv/bin/activate
make setup
```

## Train models
```bash
make train
```

## Run UI
```bash
make run
# visit http://localhost:8501
```

## Docker
```bash
docker compose up --build
```

## Streamlit Cloud
- Option A (preferred): pre-train locally and commit `artifacts/` folder.
- Option B: keep `ensure_artifacts()` in app to train at first launch.

## Notes
- Two **separate** PyCaret `setup()` calls are used (classification vs clustering).
- Clusters are mapped to actor profiles from synthetic-data majority labels and saved to `artifacts/cluster_profile_map.json`.