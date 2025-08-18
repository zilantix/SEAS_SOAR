# Cognitive SOAR on Replit

## Run
Click **Run**. First run installs deps and trains models, then launches Streamlit.
- App URL appears in the Replit "Webview" panel.

## Faster cold start
Default: `FAST_TRAIN=1`, `N_PER_CLASS=600`. Change in `start.py` for slower/higher quality.

## Tests
From the shell:
```bash
python -m unittest -v
```