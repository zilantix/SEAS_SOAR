# TESTING

Manual test matrix for Streamlit UI:

| Case | Features (key knobs) | Expected Verdict | Expected Attribution |
|------|-----------------------|------------------|---------------------|
| T1 Benign | SSL=1, Prefix_Suffix=0, Shortening=0, IP=0, Abnormal=0, URL_Length~60, Anchors~0.2, PageRank~0.7, Request~0.25, Political=0 | BENIGN | (Not applicable) |
| T2 State-Sponsored | SSL=1, Prefix_Suffix=1, Shortening=0, IP=0, Abnormal low, URL_Length~75, Anchors~0.25, PageRank~0.45, Request~0.35, Political=0 | MALICIOUS | STATE_SPONSORED |
| T3 Organized Crime | Shortening=1, IP=1, Abnormal=1, URL_Length>100, Anchors>0.55, PageRank<0.3, Request>0.6 | MALICIOUS | ORG_CRIME |
| T4 Hacktivist | Political=1 with mixed others (Prefix_Suffix ~1, SSL~0/1, URL_Length~85) | MALICIOUS | HACKTIVIST |

How to run:
1. `make train` to generate artifacts (or rely on first-run training in app).
2. `make run` to start Streamlit.
3. Use sidebar to set features and validate outcomes.

Edge checks:
- Attribution only triggers when the verdict is MALICIOUS.
- Confidence value appears when K-Means distances are available.
- Playbook suggestions expand per profile.