# TESTING

Open the app:
- Local: http://localhost:8501
- Cloud: https://seas-soar-iakupov.streamlit.app/

For each case:
1) Set the sidebar inputs.
2) Click **Analyze** on **Prediction**.
3) If verdict is **MALICIOUS**, open **Threat Attribution** to verify actor profile.

---

## A. Benign (Expected: BENIGN)

SSLfinal_State: **1**  
Prefix_Suffix: **0**  
Shortining_Service: **0**  
having_IP_Address: **0**  
Abnormal_URL: **0**  
HTTPS_token: **0**  
URL_Length: **40–60**  
URL_of_Anchor: **0.05–0.15**  
Page_Rank: **0.6–0.9**  
Request_URL: **0.1–0.2**  
has_political_keyword: **0**

Expected: **BENIGN** (Attribution not applicable)

---

## B. Malicious — STATE_SPONSORED (Expected: MALICIOUS → STATE_SPONSORED)

SSLfinal_State: **1**  
Prefix_Suffix: **1**  
Shortining_Service: **0**  
having_IP_Address: **0**  
Abnormal_URL: **0** (or low)  
HTTPS_token: **0**  
URL_Length: **70–100**  
URL_of_Anchor: **0.2–0.35**  
Page_Rank: **0.4–0.7**  
Request_URL: **0.2–0.4**  
has_political_keyword: **0**

---

## C. Malicious — ORG_CRIME (Expected: MALICIOUS → ORG_CRIME)

SSLfinal_State: **0**  
Prefix_Suffix: **0/1**  
Shortining_Service: **1**  
having_IP_Address: **1**  
Abnormal_URL: **1**  
HTTPS_token: **0/1**  
URL_Length: **90–140**  
URL_of_Anchor: **0.4–0.7**  
Page_Rank: **0.0–0.3**  
Request_URL: **0.4–0.8**  
has_political_keyword: **0**

---

## D. Malicious — HACKTIVIST (Expected: MALICIOUS → HACKTIVIST)

SSLfinal_State: **0/1**  
Prefix_Suffix: **0/1**  
Shortining_Service: **0/1**  
having_IP_Address: **0**  
Abnormal_URL: **0/1**  
HTTPS_token: **0**  
URL_Length: **60–100**  
URL_of_Anchor: **0.2–0.5**  
Page_Rank: **0.3–0.6**  
Request_URL: **0.2–0.5**  
has_political_keyword: **1**

