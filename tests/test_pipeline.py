# tests/test_pipeline.py
import os
import json
import unittest
from pathlib import Path

import pandas as pd

from train_model import (
    generate_synthetic_data,
    build_and_save_models,
    ARTIFACT_DIR,
    PROFILE_MAP_PATH,
)

from pycaret.clustering import load_model as load_clu_model, predict_model as predict_clu


class TestCognitiveSOAR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["FAST_TRAIN"] = "1"
        df = generate_synthetic_data(n_per_class=80, benign_ratio=0.5)
        build_and_save_models(df)

    def test_artifacts_written(self):
        self.assertTrue((ARTIFACT_DIR / "phishing_url_detector.pkl").exists())
        self.assertTrue((ARTIFACT_DIR / "threat_actor_profiler.pkl").exists())
        self.assertTrue(PROFILE_MAP_PATH.exists())

    def test_cluster_profile_map(self):
        mapping = json.loads(Path(PROFILE_MAP_PATH).read_text())
        self.assertEqual(len(mapping.keys()), 3)
        allowed = {"STATE_SPONSORED", "ORG_CRIME", "HACKTIVIST", "BENIGNISH"}
        self.assertTrue(set(mapping.values()).issubset(allowed))

    def test_end_to_end_org_crime_hint(self):
        sample = pd.DataFrame([{
            "SSLfinal_State": 0,
            "Prefix_Suffix": 1,
            "Shortining_Service": 1,
            "having_IP_Address": 1,
            "Abnormal_URL": 1,
            "HTTPS_token": 0,
            "URL_Length": 120,
            "URL_of_Anchor": 0.65,
            "Page_Rank": 0.2,
            "Request_URL": 0.7,
            "has_political_keyword": 0
        }])
        clu = load_clu_model(str(ARTIFACT_DIR / "threat_actor_profiler"))
        pred = predict_clu(clu, sample)
        self.assertIn("Cluster", pred.columns)


if __name__ == "__main__":
    unittest.main(verbosity=2)