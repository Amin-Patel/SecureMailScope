"""
Unsupervised anomaly detector for suspicious TLS sessions.

IsolationForest over the same feature vectors the risk classifier uses.
Unlike the classifier, this needs no labels -- it learns what "typical"
looks like across the training distribution and flags sessions that sit
far from it, which is the point: it can surface an unusual combination
the rule engine and the classifier's training labels never anticipated,
rather than only ever re-detecting known-bad patterns.
"""

from pathlib import Path
from typing import Dict, List, Optional

import joblib
from sklearn.ensemble import IsolationForest

from ml.feature_extractor import FEATURE_NAMES

MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "anomaly_detector.joblib"


class AnomalyDetector:
    def __init__(self):
        self.model: Optional[IsolationForest] = None

    def train(self, X: List[List[float]], contamination: float = 0.08, random_state: int = 42) -> IsolationForest:
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self.model.fit(X)
        return self.model

    def save(self, path: Path = MODEL_PATH) -> None:
        if self.model is None:
            raise RuntimeError("No trained model to save -- call train() first.")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)

    def load(self, path: Path = MODEL_PATH) -> None:
        self.model = joblib.load(path)

    def predict(self, features: Dict[str, float]) -> Dict:
        if self.model is None:
            raise RuntimeError("Model not loaded -- call load() or train() first.")
        vector = [[features[name] for name in FEATURE_NAMES]]
        # IsolationForest: -1 = anomaly, 1 = normal. score_samples: higher = more normal.
        is_anomaly = bool(self.model.predict(vector)[0] == -1)
        raw_score = float(self.model.score_samples(vector)[0])
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 4),
        }


_detector_instance: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> Optional[AnomalyDetector]:
    """Lazily load the trained model. Returns None if no model has been
    trained yet, so callers can degrade gracefully rather than crash."""
    global _detector_instance
    if _detector_instance is None:
        if not MODEL_PATH.exists():
            return None
        det = AnomalyDetector()
        det.load()
        _detector_instance = det
    return _detector_instance
