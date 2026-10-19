"""
Supervised cryptographic risk classifier.

A RandomForestClassifier trained to reproduce and generalize
SecurityEngine's own deterministic severity logic (see
dataset_builder.label_session) over the feature space defined in
feature_extractor.py. Predictions are advisory, not authoritative --
see gemini_service.py-style fusion in security_engine.py's ML integration:
the model may raise a session's flagged priority, never suppress a
rule-confirmed finding.
"""

from pathlib import Path
from typing import Dict, List, Optional

import joblib
from sklearn.ensemble import RandomForestClassifier

from ml.feature_extractor import FEATURE_NAMES

MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "risk_classifier.joblib"


class RiskClassifier:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None

    def train(self, X: List[List[float]], y: List[str], random_state: int = 42) -> RandomForestClassifier:
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=random_state,
        )
        self.model.fit(X, y)
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
        label = self.model.predict(vector)[0]
        proba = self.model.predict_proba(vector)[0]
        classes = list(self.model.classes_)
        confidence = float(proba[classes.index(label)])
        return {
            "ml_risk_label": label,
            "ml_confidence": round(confidence, 4),
        }

    def feature_importances(self) -> Dict[str, float]:
        if self.model is None:
            raise RuntimeError("Model not loaded.")
        return dict(sorted(
            zip(FEATURE_NAMES, (float(v) for v in self.model.feature_importances_)),
            key=lambda kv: kv[1],
            reverse=True,
        ))


_classifier_instance: Optional[RiskClassifier] = None


def get_risk_classifier() -> Optional[RiskClassifier]:
    """Lazily load the trained model. Returns None if no model has been
    trained yet, so callers can degrade gracefully rather than crash."""
    global _classifier_instance
    if _classifier_instance is None:
        if not MODEL_PATH.exists():
            return None
        clf = RiskClassifier()
        clf.load()
        _classifier_instance = clf
    return _classifier_instance
