import os
import pickle
from typing import Dict, Optional

MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../saved_models/classifier.pkl")
)


class MLClassifier:
    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
        except Exception:
            self.model = None

    def predict(self, text: str) -> Dict:
        if self.model is None:
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "score": 0.0,
                "trained": False,
            }

        import numpy as np
        from ..preprocessing import normalize_text

        normalized = normalize_text(text)
        proba = self.model.predict_proba([normalized])[0]
        label = self.model.predict([normalized])[0]
        confidence = float(max(proba))
        malicious_proba = float(proba[1]) if len(proba) > 1 else confidence

        return {
            "prediction": "malicious" if label == 1 else "benign",
            "confidence": round(confidence, 4),
            "score": round(malicious_proba * 100, 2),
            "trained": True,
        }

    def reload(self):
        self._load_model()

    def is_trained(self) -> bool:
        return self.model is not None
