import os
import time
import json
import pickle
from typing import Dict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from ..preprocessing import normalize_text
from .dataset import generate_dataset, save_dataset

MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../saved_models/classifier.pkl")
)
EVAL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../data/evaluation_results.json")
)
DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../data")
)


class ModelTrainer:
    def __init__(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        os.makedirs(DATA_DIR, exist_ok=True)

    def train(self, dataset_size: int = 1000, test_size: float = 0.2) -> Dict:
        t0 = time.time()

        dataset = generate_dataset(dataset_size)
        save_dataset(dataset, output_dir=DATA_DIR)

        texts = [normalize_text(d["text"]) for d in dataset]
        labels = [d["label"] for d in dataset]

        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )

        pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        ngram_range=(1, 3),
                        max_features=15000,
                        min_df=1,
                        sublinear_tf=True,
                        analyzer="word",
                    ),
                ),
                (
                    "clf",
                    LogisticRegression(max_iter=1000, C=1.0, random_state=42),
                ),
            ]
        )
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        ml_metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred), 4),
            "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        }

        rule_metrics = self._eval_rule_based(dataset)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump(pipeline, f)

        training_time = round(time.time() - t0, 2)

        comparison = {
            "ml_accuracy": ml_metrics["accuracy"],
            "ml_f1": ml_metrics["f1"],
            "rule_based_accuracy": rule_metrics["accuracy"],
            "rule_based_f1": rule_metrics["f1"],
            "winner": "ML Classifier" if ml_metrics["f1"] >= rule_metrics["f1"] else "Rule-Based",
        }

        eval_output = {
            "ml": ml_metrics,
            "rule_based": rule_metrics,
            "comparison": comparison,
            "dataset_size": dataset_size,
            "train_size": len(X_train),
            "test_size_samples": len(X_test),
        }

        with open(EVAL_PATH, "w") as f:
            json.dump(eval_output, f, indent=2)

        return {
            **ml_metrics,
            "train_size": len(X_train),
            "test_size": len(X_test),
            "model_type": "TF-IDF + Logistic Regression",
            "training_time": training_time,
            "comparison": comparison,
        }

    def _eval_rule_based(self, dataset) -> Dict:
        from ..detection.rule_based import RuleBasedDetector

        detector = RuleBasedDetector()
        y_true = [d["label"] for d in dataset]
        y_pred = [1 if detector.detect(d["text"])["score"] > 20 else 0 for d in dataset]

        return {
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        }
