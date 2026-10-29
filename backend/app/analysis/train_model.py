"""Machine Learning Risk Model Training & Evaluation Pipeline.

Trains a production Random Forest Classifier on the synthetic firewall benchmark dataset.
Computes comprehensive evaluation metrics (Precision, Recall, F1, Confusion Matrix,
Feature Importance) and serializes the model artifact with joblib.
"""
import csv
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

from app.analysis.features import FeatureExtractor


def load_dataset(csv_path: str) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Loads feature matrix X and target labels y from dataset CSV."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Run generate_dataset.py first.")

    X_list: List[List[float]] = []
    y_list: List[int] = []

    label_map = {"Low": 0, "Medium": 1, "High": 2}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = [float(row[feat]) for feat in FeatureExtractor.FEATURE_NAMES]
            X_list.append(features)
            y_list.append(label_map[row["risk_level"]])

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int64)
    classes = ["Low", "Medium", "High"]

    return X, y, classes


def train_and_evaluate(
    dataset_csv: str = None,
    model_output_path: str = None,
    metadata_output_path: str = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Trains Random Forest classifier, evaluates metrics, and exports artifacts."""
    base_dir = os.path.dirname(__file__)

    if dataset_csv is None:
        dataset_csv = os.path.join(base_dir, "data", "dataset_firewall_rules.csv")

    if model_output_path is None:
        model_output_path = os.path.join(base_dir, "models", "firewall_risk_rf.pkl")

    if metadata_output_path is None:
        metadata_output_path = os.path.join(base_dir, "models", "model_metadata.json")

    print(f"[*] Loading training dataset from: {dataset_csv}")
    X, y, classes = load_dataset(dataset_csv)
    print(f"    Loaded {X.shape[0]} samples with {X.shape[1]} features.")

    # 80/20 Stratified Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[*] Training RandomForestClassifier on {len(X_train)} samples...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=4,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    print(f"[*] Evaluating on test set ({len(X_test)} samples)...")
    y_pred = model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))

    report = classification_report(
        y_test, y_pred, target_names=classes, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Feature Importance analysis
    importances = model.feature_importances_.tolist()
    feature_importance_map = {
        FeatureExtractor.FEATURE_NAMES[i]: round(importances[i], 4)
        for i in range(len(importances))
    }
    sorted_features = sorted(
        feature_importance_map.items(), key=lambda x: x[1], reverse=True
    )

    print(f"\n=======================================================")
    print(f"  RANDOM FOREST RISK CLASSIFIER - EVALUATION METRICS   ")
    print(f"=======================================================")
    print(f"  Overall Accuracy:      {acc * 100:.2f}%")
    for cls in classes:
        print(f"  Class [{cls:<6}] -> Precision: {report[cls]['precision']:.2f} | "
              f"Recall: {report[cls]['recall']:.2f} | F1: {report[cls]['f1-score']:.2f}")

    print(f"\n  Top 5 Contributing Risk Features (Gini Importance):")
    for name, imp in sorted_features[:5]:
        print(f"    * {name:<30} {imp * 100:.2f}%")
    print(f"=======================================================\n")

    # Serialize Model Artifact
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(model, model_output_path)
    print(f"[+] Serialized model artifact saved to: {model_output_path}")

    # Save Metadata & Metrics
    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 10,
        "classes": classes,
        "feature_names": FeatureExtractor.FEATURE_NAMES,
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "classification_report": report,
        "confusion_matrix": cm,
        "feature_importances": feature_importance_map,
    }

    with open(metadata_output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata & metrics to: {metadata_output_path}")

    return metadata


if __name__ == "__main__":
    train_and_evaluate()
