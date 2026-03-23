"""Train and export a multiclass Random Forest attack classifier."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, top_k_accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.preprocessing.cicids_feature_schema import FEATURE_COLUMNS, LABEL_COLUMN, ensure_feature_frame


def build_stratified_sample(features: pd.DataFrame, labels: np.ndarray) -> tuple[pd.DataFrame, np.ndarray]:
    frame = features.copy()
    frame["_label"] = labels
    samples = []

    for label_value, group in frame.groupby("_label"):
        sample_size = min(len(group), max(2000, int(len(group) * 0.2)))
        sampled_group = group.sample(n=sample_size, random_state=42)
        samples.append(sampled_group)

    sampled_train = pd.concat(samples, ignore_index=True)
    sampled_labels = sampled_train.pop("_label").to_numpy(dtype=np.int32)
    return sampled_train.astype(np.float32), sampled_labels


def main() -> None:
    data_path = ROOT / "data" / "raw" / "cicids2017_cleaned.csv"
    models_dir = ROOT / "saved_models"
    reports_dir = ROOT / "results" / "reports"

    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading dataset from {data_path}...")
    dataframe = pd.read_csv(data_path, usecols=FEATURE_COLUMNS + [LABEL_COLUMN], low_memory=False)
    features = ensure_feature_frame(dataframe[FEATURE_COLUMNS])
    labels = dataframe[LABEL_COLUMN].astype(str)

    label_encoder = LabelEncoder()
    encoded_labels = label_encoder.fit_transform(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        features,
        encoded_labels,
        test_size=0.2,
        random_state=42,
        stratify=encoded_labels,
    )

    if len(X_train) > 350_000:
        X_train, y_train = build_stratified_sample(X_train, y_train)
        print(f"Using stratified training sample with {len(X_train):,} rows for faster iteration.")

    classifier = RandomForestClassifier(
        n_estimators=220,
        max_depth=28,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )

    print("Training multiclass Random Forest...")
    classifier.fit(X_train, y_train)

    probabilities = classifier.predict_proba(X_test)
    predicted = np.argmax(probabilities, axis=1)

    accuracy = accuracy_score(y_test, predicted)
    macro_f1 = f1_score(y_test, predicted, average="macro")
    weighted_f1 = f1_score(y_test, predicted, average="weighted")
    top3 = top_k_accuracy_score(y_test, probabilities, k=3, labels=np.arange(len(label_encoder.classes_)))

    metadata = {
        "model_type": "random_forest_multiclass",
        "label_column": LABEL_COLUMN,
        "feature_columns": FEATURE_COLUMNS,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "class_names": [str(name) for name in label_encoder.classes_],
        "metrics": {
            "accuracy": round(float(accuracy), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "top_3_accuracy": round(float(top3), 4),
        },
    }

    joblib.dump(classifier, models_dir / "rf_multiclass_model.pkl")
    joblib.dump(label_encoder, models_dir / "attack_label_encoder.pkl")
    (models_dir / "rf_multiclass_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (reports_dir / "rf_multiclass_report.txt").write_text(
        classification_report(
            y_test,
            predicted,
            target_names=[str(name) for name in label_encoder.classes_],
            zero_division=0,
        ),
        encoding="utf-8",
    )
    (reports_dir / "rf_multiclass_metrics.json").write_text(json.dumps(metadata["metrics"], indent=2), encoding="utf-8")

    print("Training complete.")
    print(json.dumps(metadata["metrics"], indent=2))


if __name__ == "__main__":
    main()
