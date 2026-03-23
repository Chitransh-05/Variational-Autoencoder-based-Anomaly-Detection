"""Verify exported multiclass model artifacts and confidence outputs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.models.attack_classifier import AttackTypeClassifier
from src.preprocessing.cicids_feature_schema import FEATURE_COLUMNS, LABEL_COLUMN, ensure_feature_frame


def main() -> None:
    data_path = ROOT / "data" / "raw" / "cicids2017_cleaned.csv"
    reports_dir = ROOT / "results" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    dataframe = pd.read_csv(data_path, usecols=FEATURE_COLUMNS + [LABEL_COLUMN], low_memory=False)
    features = ensure_feature_frame(dataframe[FEATURE_COLUMNS])
    labels = dataframe[LABEL_COLUMN].astype(str)

    _, X_test, _, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    classifier = AttackTypeClassifier.from_saved_models(ROOT / "saved_models")
    predictions = classifier.predict(X_test)

    predicted_labels = [item.predicted_attack_type for item in predictions]
    top3_hit = [
        truth in {candidate["attack_type"] for candidate in item.top_3_attack_types}
        for truth, item in zip(y_test.tolist(), predictions)
    ]
    confidences = [item.attack_confidence for item in predictions]
    margins = [item.confidence_margin for item in predictions]
    low_confidence_flags = [item.is_low_confidence for item in predictions]

    correct_scores = [score for score, truth, pred in zip(confidences, y_test.tolist(), predicted_labels) if truth == pred]
    incorrect_scores = [score for score, truth, pred in zip(confidences, y_test.tolist(), predicted_labels) if truth != pred]
    correct_margins = [margin for margin, truth, pred in zip(margins, y_test.tolist(), predicted_labels) if truth == pred]
    incorrect_margins = [margin for margin, truth, pred in zip(margins, y_test.tolist(), predicted_labels) if truth != pred]

    summary = {
        "verification_rows": int(len(X_test)),
        "accuracy": round(float(accuracy_score(y_test, predicted_labels)), 4),
        "top_3_hit_rate": round(float(sum(top3_hit) / len(top3_hit)), 4),
        "mean_prediction_confidence": round(float(sum(confidences) / len(confidences)), 4),
        "median_prediction_confidence": round(float(pd.Series(confidences).median()), 4),
        "mean_confidence_margin": round(float(sum(margins) / len(margins)), 4),
        "low_confidence_rate": round(float(sum(low_confidence_flags) / len(low_confidence_flags)), 4),
        "confidence_by_correctness": {
            "correct_mean": round(float(pd.Series(correct_scores).mean()), 4),
            "incorrect_mean": round(float(pd.Series(incorrect_scores).mean()), 4),
            "correct_margin_mean": round(float(pd.Series(correct_margins).mean()), 4),
            "incorrect_margin_mean": round(float(pd.Series(incorrect_margins).mean()), 4),
        },
        "sample_predictions": [
            {
                "actual_attack_type": truth,
                "predicted_attack_type": item.predicted_attack_type,
                "attack_confidence": item.attack_confidence,
                "confidence_margin": item.confidence_margin,
                "is_low_confidence": item.is_low_confidence,
                "top_3_attack_types": item.top_3_attack_types,
            }
            for truth, item in zip(y_test.tolist()[:10], predictions[:10])
        ],
    }

    (reports_dir / "rf_multiclass_validation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
