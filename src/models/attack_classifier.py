"""Runtime multiclass attack prediction helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from src.preprocessing.cicids_feature_schema import FEATURE_COLUMNS, ensure_feature_frame


@dataclass
class AttackPrediction:
    predicted_attack_type: str
    attack_confidence: float
    confidence_margin: float
    is_low_confidence: bool
    top_3_attack_types: list[dict[str, float]]
    classification_source: str


class AttackTypeClassifier:
    """Wrapper around the exported multiclass model and label metadata."""

    LOW_CONFIDENCE_THRESHOLD = 0.75
    LOW_MARGIN_THRESHOLD = 0.20

    def __init__(
        self,
        model_path: str | Path,
        label_encoder_path: str | Path,
        metadata_path: str | Path,
    ) -> None:
        self.model_path = Path(model_path)
        self.label_encoder_path = Path(label_encoder_path)
        self.metadata_path = Path(metadata_path)

        self.model = joblib.load(self.model_path)
        self.label_encoder = joblib.load(self.label_encoder_path)
        self.metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        self.feature_columns = self.metadata.get("feature_columns", FEATURE_COLUMNS)

    @classmethod
    def from_saved_models(cls, base_dir: str | Path) -> "AttackTypeClassifier":
        base_path = Path(base_dir)
        return cls(
            model_path=base_path / "rf_multiclass_model.pkl",
            label_encoder_path=base_path / "attack_label_encoder.pkl",
            metadata_path=base_path / "rf_multiclass_metadata.json",
        )

    def predict(self, feature_data: pd.DataFrame | dict | list[dict[str, Any]]) -> list[AttackPrediction]:
        features = ensure_feature_frame(feature_data)
        probabilities = self.model.predict_proba(features)
        top_indices = np.argsort(probabilities, axis=1)[:, ::-1][:, :3]

        predictions: list[AttackPrediction] = []
        for row_index, class_indexes in enumerate(top_indices):
            winning_index = int(class_indexes[0])
            winning_label = str(self.label_encoder.inverse_transform([winning_index])[0])
            winning_probability = float(probabilities[row_index, winning_index])
            runner_up_probability = float(probabilities[row_index, int(class_indexes[1])]) if len(class_indexes) > 1 else 0.0
            margin = winning_probability - runner_up_probability

            top_predictions = []
            for class_index in class_indexes:
                label = str(self.label_encoder.inverse_transform([int(class_index)])[0])
                probability = float(probabilities[row_index, int(class_index)])
                top_predictions.append(
                    {
                        "attack_type": label,
                        "probability": round(probability, 4),
                    }
                )

            predictions.append(
                AttackPrediction(
                    predicted_attack_type=winning_label,
                    attack_confidence=round(winning_probability, 4),
                    confidence_margin=round(margin, 4),
                    is_low_confidence=winning_probability < self.LOW_CONFIDENCE_THRESHOLD or margin < self.LOW_MARGIN_THRESHOLD,
                    top_3_attack_types=top_predictions,
                    classification_source=self.metadata.get("model_type", "random_forest_multiclass"),
                )
            )

        return predictions

    def enrich_alert(self, alert: dict[str, Any], feature_row: dict[str, Any] | pd.Series) -> dict[str, Any]:
        final_decision = alert.get("final_decision", alert.get("decision", "NORMAL"))
        if final_decision == "NORMAL":
            alert.update(
                {
                    "predicted_attack_type": "Normal Traffic",
                    "attack_confidence": 1.0,
                    "confidence_margin": 1.0,
                    "is_low_confidence": False,
                    "top_3_attack_types": [{"attack_type": "Normal Traffic", "probability": 1.0}],
                    "classification_source": "not_applicable_normal_flow",
                }
            )
            return alert

        enriched = self.predict(pd.DataFrame([feature_row]))[0]
        alert.update(
            {
                "predicted_attack_type": enriched.predicted_attack_type,
                "attack_confidence": enriched.attack_confidence,
                "confidence_margin": enriched.confidence_margin,
                "is_low_confidence": enriched.is_low_confidence,
                "top_3_attack_types": enriched.top_3_attack_types,
                "classification_source": enriched.classification_source,
            }
        )
        return alert
