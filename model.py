import sqlite3
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import DB_PATH

DB_FILE = str(DB_PATH)


# Define PyTorch Autoencoder Architecture
class TelemetryAutoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16), nn.ReLU(), nn.Linear(16, 2)
        )
        self.decoder = nn.Sequential(
            nn.Linear(2, 16), nn.ReLU(), nn.Linear(16, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


def run_ai_analysis():
    start_time = time.perf_counter()
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM api_logs ORDER BY id ASC", conn)

    if len(df) < 10:
        conn.close()
        return 0.0

    # 1. Behavioral Feature Engineering
    
    df["is_error"] = (df["status_code"] >= 400).astype(int)

    # Use only the previous 9 requests from the same actor.
    # The current request's outcome is excluded.
    df["actor_error_rate"] = (
        df.groupby("actor_hash", sort=False)["is_error"]
        .transform(
            lambda s: s.shift(1).rolling(9, min_periods=1).mean()
        )
        .fillna(0.0)
    )


    feature_cols = ["payload_size", "latency_ms", "is_error", "actor_error_rate"]
    X_raw = df[feature_cols].fillna(0).values

    # Chronological split: earlier events train the models;
    # later events are held out for evaluation.
    split_idx = int(len(df) * 0.8)
    split_idx = max(5, min(split_idx, len(df) - 1))

    X_train_raw = X_raw[:split_idx]
    X_test_raw = X_raw[split_idx:]

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)


    
    # 2. Model A: Fit Isolation Forest on training data only
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.14,
        random_state=42,
    )
    iso_forest.fit(X_train_scaled)

    # Score both partitions without refitting the model.
    if_preds = np.concatenate(
        [
            iso_forest.predict(X_train_scaled),
            iso_forest.predict(X_test_scaled),
        ]
    )
    if_scores = np.concatenate(
        [
            iso_forest.decision_function(X_train_scaled),
            iso_forest.decision_function(X_test_scaled),
        ]
    )

    # 3. Model B: Autoencoder trained on training-period baseline only
    torch.manual_seed(42)

    train_df = df.iloc[:split_idx]
    normal_mask = (
        (train_df["is_shadow"] == 0)
        & (train_df["actor_error_rate"] < 0.3)
    )

    X_autoencoder_train = (
        X_train_scaled[normal_mask.to_numpy()]
        if normal_mask.sum() >= 5
        else X_train_scaled
    )

    model = TelemetryAutoencoder(input_dim=len(feature_cols))
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.02)

    X_train_tensor = torch.tensor(
        X_autoencoder_train, dtype=torch.float32
    )

    model.train()
    for _ in range(60):
        optimizer.zero_grad()
        output = model(X_train_tensor)
        loss = criterion(output, X_train_tensor)
        loss.backward()
        optimizer.step()

    # Calculate reconstruction errors without training on the test partition.
    model.eval()
    with torch.no_grad():
        X_train_tensor_all = torch.tensor(
            X_train_scaled, dtype=torch.float32
        )
        X_test_tensor = torch.tensor(
            X_test_scaled, dtype=torch.float32
        )

        train_reconstructed = model(X_train_tensor_all)
        test_reconstructed = model(X_test_tensor)

        train_mse = torch.mean(
            (X_train_tensor_all - train_reconstructed) ** 2, dim=1
        ).numpy()
        test_mse = torch.mean(
            (X_test_tensor - test_reconstructed) ** 2, dim=1
        ).numpy()

    mse_scores = np.concatenate([train_mse, test_mse])

    # Threshold is derived from training errors only.
    mse_threshold = float(np.percentile(train_mse, 85))

    df["anomaly_score"] = np.round(if_scores, 4)
    df["autoencoder_mse"] = np.round(mse_scores, 4)
    df["is_anomaly"] = np.where(
        (if_preds == -1) | (mse_scores > mse_threshold), 1, 0
    )


    # 4. Hybrid Risk Scoring & Explainable Alert Generation
    risk_scores, severities, explanations = [], [], []

    for idx, row in df.iterrows():
        score = 10
        reasons = []

        if row["is_shadow"] == 1:
            score += 55
            reasons.append(
                f"Undocumented Shadow API ({row['method']} {row['normalized_path']})"
            )

        if if_preds[idx] == -1:
            score += 25
            reasons.append(f"Isolation Forest outlier (score: {row['anomaly_score']})")

        if row["autoencoder_mse"] > mse_threshold:
            score += 20
            reasons.append(
                f"Autoencoder high reconstruction error (MSE: {row['autoencoder_mse']})"
            )

        if row["actor_error_rate"] >= 0.4:
            score += 40
            reasons.append(
                f"Sustained 4xx/5xx probing "
                f"({int(row['actor_error_rate'] * 100)}% error rate)"
            )

        score = min(score, 100)
        sev = (
            "Critical"
            if score >= 75
            else "High"
            if score >= 50
            else "Medium"
            if score >= 30
            else "Low"
        )

        risk_scores.append(score)
        severities.append(sev)
        explanations.append(
            "; ".join(reasons) if reasons else "Normal baseline activity"
        )

    df["risk_score"] = risk_scores
    df["severity"] = severities
    df["explanation"] = explanations

    cursor = conn.cursor()
    for _, row in df.iterrows():
        cursor.execute(
            """
            UPDATE api_logs
            SET anomaly_score = ?, autoencoder_mse = ?, is_anomaly = ?,
                risk_score = ?, severity = ?, explanation = ?
            WHERE id = ?
        """,
            (
                float(row["anomaly_score"]),
                float(row["autoencoder_mse"]),
                int(row["is_anomaly"]),
                int(row["risk_score"]),
                row["severity"],
                row["explanation"],
                int(row["id"]),
            ),
        )
    conn.commit()
    conn.close()

    return round((time.perf_counter() - start_time) * 1000, 2)


if __name__ == "__main__":
    ms = run_ai_analysis()
    print(f"Dual-model AI analysis completed in {ms} ms.")
