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
    df["actor_error_rate"] = df.groupby("actor_hash")["is_error"].transform(
        lambda s: s.rolling(10, min_periods=1).mean()
    )

    feature_cols = ["payload_size", "latency_ms", "is_error", "actor_error_rate"]
    X_raw = df[feature_cols].fillna(0).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    # 2. Model A: Unsupervised Isolation Forest
    iso_forest = IsolationForest(n_estimators=100, contamination=0.14, random_state=42)
    if_preds = iso_forest.fit_predict(X_scaled)
    if_scores = iso_forest.decision_function(X_scaled)

    # 3. Model B: Deep Learning Autoencoder (Trained on non-shadow baseline)
    torch.manual_seed(42)
    normal_mask = (df["is_shadow"] == 0) & (df["actor_error_rate"] < 0.3)
    X_train = X_scaled[normal_mask] if normal_mask.sum() >= 5 else X_scaled

    model = TelemetryAutoencoder(input_dim=len(feature_cols))
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.02)

    X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
    model.train()
    for _ in range(60):
        optimizer.zero_grad()
        output = model(X_train_tensor)
        loss = criterion(output, X_train_tensor)
        loss.backward()
        optimizer.step()

    # Calculate Reconstruction Error (MSE) across all traffic
    model.eval()
    with torch.no_grad():
        X_all_tensor = torch.tensor(X_scaled, dtype=torch.float32)
        reconstructed = model(X_all_tensor)
        mse_scores = torch.mean((X_all_tensor - reconstructed) ** 2, dim=1).numpy()

    mse_threshold = float(np.percentile(mse_scores, 85))

    df["anomaly_score"] = np.round(if_scores, 4)
    df["autoencoder_mse"] = np.round(mse_scores, 4)
    df["is_anomaly"] = np.where((if_preds == -1) | (mse_scores > mse_threshold), 1, 0)

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
