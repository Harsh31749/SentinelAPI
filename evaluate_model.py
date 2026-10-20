
import sqlite3

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from config import DB_PATH


class TelemetryAutoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 2),
        )
        self.decoder = nn.Sequential(
            nn.Linear(2, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


def main():
    conn = sqlite3.connect(str(DB_PATH))
    try:
        df = pd.read_sql_query(
            """
            SELECT id, ground_truth, payload_size, latency_ms,
                   status_code, actor_hash, is_shadow
            FROM api_logs
            WHERE traffic_source = 'attack_simulator'
              AND request_id IS NOT NULL
              AND TRIM(request_id) != ''
              AND ground_truth IN (0, 1)
            ORDER BY id ASC
            """,
            conn,
        )
    finally:
        conn.close()

    if df.empty or df["ground_truth"].nunique() != 2:
        raise RuntimeError(
            "Need labeled benchmark events from both classes."
        )

    # Reconstruct causal features in chronological order.
    df["is_error"] = (df["status_code"] >= 400).astype(int)
    df["actor_error_rate"] = (
        df.groupby("actor_hash", sort=False)["is_error"]
        .transform(lambda s: s.shift(1).rolling(9, min_periods=1).mean())
        .fillna(0.0)
    )

    feature_cols = [
        "payload_size",
        "latency_ms",
        "actor_error_rate",
    ]
    X = df[feature_cols].fillna(0).to_numpy(dtype=float)
    y = df["ground_truth"].to_numpy(dtype=int)

    # Stratified split keeps both classes in both partitions.
    indices = np.arange(len(df))
    train_idx, test_idx = train_test_split(
        indices,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    # Fit preprocessing only on the training partition.
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X[train_idx])
    X_test = scaler.transform(X[test_idx])

    # Isolation Forest: train only on the training partition.
    forest = IsolationForest(
        n_estimators=100,
        contamination=0.14,
        random_state=42,
    )
    forest.fit(X_train)
    test_if = (forest.predict(X_test) == -1).astype(int)

    # Autoencoder: train only on normal training examples when enough exist.
    torch.manual_seed(42)
    normal_mask = (
        (df.iloc[train_idx]["is_shadow"].to_numpy() == 0)
        & (y[train_idx] == 0)
    )
    X_ae_train = (
        X_train[normal_mask]
        if normal_mask.sum() >= 5
        else X_train[y[train_idx] == 0]
    )

    if len(X_ae_train) < 5:
        raise RuntimeError(
            "Not enough benign training events to fit the autoencoder."
        )

    model = TelemetryAutoencoder(input_dim=len(feature_cols))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.02)
    criterion = nn.MSELoss()
    train_tensor = torch.tensor(X_ae_train, dtype=torch.float32)

    model.train()
    for _ in range(60):
        optimizer.zero_grad()
        loss = criterion(model(train_tensor), train_tensor)
        loss.backward()
        optimizer.step()

    # Select the reconstruction threshold using training benign events only.
    benign_train = torch.tensor(
        X_train[y[train_idx] == 0], dtype=torch.float32
    )
    with torch.no_grad():
        benign_reconstruction = model(benign_train)
        benign_mse = torch.mean(
            (benign_train - benign_reconstruction) ** 2, dim=1
        ).numpy()

        test_tensor = torch.tensor(X_test, dtype=torch.float32)
        test_reconstruction = model(test_tensor)
        test_mse = torch.mean(
            (test_tensor - test_reconstruction) ** 2, dim=1
        ).numpy()

    threshold = float(np.percentile(benign_mse, 85))
    test_ae = (test_mse > threshold).astype(int)

    # Hybrid detector: model outputs plus the existing explicit rules.
    test_df = df.iloc[test_idx].reset_index(drop=True)
    risk = np.full(len(test_idx), 10, dtype=int)
    risk += test_df["is_shadow"].to_numpy(dtype=int) * 55
    risk += test_if * 25
    risk += test_ae * 20
    risk += (
        test_df["actor_error_rate"].to_numpy() >= 0.4
    ).astype(int) * 40
    predictions = (np.minimum(risk, 100) >= 50).astype(int)

    y_test = y[test_idx]
    print(f"Total labeled events: {len(df)}")
    print(f"Training events: {len(train_idx)}")
    print(f"Held-out events: {len(test_idx)}")
    print(f"Training benign events: {(y[train_idx] == 0).sum()}")
    print(f"Training attack events: {(y[train_idx] == 1).sum()}")
    print(f"Test benign events: {(y_test == 0).sum()}")
    print(f"Test attack events: {(y_test == 1).sum()}")
    print("\nConfusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Benign", "Attack"],
            zero_division=0,
        )
    )

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.3f}")
    print(f"Recall: {recall_score(y_test, predictions, zero_division=0):.3f}")
    print(f"F1-score: {f1_score(y_test, predictions, zero_division=0):.3f}")
    print(f"False-positive rate: {fpr:.3f}")
    print("\nNote: held-out simulator evaluation, not production accuracy.")


if __name__ == "__main__":
    main()
