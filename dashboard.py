import json
import sqlite3
from datetime import datetime, timezone
import pandas as pd
import streamlit as st
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from model import run_ai_analysis
from semantic_tester import init_semantic_db, run_semantic_tests

DB_FILE = "telemetry.db"
init_semantic_db()

st.set_page_config(page_title="AI-Based API Security Analyzer", layout="wide")
st.title("🛡️ SentinelAPI — AI-Based API Security Analyzer")
st.caption("Telemetry Ingestion • Shadow API Discovery • Isolation Forest + PyTorch Autoencoder • BOLA/BFLA Fuzzer • Gateway Mitigation")

# Sidebar Controls
st.sidebar.header("⚙️ Analyzer Operations")
if st.sidebar.button("🧠 Run Dual-Model AI Engine", type="primary", use_container_width=True):
    with st.spinner("Running Isolation Forest & PyTorch Autoencoder..."):
        latency = run_ai_analysis()
    st.sidebar.success(f"AI inference completed in {latency} ms")

if st.sidebar.button("🎯 Run BOLA/BFLA Semantic Fuzzer", use_container_width=True):
    with st.spinner("Probing API specification for authorization flaws..."):
        tests_run = run_semantic_tests()
    st.sidebar.warning(f"Executed {tests_run} active authorization tests!")

severity_filter = st.sidebar.multiselect(
    "Filter by Severity",
    options=["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium", "Low"]
)

# Load Telemetry Data
conn = sqlite3.connect(DB_FILE)
df = pd.read_sql_query("SELECT * FROM api_logs ORDER BY id DESC", conn)
sem_df = pd.read_sql_query("SELECT * FROM semantic_test_results ORDER BY id DESC", conn)
policies_df = pd.read_sql_query("SELECT * FROM gateway_policies ORDER BY created_at DESC", conn)
conn.close()

if df.empty:
    st.warning("No API telemetry recorded yet. Start `main.py` and run `attack_script.py` to populate traffic.")
    st.stop()

# Format timestamps to clean IST (Asia/Kolkata)
df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.tz_convert("Asia/Kolkata").dt.strftime("%Y-%m-%d %I:%M:%S %p")
if not sem_df.empty:
    sem_df["timestamp"] = pd.to_datetime(sem_df["timestamp"]).dt.tz_convert("Asia/Kolkata").dt.strftime("%Y-%m-%d %I:%M:%S %p")

# Top Overview Metrics
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total API Events", len(df))
c2.metric("Shadow API Hits", int(df["is_shadow"].sum()))
c3.metric("AI Anomalies (IF + AE)", int(df["is_anomaly"].sum()))
c4.metric("High / Critical Alerts", int((df["risk_score"] >= 50).sum()))
c5.metric("Confirmed BOLA/BFLA Flaws", int(sem_df["vulnerable"].sum()) if not sem_df.empty else 0)

st.divider()

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🚨 Security Alerts",
    "🗺️ Shadow API Inventory",
    "🎯 Semantic Fuzzing (BOLA/BFLA)",
    "🛑 Gateway Mitigation & SIEM",
    "📊 Telemetry & Dual-AI Scores",
    "🧪 Model Evaluation"
])

with tab1:
    st.subheader("Consolidated Risk-Ranked Alerts")
    alerts_df = df[(df["risk_score"] >= 30) & (df["severity"].isin(severity_filter))]
    st.dataframe(
        alerts_df[["id", "timestamp", "severity", "risk_score", "method", "raw_path", "actor_hash", "status_code", "explanation"]],
        use_container_width=True
    )

with tab2:
    st.subheader("Endpoint Discovery & OpenAPI Schema Mapping")
    inventory = df.groupby(["method", "normalized_path", "is_shadow"]).agg(
        total_calls=("id", "count"),
        avg_latency_ms=("latency_ms", "mean"),
        max_risk_score=("risk_score", "max")
    ).reset_index()
    inventory["Schema Status"] = inventory["is_shadow"].map({0: "✅ Documented (OpenAPI)", 1: "⚠️ Shadow API (Undocumented)"})
    st.dataframe(
        inventory[["Schema Status", "method", "normalized_path", "total_calls", "avg_latency_ms", "max_risk_score"]],
        use_container_width=True
    )

with tab3:
    st.subheader("Automated Schema-Aware Authorization Testing (BOLA & BFLA)")
    st.markdown("Tests whether authenticated actors can cross object boundaries (`BOLA`) or invoke administrative functions (`BFLA`).")
    if sem_df.empty:
        st.info("Click **'🎯 Run BOLA/BFLA Semantic Fuzzer'** in the left sidebar to execute live authorization tests.")
    else:
        sem_df["Result"] = sem_df["vulnerable"].map({1: "🔴 VULNERABLE", 0: "🟢 SECURE"})
        st.dataframe(
            sem_df[["id", "timestamp", "Result", "test_type", "method", "endpoint", "actor_used", "target_resource", "status_code", "evidence"]],
            use_container_width=True
        )

with tab4:
    st.subheader("Active API Gateway Policy Control & SIEM Integration")
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("#### 🔒 Active Actor Blocking (Gateway Enforcement)")
        suspicious_actors = df[df["risk_score"] >= 50]["actor_hash"].unique().tolist()
        selected_actor = st.selectbox("Select High-Risk Actor Hash to Block", options=suspicious_actors if suspicious_actors else ["None"])
        block_reason = st.text_input("Mitigation Policy Reason", value="Automated block due to Shadow API / BOLA probing")

        if st.button("🚫 Enforce Gateway Block Policy") and selected_actor != "None":
            conn = sqlite3.connect(DB_FILE)
            conn.execute(
                "INSERT OR REPLACE INTO gateway_policies (actor_hash, action, reason, created_at) VALUES (?, 'BLOCK', ?, ?)",
                (selected_actor, block_reason, datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            conn.close()
            st.success(f"Actor `{selected_actor}` added to Gateway Blocklist! Future requests will receive HTTP 403.")
            st.rerun()

        if not policies_df.empty:
            st.write("**Currently Enforced Gateway Rules:**")
            st.dataframe(policies_df, use_container_width=True)
            if st.button("♻️ Clear All Gateway Blocks"):
                conn = sqlite3.connect(DB_FILE)
                conn.execute("DELETE FROM gateway_policies")
                conn.commit()
                conn.close()
                st.rerun()

    with col_b:
        st.markdown("#### 📡 SIEM Alert Export (Splunk / ELK / Wazuh JSONL)")
        high_alerts = df[df["risk_score"] >= 50].to_dict(orient="records")
        siem_payload = "\n".join([json.dumps({"event_source": "AI_API_Security_Analyzer", **row}) for row in high_alerts])
        st.download_button(
            label="📥 Download SIEM-Compatible JSONL Alert Feed",
            data=siem_payload,
            file_name="siem_security_alerts.jsonl",
            mime="application/json"
        )
        st.code(siem_payload[:600] + ("\n..." if len(siem_payload) > 600 else ""), language="json")

with tab5:
    st.subheader("Telemetry & Dual-Model Scores (Isolation Forest vs Autoencoder)")
    filtered_df = df[df["severity"].isin(severity_filter)]
    st.dataframe(
        filtered_df[[
            "id", "timestamp", "actor_hash", "auth_masked", "method",
            "raw_path", "status_code", "latency_ms", "anomaly_score",
            "autoencoder_mse", "risk_score", "severity"
        ]],
        use_container_width=True
    )

with tab6:
    st.subheader("Benchmark Evaluation & Model Comparison")
    y_true = df["ground_truth"]
    y_pred = (df["risk_score"] >= 50).astype(int)

    if y_true.nunique() > 1:
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Precision", f"{prec:.2%}")
        m2.metric("Recall (Detection Rate)", f"{rec:.2%}")
        m3.metric("F1-Score", f"{f1:.2%}")
        m4.metric("False Positive Rate", f"{fpr:.2%}")

        cm_df = pd.DataFrame(
            [[tp, fn], [fp, tn]],
            index=["Actual Attack / Shadow API", "Actual Benign Traffic"],
            columns=["Predicted High Risk (Alert)", "Predicted Normal"]
        )
        st.table(cm_df)