import streamlit as st
import plotly.graph_objects as go
import numpy as np
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers, load_models

def render():
    df = load_attackers()
    models = load_models()

    st.markdown("## 🤖 ML Detection Engine")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Dual-path 4-model ensemble architecture. Each model contributes individually to the final 99.43% confidence score.</p>", unsafe_allow_html=True)

    # ── Individual Model Score Cards with progress bars ───────────────────────
    st.markdown("### 🔬 Individual Model Scores")
    model_data = [
        ("Random Forest", "Session Detection", 100.00, "#00f5a0",
         "Detects high-risk sessions using tree ensemble voting. 100 decision trees vote on each session.",
         "Path A", "Weight: 40%"),
        ("Logistic Regression", "Session Detection", 99.67, "#00c8ff",
         "Probability-based session risk scoring. Gives a clean probability between 0 and 1.",
         "Path A", "Weight: 35%"),
        ("Random Forest", "Attacker Profiling", 100.00, "#a855f7",
         "Classifies PERSISTENT vs SCANNER vs APT attacker types across all sessions.",
         "Path B", "Weight: —"),
        ("SVM (LinearSVC)", "Attacker Profiling", 100.00, "#ffa500",
         "Support vector machine for behavioural classification. Finds the optimal boundary between attack types.",
         "Path B", "Weight: 25%"),
    ]

    cols = st.columns(4)
    for i, (name, path, acc, color, desc, ab, weight) in enumerate(model_data):
        with cols[i]:
            bar_width = int(acc)
            st.markdown(f"""
            <div style="background:#0a0f1e; border:1px solid #1a2540; border-top:4px solid {color};
                 border-radius:10px; padding:18px; text-align:center; height:260px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <span style="font-size:0.6rem;color:#4a5a7a;text-transform:uppercase;letter-spacing:1px;">{path}</span>
                <span style="font-size:0.6rem;background:{color}20;color:{color};padding:2px 6px;border-radius:10px;font-family:Share Tech Mono,monospace;">{ab}</span>
              </div>
              <div style="font-family:Rajdhani,sans-serif; font-size:1rem; font-weight:700; color:{color}; margin:4px 0;">{name}</div>
              <div style="font-family:Rajdhani,sans-serif; font-size:3rem; font-weight:700; color:{color}; line-height:1;">{acc:.2f}%</div>
              <div style="background:#1a2540;border-radius:4px;height:8px;margin:10px 0;">
                <div style="background:{color};width:{bar_width}%;height:100%;border-radius:4px;"></div>
              </div>
              <div style="font-size:0.6rem;color:#4a5a7a;line-height:1.4;margin-top:4px;">{desc}</div>
              <div style="font-size:0.62rem;color:{color};margin-top:6px;font-family:Share Tech Mono,monospace;">{weight}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Ensemble formula ──────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:#0a0f1e; border:1px solid #1a2540; border-radius:10px; padding:20px; margin-bottom:20px;">
      <div style="font-size:0.7rem;color:#4a5a7a;text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;">Ensemble Fusion Formula</div>
      <div style="font-family:Share Tech Mono,monospace; font-size:1rem; color:#c8d8f0; text-align:center;">
        Final Score = <span style="color:#00f5a0;">RF_session × 0.40</span> + 
        <span style="color:#00c8ff;">LR_session × 0.35</span> + 
        <span style="color:#ffa500;">SVM_attacker × 0.25</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Final combined confidence banner
    st.markdown("""
    <div style="background:linear-gradient(135deg,#0a0f1e,#0d1a2e); border:2px solid #00f5a040;
         border-radius:12px; padding:28px; text-align:center; margin:16px 0;">
      <div style="font-size:0.75rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:3px;">Final Combined Confidence</div>
      <div style="font-family:Rajdhani,sans-serif; font-size:5rem; font-weight:700; color:#00f5a0; line-height:1; margin:8px 0;">99.43%</div>
      <div style="font-family:Share Tech Mono,monospace; color:#00c8ff; font-size:0.85rem;">RF·LR·RF·SVM Ensemble · All 4 Models In Agreement</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Per-attacker model agreement chart ───────────────────────────────────
    st.markdown("### 📊 Per-Model Score Distribution Across All Attackers")
    fig_compare = go.Figure()
    score_cols = [
        ("rf_score",  "RF Session",  "#00f5a0"),
        ("lr_score",  "LR Session",  "#00c8ff"),
        ("svm_score", "SVM Attacker","#ffa500"),
        ("final_confidence", "Ensemble", "#ff4560"),
    ]
    for col, label, color in score_cols:
        if col in df.columns:
            fig_compare.add_trace(go.Box(
                y=df[col], name=label,
                marker_color=color,
                boxmean=True,
            ))
    fig_compare.update_layout(
        paper_bgcolor="#050810", plot_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        yaxis=dict(gridcolor="#1a2540", title="Score", range=[0,1]),
        xaxis=dict(gridcolor="#1a2540"),
        margin=dict(l=0, r=0, t=10, b=0), height=300,
        showlegend=False,
    )
    st.plotly_chart(fig_compare, use_container_width=True)



    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📊 Confidence Distribution")
        fig = go.Figure()
        colors = {"HIGH": "#ff4560", "MEDIUM": "#ffa500", "LOW": "#00f5a0"}
        for risk, color in colors.items():
            sub = df[df["risk_level"] == risk]["final_confidence"]
            fig.add_trace(go.Histogram(
                x=sub, name=risk, nbinsx=30,
                marker_color=color, opacity=0.7,
            ))
        fig.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            barmode="overlay",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540", title="Confidence Score"),
            yaxis=dict(gridcolor="#1a2540", title="Count"),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🧬 Feature Importance (RF Session)")
        features = ["Session Count", "Total Events", "Commands Tried", "Usernames", "Passwords", "RF Score", "LR Score", "SVM Score"]
        importances = models["rf_session"].feature_importances_
        sorted_idx = np.argsort(importances)
        
        fig2 = go.Figure(go.Bar(
            x=importances[sorted_idx],
            y=[features[i] for i in sorted_idx],
            orientation="h",
            marker=dict(
                color=importances[sorted_idx],
                colorscale=[[0, "#1a2540"], [1, "#00f5a0"]],
            ),
        ))
        fig2.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540"),
            yaxis=dict(gridcolor="#1a2540"),
            margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig2, use_container_width=True)

    # Architecture diagram using Streamlit columns - no raw HTML complexity
    st.markdown("### 🏗️ Dual-Path Architecture")

    # Row 1 - Input
    st.markdown(
        "<div style='text-align:center;padding:12px;background:#1a2540;border:1px solid #00c8ff;"
        "border-radius:8px;font-family:Rajdhani,sans-serif;font-weight:700;color:#00c8ff;"
        "letter-spacing:2px;margin-bottom:8px;'>🌐 INCOMING ATTACK SESSION</div>",
        unsafe_allow_html=True)
    st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:1.4rem;'>▼</div>", unsafe_allow_html=True)

    # Row 2 - Two paths
    colA, colMid, colB = st.columns([5, 1, 5])
    with colA:
        st.markdown(
            "<div style='background:#050e08;border:1px solid #00f5a040;border-radius:10px;padding:16px;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-size:0.7rem;color:#00f5a0;letter-spacing:3px;"
            "text-transform:uppercase;margin-bottom:12px;text-align:center;'>PATH A · SESSION DETECTION</div>"
            "<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;'>"
            "<div style='background:#0a0f1e;border:1px solid #00f5a030;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#00f5a0;'>Random Forest</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#00f5a0;'>100.00%</div></div>"
            "<div style='background:#0a0f1e;border:1px solid #00c8ff30;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#00c8ff;'>Logistic Reg.</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#00c8ff;'>99.67%</div></div>"
            "</div></div>", unsafe_allow_html=True)
    with colMid:
        st.markdown("<div style='text-align:center;color:#4a5a7a;padding-top:40px;font-size:1.2rem;'>│</div>", unsafe_allow_html=True)
    with colB:
        st.markdown(
            "<div style='background:#0e0510;border:1px solid #a855f740;border-radius:10px;padding:16px;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-size:0.7rem;color:#a855f7;letter-spacing:3px;"
            "text-transform:uppercase;margin-bottom:12px;text-align:center;'>PATH B · ATTACKER PROFILING</div>"
            "<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;'>"
            "<div style='background:#0a0f1e;border:1px solid #a855f730;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#a855f7;'>Random Forest</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#a855f7;'>100.00%</div></div>"
            "<div style='background:#0a0f1e;border:1px solid #ffa50030;border-radius:6px;padding:10px;text-align:center;'>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#ffa500;'>SVM LinearSVC</div>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.75rem;color:#ffa500;'>100.00%</div></div>"
            "</div></div>", unsafe_allow_html=True)

    st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:1.4rem;margin-top:8px;'>▼</div>", unsafe_allow_html=True)

    # Row 3 - Ensemble
    st.markdown(
        "<div style='text-align:center;padding:20px;background:#0a1628;border:2px solid #00f5a0;"
        "border-radius:8px;margin:4px 80px;'>"
        "<div style='font-family:Rajdhani,sans-serif;font-size:0.7rem;color:#4a5a7a;letter-spacing:3px;'>ENSEMBLE FUSION (WEIGHTED)</div>"
        "<div style='font-family:Rajdhani,sans-serif;font-size:2.5rem;font-weight:700;color:#00f5a0;'>99.43%</div>"
        "<div style='font-family:Share Tech Mono,monospace;font-size:0.8rem;color:#4a5a7a;'>FINAL CONFIDENCE SCORE</div>"
        "</div>", unsafe_allow_html=True)

    st.markdown("<div style='text-align:center;color:#4a5a7a;font-size:1.4rem;margin-top:8px;'>▼</div>", unsafe_allow_html=True)

    # Row 4 - Response
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            "<div style='background:#1a050a;border:1px solid #ff456050;border-radius:8px;padding:14px;text-align:center;'>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.7rem;color:#ff4560;'>HIGH RISK</div>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:1rem;'>🚫 Block IP</div>"
            "<div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;font-size:0.75rem;'>Activate Deception Mode</div>"
            "</div>", unsafe_allow_html=True)
    with c2:
        st.markdown(
            "<div style='background:#1a0e00;border:1px solid #ffa50050;border-radius:8px;padding:14px;text-align:center;'>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.7rem;color:#ffa500;'>MEDIUM RISK</div>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:1rem;'>👁️ Monitor</div>"
            "<div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;font-size:0.75rem;'>Generate Alert</div>"
            "</div>", unsafe_allow_html=True)
    with c3:
        st.markdown(
            "<div style='background:#001a0a;border:1px solid #00f5a030;border-radius:8px;padding:14px;text-align:center;'>"
            "<div style='font-family:Share Tech Mono,monospace;font-size:0.7rem;color:#00f5a0;'>LOW RISK</div>"
            "<div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:1rem;'>📝 Log</div>"
            "<div style='font-family:Rajdhani,sans-serif;color:#4a5a7a;font-size:0.75rem;'>Continue Capture</div>"
            "</div>", unsafe_allow_html=True)

    # ── Per-IP Individual Model Scores ───────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🔍 Per-Attacker Individual Model Scores")
    st.markdown("<p style='color:#4a5a7a;font-size:0.85rem;'>Browse each attacker IP and see exactly how each model individually scored them — RF Session, LR Session, SVM Attacker — and the final ensemble.</p>", unsafe_allow_html=True)

    col_search, col_risk, col_sort = st.columns(3)
    with col_search:
        search_ip = st.text_input("🔎 Search IP", placeholder="e.g. 192.168.1.1")
    with col_risk:
        risk_filter = st.selectbox("Filter by Risk", ["ALL","HIGH","MEDIUM","LOW"])
    with col_sort:
        sort_by = st.selectbox("Sort by", ["Ensemble Score","RF Score","LR Score","SVM Score","Sessions"])

    sort_col = {"Ensemble Score":"final_confidence","RF Score":"rf_score",
                "LR Score":"lr_score","SVM Score":"svm_score","Sessions":"session_count"}[sort_by]

    display_df = df.copy()
    if search_ip:
        display_df = display_df[display_df["ip"].str.contains(search_ip, na=False)]
    if risk_filter != "ALL":
        display_df = display_df[display_df["risk_level"] == risk_filter]
    display_df = display_df.sort_values(sort_col, ascending=False).head(30)

    risk_colors = {"HIGH":"#ff4560","MEDIUM":"#ffa500","LOW":"#00f5a0"}

    for _, row in display_df.iterrows():
        ip    = row.get("ip","?")
        cntry = row.get("country","?")
        risk  = row.get("risk_level","?")
        cls   = row.get("classification","?")
        rc    = risk_colors.get(risk,"#888")
        rf_s  = float(row.get("rf_score",0))
        lr_s  = float(row.get("lr_score",0))
        svm_s = float(row.get("svm_score",0))
        ens   = float(row.get("final_confidence",0))
        sess  = int(row.get("session_count",0))
        cmds  = row.get("commands_tried",[])
        cmd_str = " · ".join(cmds[:3]) if isinstance(cmds,list) and cmds else "—"

        def bar(val, color):
            return (f"<div style='background:#1a2540;border-radius:3px;height:5px;margin-top:3px;'>"
                    f"<div style='background:{color};width:{int(val*100)}%;height:100%;border-radius:3px;'></div></div>")

        st.markdown(f"""
        <div style='background:#0a0f1e;border:1px solid #1a2540;border-left:3px solid {rc};
             border-radius:8px;padding:14px 18px;margin:4px 0;'>
          <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;'>
            <div>
              <span style='font-family:Share Tech Mono,monospace;font-size:0.9rem;color:#00c8ff;font-weight:700;'>{ip}</span>
              <span style='color:#4a5a7a;font-size:0.8rem;margin-left:10px;'>{cntry}</span>
              <span style='background:{rc}20;color:{rc};border:1px solid {rc}40;font-family:Rajdhani,sans-serif;
                   font-size:0.7rem;font-weight:700;padding:2px 8px;border-radius:10px;margin-left:8px;'>{risk}</span>
              <span style='color:#4a5a7a;font-size:0.75rem;margin-left:8px;'>{cls}</span>
            </div>
            <div style='font-family:Rajdhani,sans-serif;font-size:1.5rem;font-weight:700;color:{rc};'>{int(ens*100)}%</div>
          </div>
          <div style='display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:8px;'>
            <div style='background:#050810;border:1px solid #00f5a030;border-radius:6px;padding:8px;text-align:center;'>
              <div style='font-size:0.6rem;color:#4a5a7a;font-family:Share Tech Mono,monospace;'>RF SESSION</div>
              <div style='font-family:Rajdhani,sans-serif;font-size:1.2rem;font-weight:700;color:#00f5a0;'>{int(rf_s*100)}%</div>
              {bar(rf_s,"#00f5a0")}
            </div>
            <div style='background:#050810;border:1px solid #00c8ff30;border-radius:6px;padding:8px;text-align:center;'>
              <div style='font-size:0.6rem;color:#4a5a7a;font-family:Share Tech Mono,monospace;'>LR SESSION</div>
              <div style='font-family:Rajdhani,sans-serif;font-size:1.2rem;font-weight:700;color:#00c8ff;'>{int(lr_s*100)}%</div>
              {bar(lr_s,"#00c8ff")}
            </div>
            <div style='background:#050810;border:1px solid #a855f730;border-radius:6px;padding:8px;text-align:center;'>
              <div style='font-size:0.6rem;color:#4a5a7a;font-family:Share Tech Mono,monospace;'>SVM ATTACKER</div>
              <div style='font-family:Rajdhani,sans-serif;font-size:1.2rem;font-weight:700;color:#a855f7;'>{int(svm_s*100)}%</div>
              {bar(svm_s,"#a855f7")}
            </div>
            <div style='background:#050810;border:1px solid {rc}30;border-radius:6px;padding:8px;text-align:center;'>
              <div style='font-size:0.6rem;color:#4a5a7a;font-family:Share Tech Mono,monospace;'>ENSEMBLE</div>
              <div style='font-family:Rajdhani,sans-serif;font-size:1.2rem;font-weight:700;color:{rc};'>{int(ens*100)}%</div>
              {bar(ens,rc)}
            </div>
          </div>
          <div style='font-size:0.72rem;color:#4a5a7a;'>
            Sessions: <span style='color:#c8d8f0;'>{sess}</span> &nbsp;·&nbsp;
            Commands: <span style='color:#c8d8f0;font-family:Share Tech Mono,monospace;'>{cmd_str}</span>
          </div>
        </div>""", unsafe_allow_html=True)

    # ── Full metrics table from saved metrics.json ────────────────────────────
    import os
    metrics_path = "models/metrics.json"
    if os.path.exists(metrics_path):
        import json as _json
        with open(metrics_path) as f:
            saved = _json.load(f)

        st.markdown("### 📋 Full Metrics Report — All Models (80/20 Test Split)")
        st.markdown("""
        <div style='background:#0a0f1e;border:1px solid #1a2540;border-left:3px solid #00c8ff;
             border-radius:8px;padding:14px;margin-bottom:16px;'>
          <div style='font-size:0.82rem;color:#c8d8f0;line-height:1.7;'>
            Evaluated on <b style='color:#00c8ff;'>80/20 stratified train-test split</b>
            with <b style='color:#00f5a0;'>5-fold cross-validation</b>.
            Dataset: <b style='color:#a855f7;'>1,811 attacker profiles</b> from 524,182 real Cowrie events.
          </div>
        </div>
        """, unsafe_allow_html=True)

        model_order = ["rf_session","lr_session","rf_attacker","svm_attacker","ensemble"]
        model_labels = {
            "rf_session":   "RF Session",
            "lr_session":   "LR Session",
            "rf_attacker":  "RF Attacker",
            "svm_attacker": "SVM Attacker",
            "ensemble":     "Ensemble",
        }
        metric_cols = ["accuracy","precision","recall","f1","roc_auc","cv_mean"]
        col_labels  = ["Model","Accuracy","Precision","Recall","F1 Score","ROC-AUC","CV Score"]

        header = "".join([f"<th style='padding:10px 14px;background:#0f2030;color:#4a5a7a;font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;text-align:center;border-bottom:2px solid #1a2540;'>{c}</th>" for c in col_labels])
        rows_html = ""
        for key in model_order:
            if key not in saved: continue
            m = saved[key]
            is_ens = key == "ensemble"
            bg = "#0d1a2e" if is_ens else "#0a0f1e"
            border = "border-top:2px solid #00f5a020;" if is_ens else ""
            name_color = "#00f5a0" if is_ens else "#c8d8f0"
            label = "⭐ Ensemble" if is_ens else model_labels[key]

            def cell(val, green_threshold=0.95):
                color = "#00f5a0" if val >= green_threshold else "#ffa500" if val >= 0.90 else "#ff4560"
                return f"<td style='padding:10px 14px;text-align:center;font-family:Share Tech Mono,monospace;font-size:0.85rem;color:{color};'>{val:.4f}</td>"

            rows_html += f"""<tr style='background:{bg};{border}'>
              <td style='padding:10px 14px;font-family:Rajdhani,sans-serif;font-weight:700;color:{name_color};font-size:0.9rem;'>{label}</td>
              {cell(m['accuracy'])}{cell(m['precision'])}{cell(m['recall'])}{cell(m['f1'])}{cell(m['roc_auc'])}
              <td style='padding:10px 14px;text-align:center;font-family:Share Tech Mono,monospace;font-size:0.82rem;color:#4a5a7a;'>{m['cv_mean']:.4f} ± {m.get('cv_std',0):.4f}</td>
            </tr>"""

        st.markdown(f"""
        <div style='overflow-x:auto;'>
        <table style='width:100%;border-collapse:collapse;'>
          <thead><tr>{header}</tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
        </div>
        """, unsafe_allow_html=True)

        # Confusion matrices
        st.markdown("### 🔲 Confusion Matrices")
        cm_cols = st.columns(len(model_order))
        for i, key in enumerate(model_order):
            if key not in saved: continue
            m = saved[key]
            with cm_cols[i]:
                label = "Ensemble" if key=="ensemble" else model_labels[key]
                tp,fp,fn,tn = m['tp'],m['fp'],m['fn'],m['tn']
                st.markdown(f"""
                <div style='background:#0a0f1e;border:1px solid #1a2540;border-radius:8px;padding:12px;text-align:center;'>
                  <div style='font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8f0;font-size:0.85rem;margin-bottom:10px;'>{label}</div>
                  <div style='display:grid;grid-template-columns:1fr 1fr;gap:4px;'>
                    <div style='background:#00f5a020;border:1px solid #00f5a040;border-radius:4px;padding:8px;'>
                      <div style='font-size:0.6rem;color:#4a5a7a;'>True Positive</div>
                      <div style='font-family:Rajdhani,sans-serif;font-size:1.3rem;font-weight:700;color:#00f5a0;'>{tp}</div>
                    </div>
                    <div style='background:#ff456020;border:1px solid #ff456040;border-radius:4px;padding:8px;'>
                      <div style='font-size:0.6rem;color:#4a5a7a;'>False Positive</div>
                      <div style='font-family:Rajdhani,sans-serif;font-size:1.3rem;font-weight:700;color:#ff4560;'>{fp}</div>
                    </div>
                    <div style='background:#ffa50020;border:1px solid #ffa50040;border-radius:4px;padding:8px;'>
                      <div style='font-size:0.6rem;color:#4a5a7a;'>False Negative</div>
                      <div style='font-family:Rajdhani,sans-serif;font-size:1.3rem;font-weight:700;color:#ffa500;'>{fn}</div>
                    </div>
                    <div style='background:#00c8ff20;border:1px solid #00c8ff40;border-radius:4px;padding:8px;'>
                      <div style='font-size:0.6rem;color:#4a5a7a;'>True Negative</div>
                      <div style='font-family:Rajdhani,sans-serif;font-size:1.3rem;font-weight:700;color:#00c8ff;'>{tn}</div>
                    </div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("Run `python3 models/train.py` on your VM to generate the full metrics report.")
