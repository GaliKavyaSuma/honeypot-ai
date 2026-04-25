import streamlit as st
import plotly.graph_objects as go
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers, risk_color

def render():
    df = load_attackers()

    st.markdown("## 👤 Attacker Intelligence Profiles")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Deep-dive intelligence on each threat actor — commands attempted, credentials used, ML model breakdown.</p>", unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        search_ip = st.text_input("🔍 Search IP", placeholder="e.g. 192.168.")
    with col2:
        risk_f = st.selectbox("Risk", ["ALL", "HIGH", "MEDIUM", "LOW"])
    with col3:
        cls_f = st.selectbox("Type", ["ALL", "APT", "PERSISTENT", "EXPLOITER", "DROPPER", "BRUTEFORCE", "SCANNER"])
    with col4:
        sort_by = st.selectbox("Sort by", ["final_confidence", "session_count", "total_events"])

    # Classification color map
    cls_colors = {
        "APT":        "#ff4560",
        "PERSISTENT": "#00c8ff",
        "EXPLOITER":  "#a855f7",
        "DROPPER":    "#ffa500",
        "BRUTEFORCE": "#f59e0b",
        "SCANNER":    "#00f5a0",
    }

    filtered = df.copy()
    if search_ip:
        filtered = filtered[filtered["ip"].str.contains(search_ip)]
    if risk_f != "ALL":
        filtered = filtered[filtered["risk_level"] == risk_f]
    if cls_f != "ALL":
        filtered = filtered[filtered["classification"] == cls_f]
    filtered = filtered.sort_values(sort_by, ascending=False)

    st.markdown(f"<div style='font-family:Share Tech Mono,monospace; color:#00c8ff; font-size:0.8rem; margin:8px 0 16px;'>Found {len(filtered):,} attackers</div>", unsafe_allow_html=True)

    # Show top attackers as cards
    top = filtered.head(12)
    cols = st.columns(3)

    for i, (_, row) in enumerate(top.iterrows()):
        with cols[i % 3]:
            risk = row["risk_level"]
            rc = risk_color(risk)
            cls_color = cls_colors.get(row["classification"], "#00c8ff")
            conf_pct = int(row["final_confidence"] * 100)
            
            cmds = row["commands_tried"][:4] if isinstance(row["commands_tried"], list) else []
            cmd_html = "".join([f'<div style="font-family:Share Tech Mono,monospace;font-size:0.65rem;color:#4a5a7a;padding:1px 0;">$ {c[:30]}</div>' for c in cmds])
            if not cmds:
                cmd_html = '<div style="font-size:0.72rem;color:#4a5a7a;">No commands recorded</div>'

            st.markdown(f"""
            <div style="background:#0a0f1e; border:1px solid #1a2540; border-top:3px solid {rc};
                 border-radius:10px; padding:18px; margin-bottom:12px;">
              
              <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
                <div>
                  <div style="font-family:Share Tech Mono,monospace; font-size:0.85rem; color:#00c8ff;">{row['ip']}</div>
                  <div style="font-family:Rajdhani,sans-serif; font-size:1.0rem; font-weight:700; color:#c8d8f0; margin-top:2px;">
                    {row['country']} {row['country_code']}
                  </div>
                </div>
                <div style="text-align:right;">
                  <div style="background:{rc}22; color:{rc}; border:1px solid {rc}44;
                       font-family:Rajdhani,sans-serif; font-size:0.72rem; font-weight:700;
                       padding:2px 8px; border-radius:4px; letter-spacing:1px;">{risk}</div>
                  <div style="background:{cls_color}22; color:{cls_color}; border:1px solid {cls_color}44;
                       font-family:Rajdhani,sans-serif; font-size:0.65rem;
                       padding:2px 8px; border-radius:4px; letter-spacing:1px; margin-top:3px;">{row['classification']}</div>
                </div>
              </div>

              <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; margin-bottom:12px;">
                <div style="text-align:center; background:#050810; border-radius:6px; padding:8px;">
                  <div style="font-family:Rajdhani,sans-serif; font-size:1.3rem; font-weight:700; color:{rc};">{row['session_count']}</div>
                  <div style="font-size:0.6rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:1px;">Sessions</div>
                </div>
                <div style="text-align:center; background:#050810; border-radius:6px; padding:8px;">
                  <div style="font-family:Rajdhani,sans-serif; font-size:1.3rem; font-weight:700; color:#00c8ff;">{row['total_events']}</div>
                  <div style="font-size:0.6rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:1px;">Events</div>
                </div>
                <div style="text-align:center; background:#050810; border-radius:6px; padding:8px;">
                  <div style="font-family:Rajdhani,sans-serif; font-size:1.3rem; font-weight:700; color:#00f5a0;">{conf_pct}%</div>
                  <div style="font-size:0.6rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:1px;">Confidence</div>
                </div>
              </div>

              <div style="margin-bottom:10px;">
                <div style="font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">ML Scores</div>
                <div style="display:flex; gap:4px; flex-wrap:wrap;">
                  <span style="font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#00f5a0;">RF:{int(row['rf_score']*100)}%</span>
                  <span style="color:#1a2540;">|</span>
                  <span style="font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#00c8ff;">LR:{int(row['lr_score']*100)}%</span>
                  <span style="color:#1a2540;">|</span>
                  <span style="font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#a855f7;">SVM:{int(row['svm_score']*100)}%</span>
                </div>
              </div>

              <div>
                <div style="font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Commands Tried</div>
                {cmd_html}
              </div>

              {"<div style='margin-top:10px; background:#ff456015; border:1px solid #ff456040; border-radius:4px; padding:4px 8px; font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#ff4560;'>🚫 IP BLOCKED</div>" if row['blocked'] else ""}
            </div>
            """, unsafe_allow_html=True)

    # Detailed table below cards
    st.markdown("### 📋 Full Attacker Table")
    display_cols = ["ip", "country", "risk_level", "classification", "session_count", "total_events", "final_confidence", "blocked"]
    st.dataframe(
        filtered[display_cols].head(100).style.format({"final_confidence": "{:.1%}"}),
        use_container_width=True,
        height=350,
    )
