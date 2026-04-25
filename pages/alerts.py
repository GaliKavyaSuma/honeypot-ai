import streamlit as st
import plotly.graph_objects as go
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers

def render():
    df = load_attackers()

    st.markdown("## 🔔 Threat Alerts & Blocked IPs")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>All high-confidence detections that triggered the adaptive response engine. Each alert includes a full 4-model breakdown.</p>", unsafe_allow_html=True)

    high_risk = df[df["risk_level"] == "HIGH"].sort_values("final_confidence", ascending=False)
    blocked = df[df["blocked"] == True]

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""<div class='metric-card danger-card'>
          <div class='metric-val'>{len(high_risk)}</div><div class='metric-lbl'>High Risk Detections</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='metric-card warn-card'>
          <div class='metric-val'>{len(blocked)}</div><div class='metric-lbl'>IPs Blocked</div></div>""", unsafe_allow_html=True)
    with c3:
        avg_conf = high_risk["final_confidence"].mean()
        st.markdown(f"""<div class='metric-card'>
          <div class='metric-val'>{avg_conf:.1%}</div><div class='metric-lbl'>Avg Alert Confidence</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Live alert feed
    st.markdown("### 🚨 Alert Feed — Top Threats")
    
    for _, row in high_risk.head(20).iterrows():
        conf = row["final_confidence"]
        conf_pct = int(conf * 100)
        blocked_badge = "🚫 BLOCKED" if row["blocked"] else "⚠️ MONITORED"
        blocked_color = "#ff4560" if row["blocked"] else "#ffa500"

        cmds = row["commands_tried"][:3] if isinstance(row["commands_tried"], list) else []
        cmd_str = " · ".join([f"<code style='background:#050810;color:#a855f7;padding:1px 4px;border-radius:3px;font-size:0.7rem;'>{c[:25]}</code>" for c in cmds]) or "No commands"

        st.markdown(f"""
        <div style="background:#0a0f1e; border:1px solid #1a2540; border-left:4px solid #ff4560;
             border-radius:8px; padding:16px; margin-bottom:8px;">

          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
            <div style="display:flex; gap:12px; align-items:center;">
              <span style="font-family:Share Tech Mono,monospace; color:#00c8ff; font-size:0.9rem;">{row['ip']}</span>
              <span style="font-family:Rajdhani,sans-serif; font-weight:700; color:#c8d8f0;">{row['country']}</span>
              <span style="font-family:Rajdhani,sans-serif; font-size:0.75rem; color:{blocked_color}; 
                   border:1px solid {blocked_color}44; padding:1px 8px; border-radius:4px;">{blocked_badge}</span>
            </div>
            <div style="font-family:Rajdhani,sans-serif; font-size:1.6rem; font-weight:700; color:#ff4560;">{conf_pct}%</div>
          </div>

          <div style="margin-bottom:12px;">
            <div style="font-size:0.65rem; color:#4a5a7a; text-transform:uppercase; letter-spacing:2px; margin-bottom:6px;">Individual Model Scores</div>
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:6px;">
              <div style="background:#050810; border:1px solid #00f5a040; border-radius:6px; padding:8px; text-align:center;">
                <div style="font-family:Share Tech Mono,monospace; font-size:0.62rem; color:#4a5a7a;">RF Session</div>
                <div style="font-family:Rajdhani,sans-serif; font-size:1.2rem; font-weight:700; color:#00f5a0;">{int(row['rf_score']*100)}%</div>
                <div style="background:#1a2540; border-radius:3px; height:4px; margin-top:4px;"><div style="background:#00f5a0; width:{int(row['rf_score']*100)}%; height:100%; border-radius:3px;"></div></div>
              </div>
              <div style="background:#050810; border:1px solid #00c8ff40; border-radius:6px; padding:8px; text-align:center;">
                <div style="font-family:Share Tech Mono,monospace; font-size:0.62rem; color:#4a5a7a;">LR Session</div>
                <div style="font-family:Rajdhani,sans-serif; font-size:1.2rem; font-weight:700; color:#00c8ff;">{int(row['lr_score']*100)}%</div>
                <div style="background:#1a2540; border-radius:3px; height:4px; margin-top:4px;"><div style="background:#00c8ff; width:{int(row['lr_score']*100)}%; height:100%; border-radius:3px;"></div></div>
              </div>
              <div style="background:#050810; border:1px solid #a855f740; border-radius:6px; padding:8px; text-align:center;">
                <div style="font-family:Share Tech Mono,monospace; font-size:0.62rem; color:#4a5a7a;">SVM Attacker</div>
                <div style="font-family:Rajdhani,sans-serif; font-size:1.2rem; font-weight:700; color:#a855f7;">{int(row['svm_score']*100)}%</div>
                <div style="background:#1a2540; border-radius:3px; height:4px; margin-top:4px;"><div style="background:#a855f7; width:{int(row['svm_score']*100)}%; height:100%; border-radius:3px;"></div></div>
              </div>
              <div style="background:#050810; border:1px solid #ffa50040; border-radius:6px; padding:8px; text-align:center;">
                <div style="font-family:Share Tech Mono,monospace; font-size:0.62rem; color:#4a5a7a;">Ensemble</div>
                <div style="font-family:Rajdhani,sans-serif; font-size:1.2rem; font-weight:700; color:#ffa500;">{int(row['final_confidence']*100)}%</div>
                <div style="background:#1a2540; border-radius:3px; height:4px; margin-top:4px;"><div style="background:#ffa500; width:{int(row['final_confidence']*100)}%; height:100%; border-radius:3px;"></div></div>
              </div>
            </div>
          </div>

          <div style="font-size:0.75rem; color:#4a5a7a;">Commands: {cmd_str}</div>
        </div>
        """, unsafe_allow_html=True)

    # Blocked IPs map
    st.markdown("### 🗺️ Blocked IP Origins")
    blocked_df = df[df["blocked"] == True]
    blocked_by_country = blocked_df.groupby(["country", "lat", "lon"]).size().reset_index(name="count")

    fig = go.Figure(go.Scattergeo(
        lon=blocked_by_country["lon"],
        lat=blocked_by_country["lat"],
        mode="markers",
        marker=dict(
            size=blocked_by_country["count"].clip(5, 25),
            color="#ff4560",
            opacity=0.7,
            line=dict(width=1, color="white"),
        ),
        hovertemplate="<b>%{customdata[0]}</b><br>Blocked IPs: %{customdata[1]}<extra></extra>",
        customdata=blocked_by_country[["country", "count"]].values,
    ))
    fig.update_geos(
        projection_type="natural earth",
        showcoastlines=True, coastlinecolor="#1a2540",
        showland=True, landcolor="#0a0f1e",
        showocean=True, oceancolor="#050810",
        showcountries=True, countrycolor="#1a2540",
        showframe=False, bgcolor="#050810",
    )
    fig.update_layout(
        paper_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        margin=dict(l=0, r=0, t=0, b=0), height=380,
    )
    st.plotly_chart(fig, use_container_width=True)
