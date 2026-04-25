import streamlit as st
import plotly.graph_objects as go
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers

def render():
    df = load_attackers()

    st.markdown("## 🌍 Global Attack Map")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Live attacker geolocation — each dot represents a unique threat actor IP. Size = session count. Color = risk level.</p>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        risk_filter = st.multiselect("Risk Level", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"])
    with col2:
        all_types = ["APT", "PERSISTENT", "EXPLOITER", "DROPPER", "BRUTEFORCE", "SCANNER"]
        cls_filter = st.multiselect("Classification", all_types, default=all_types)
    with col3:
        min_sessions = st.slider("Min Sessions", 1, 40, 1)

    filtered = df[
        df["risk_level"].isin(risk_filter) &
        df["classification"].isin(cls_filter) &
        (df["session_count"] >= min_sessions)
    ]

    st.markdown(f"<div style='font-family:Share Tech Mono,monospace; color:#00c8ff; font-size:0.8rem; margin-bottom:12px;'>Showing {len(filtered):,} of {len(df):,} attackers</div>", unsafe_allow_html=True)

    color_map = {"HIGH": "#ff4560", "MEDIUM": "#ffa500", "LOW": "#00f5a0"}

    fig = go.Figure()

    for risk in ["LOW", "MEDIUM", "HIGH"]:
        sub = filtered[filtered["risk_level"] == risk]
        if sub.empty:
            continue
        fig.add_trace(go.Scattergeo(
            lon=sub["lon"], lat=sub["lat"],
            mode="markers",
            name=risk,
            marker=dict(
                size=sub["session_count"].clip(3, 20),
                color=color_map[risk],
                opacity=0.8,
                line=dict(width=0.5, color="white"),
            ),
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>"
                "IP: %{customdata[1]}<br>"
                "Risk: " + risk + "<br>"
                "Sessions: %{customdata[2]}<br>"
                "Classification: %{customdata[3]}<br>"
                "Confidence: %{customdata[4]:.1%}<extra></extra>"
            ),
            customdata=sub[["country", "ip", "session_count", "classification", "final_confidence"]].values,
        ))

    fig.update_geos(
        projection_type="natural earth",
        showcoastlines=True, coastlinecolor="#1a2540",
        showland=True, landcolor="#0a0f1e",
        showocean=True, oceancolor="#050810",
        showlakes=True, lakecolor="#050810",
        showcountries=True, countrycolor="#1a2540",
        showframe=False,
        bgcolor="#050810",
    )
    fig.update_layout(
        paper_bgcolor="#050810",
        geo_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        legend=dict(
            bgcolor="rgba(10,15,30,0.8)", bordercolor="#1a2540", borderwidth=1,
            font=dict(color="#c8d8f0", family="Rajdhani"),
        ),
        margin=dict(l=0, r=0, t=0, b=0),
        height=560,
    )

    st.plotly_chart(fig, use_container_width=True)

    # Heatmap-style country breakdown
    st.markdown("### 🔥 Attack Intensity by Country")
    country_stats = filtered.groupby("country").agg(
        attackers=("ip", "count"),
        avg_confidence=("final_confidence", "mean"),
        high_risk=("risk_level", lambda x: (x == "HIGH").sum()),
    ).reset_index().sort_values("attackers", ascending=False).head(15)

    fig2 = go.Figure(go.Bar(
        x=country_stats["country"],
        y=country_stats["attackers"],
        marker=dict(
            color=country_stats["avg_confidence"],
            colorscale=[[0, "#1a2540"], [0.5, "#ffa500"], [1, "#ff4560"]],
            colorbar=dict(title="Avg Conf", tickfont=dict(color="#c8d8f0")),
            showscale=True,
        ),
        text=country_stats["attackers"],
        textposition="outside",
        textfont=dict(color="#c8d8f0", family="Share Tech Mono"),
        hovertemplate="<b>%{x}</b><br>Attackers: %{y}<br>High Risk: %{customdata}<extra></extra>",
        customdata=country_stats["high_risk"],
    ))
    fig2.update_layout(
        paper_bgcolor="#050810", plot_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        xaxis=dict(gridcolor="#1a2540", tickangle=-30),
        yaxis=dict(gridcolor="#1a2540"),
        margin=dict(l=0, r=0, t=10, b=60),
        height=320,
    )
    st.plotly_chart(fig2, use_container_width=True)
