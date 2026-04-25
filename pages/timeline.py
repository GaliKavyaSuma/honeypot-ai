import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_events, load_attackers
from utils.colors import fill

def render():
    ev = load_events()
    df = load_attackers()

    st.markdown("## ⏱️ Attack Timeline & Replay")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Scrub through the full attack timeline. See how threats evolved hour by hour.</p>", unsafe_allow_html=True)

    min_date = ev["timestamp"].min().date()
    max_date = ev["timestamp"].max().date()

    col1, col2, col3 = st.columns(3)
    with col1:
        start = st.date_input("Start Date", min_date)
    with col2:
        end = st.date_input("End Date", max_date)
    with col3:
        quick = st.selectbox("Quick Range", ["Custom", "Last 7 days", "Last 16 days", "All time"])
        if quick == "Last 7 days":
            start = max_date - pd.Timedelta(days=7)
            end = max_date
        elif quick in ["Last 16 days", "All time"]:
            start = min_date
            end = max_date

    mask = (ev["timestamp"].dt.date >= start) & (ev["timestamp"].dt.date <= end)
    filtered_ev = ev[mask]

    # Hourly heatmap
    st.markdown("### 🔥 Attack Intensity Heatmap (Hour × Day)")
    filtered_ev = filtered_ev.copy()
    filtered_ev["hour"] = filtered_ev["timestamp"].dt.hour
    filtered_ev["day"] = filtered_ev["timestamp"].dt.strftime("%b %d")

    pivot = filtered_ev.groupby(["hour", "day"]).size().reset_index(name="count")
    pivot_wide = pivot.pivot(index="hour", columns="day", values="count").fillna(0)

    fig = go.Figure(go.Heatmap(
        z=pivot_wide.values,
        x=pivot_wide.columns,
        y=[f"{h:02d}:00" for h in pivot_wide.index],
        colorscale=[[0, "#050810"], [0.3, "#1a2540"], [0.6, "#ffa500"], [1, "#ff4560"]],
        showscale=True,
        colorbar=dict(title="Events", tickfont=dict(color="#c8d8f0")),
        hovertemplate="Day: %{x}<br>Hour: %{y}<br>Events: %{z}<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="#050810", plot_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        xaxis=dict(side="top", tickangle=-45),
        margin=dict(l=60, r=0, t=60, b=0),
        height=380,
    )
    st.plotly_chart(fig, use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📈 Events Per Hour")
        hourly = filtered_ev.groupby([filtered_ev["timestamp"].dt.floor("h"), "risk_level"]).size().reset_index(name="count")
        hourly.columns = ["hour", "risk_level", "count"]
        colors = {"HIGH": "#ff4560", "MEDIUM": "#ffa500", "LOW": "#00f5a0"}
        fig2 = go.Figure()
        for risk, color in colors.items():
            sub = hourly[hourly["risk_level"] == risk]
            fig2.add_trace(go.Scatter(
                x=sub["hour"], y=sub["count"],
                name=risk, mode="lines",
                line=dict(color=color, width=2),
                fill="tozeroy",
                fillcolor=fill(color, 0.12),
            ))
        fig2.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540"),
            yaxis=dict(gridcolor="#1a2540"),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=0, r=0, t=10, b=0), height=260,
        )
        st.plotly_chart(fig2, use_container_width=True)

    with col2:
        st.markdown("### 🎯 Event Type Breakdown")
        event_counts = filtered_ev["event_type"].value_counts()
        fig3 = go.Figure(go.Bar(
            x=event_counts.index, y=event_counts.values,
            marker=dict(
                color=["#ff4560", "#ffa500", "#00f5a0", "#00c8ff", "#a855f7"],
            ),
            text=event_counts.values, textposition="outside",
            textfont=dict(color="#c8d8f0"),
        ))
        fig3.update_layout(
            paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540"),
            yaxis=dict(gridcolor="#1a2540"),
            margin=dict(l=0, r=0, t=10, b=0), height=260,
        )
        st.plotly_chart(fig3, use_container_width=True)

    # Command frequency
    st.markdown("### 💻 Most Used Attack Commands")
    all_commands = []
    for cmds in df["commands_tried"]:
        if isinstance(cmds, list):
            all_commands.extend(cmds)

    from collections import Counter
    cmd_counts = Counter(all_commands).most_common(15)
    cmd_df = pd.DataFrame(cmd_counts, columns=["command", "count"])

    fig4 = go.Figure(go.Bar(
        x=cmd_df["count"], y=cmd_df["command"],
        orientation="h",
        marker=dict(
            color=cmd_df["count"],
            colorscale=[[0, "#1a2540"], [0.5, "#a855f7"], [1, "#ff4560"]],
        ),
        text=cmd_df["count"], textposition="outside",
        textfont=dict(color="#c8d8f0", family="Share Tech Mono"),
        hovertemplate="<b>%{y}</b><br>Count: %{x}<extra></extra>",
    ))
    fig4.update_layout(
        paper_bgcolor="#050810", plot_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        yaxis=dict(autorange="reversed", gridcolor="#1a2540",
                   tickfont=dict(family="Share Tech Mono", size=11)),
        xaxis=dict(gridcolor="#1a2540"),
        margin=dict(l=0, r=0, t=10, b=0), height=420,
    )
    st.plotly_chart(fig4, use_container_width=True)
