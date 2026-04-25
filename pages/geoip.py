import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import sys; sys.path.insert(0, ".")
from utils.data_loader import load_attackers

COUNTRY_RISK = {
    "CN":0.95,"RU":0.90,"UA":0.80,"IR":0.85,"KP":0.95,"BR":0.60,"IN":0.55,
    "VN":0.70,"RO":0.65,"NG":0.70,"PK":0.60,"BD":0.55,"TH":0.50,"ID":0.55,
    "TR":0.60,"US":0.40,"DE":0.35,"GB":0.35,"FR":0.35,"NL":0.45,"SG":0.50,
    "KR":0.45,"JP":0.30,"AU":0.25,"CA":0.30,
}

# Country centroids for scatter map
COUNTRY_COORDS = {
    "CN":(35.86,104.19,"China"),"RU":(61.52,105.31,"Russia"),
    "UA":(48.37,31.16,"Ukraine"),"IR":(32.42,53.68,"Iran"),
    "KP":(40.33,127.51,"North Korea"),"BR":(-14.23,-51.92,"Brazil"),
    "IN":(20.59,78.96,"India"),"VN":(14.05,108.27,"Vietnam"),
    "RO":(45.94,24.96,"Romania"),"NG":(9.08,8.67,"Nigeria"),
    "PK":(30.37,69.34,"Pakistan"),"BD":(23.68,90.35,"Bangladesh"),
    "TH":(15.87,100.99,"Thailand"),"ID":(-0.78,113.92,"Indonesia"),
    "TR":(38.96,35.24,"Turkey"),"US":(37.09,-95.71,"United States"),
    "DE":(51.16,10.45,"Germany"),"GB":(55.37,-3.43,"United Kingdom"),
    "FR":(46.22,2.21,"France"),"NL":(52.13,5.29,"Netherlands"),
    "SG":(1.35,103.81,"Singapore"),"KR":(35.90,127.76,"South Korea"),
    "JP":(36.20,138.25,"Japan"),"AU":(-25.27,133.77,"Australia"),
    "CA":(56.13,-106.34,"Canada"),
}

def render():
    df = load_attackers()

    st.markdown("## 🌍 GeoIP Threat Scoring")
    st.markdown("<p style='color:#4a5a7a; font-size:0.85rem;'>Geographic risk intelligence — countries with historically high attack volumes get a higher base risk score fed into the ML models.</p>", unsafe_allow_html=True)

    st.markdown("""
    <div style='background:#0a0f1e; border:1px solid #00c8ff40; border-left:3px solid #00c8ff;
         border-radius:8px; padding:16px; margin-bottom:20px;'>
      <div style='font-family:Rajdhani,sans-serif; font-weight:700; color:#00c8ff; font-size:1.1rem; margin-bottom:6px;'>How GeoIP Scoring Works</div>
      <div style='font-size:0.85rem; color:#c8d8f0; line-height:1.6;'>
        Based on public threat intelligence (Cloudflare Radar, Akamai SOTI, IBM X-Force),
        each country gets a <b style='color:#00f5a0;'>base risk score (0–1)</b>.
        This score is fed as an extra feature into the ML ensemble —
        so an attacker from <b style='color:#ff4560;'>China or Russia</b> starts
        with a higher suspicion score before any commands are even attempted.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Map using scatter geo ─────────────────────────────────────────────────
    st.markdown("### 🗺️ Global Risk Heat Map")

    map_data = []
    for code, risk in COUNTRY_RISK.items():
        if code in COUNTRY_COORDS:
            lat, lon, name = COUNTRY_COORDS[code]
            map_data.append({"code":code,"name":name,"lat":lat,"lon":lon,"risk":risk})
    map_df = pd.DataFrame(map_data)

    # Color each circle by risk
    def risk_color(r):
        if r >= 0.85: return "#ff4560"
        elif r >= 0.70: return "#ff7043"
        elif r >= 0.55: return "#ffa500"
        elif r >= 0.40: return "#ffd600"
        else: return "#00f5a0"

    map_df["color"] = map_df["risk"].apply(risk_color)
    map_df["size"]  = map_df["risk"] * 40 + 10

    fig = go.Figure()

    # Background world map
    fig.add_trace(go.Scattergeo(
        lon=map_df["lon"], lat=map_df["lat"],
        mode="markers",
        marker=dict(
            size=map_df["size"],
            color=map_df["color"],
            opacity=0.85,
            line=dict(width=1, color="white"),
        ),
        text=map_df.apply(lambda r: f"{r['name']} ({r['code']})<br>Risk Score: {r['risk']:.0%}", axis=1),
        hovertemplate="%{text}<extra></extra>",
        name="Risk Score",
    ))

    fig.update_geos(
        showcoastlines=True, coastlinecolor="#2a3550",
        showland=True, landcolor="#0d1520",
        showocean=True, oceancolor="#050810",
        showcountries=True, countrycolor="#1a2540",
        showframe=False, bgcolor="#050810",
        projection_type="natural earth",
    )
    fig.update_layout(
        paper_bgcolor="#050810", geo_bgcolor="#050810",
        font=dict(color="#c8d8f0", family="Rajdhani"),
        margin=dict(l=0,r=0,t=0,b=0), height=440,
        showlegend=False,
        annotations=[
            dict(x=0.01, y=0.15, xref="paper", yref="paper", showarrow=False,
                 text="<b style='color:#c8d8f0'>Risk Scale</b><br>"
                      "<span style='color:#ff4560'>● 85–100% Critical</span><br>"
                      "<span style='color:#ffa500'>● 55–84% High</span><br>"
                      "<span style='color:#00f5a0'>● &lt;55% Moderate</span>",
                 font=dict(color="#c8d8f0", size=11, family="Rajdhani"),
                 align="left",
                 bgcolor="#0a0f1e", bordercolor="#1a2540", borderwidth=1,
                 borderpad=8),
        ]
    )
    st.plotly_chart(fig, use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📊 Risk Score by Country")
        risk_sorted = sorted(COUNTRY_RISK.items(), key=lambda x: x[1], reverse=True)
        codes = [COUNTRY_COORDS.get(c,(0,0,c))[2] for c,_ in risk_sorted]
        scores = [s for _,s in risk_sorted]
        bar_colors = [risk_color(s) for s in scores]

        fig2 = go.Figure(go.Bar(
            x=codes, y=scores,
            marker=dict(color=bar_colors),
            text=[f"{s:.0%}" for s in scores],
            textposition="outside",
            textfont=dict(color="#c8d8f0", size=9),
        ))
        fig2.update_layout(paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540", tickangle=-35),
            yaxis=dict(gridcolor="#1a2540", range=[0,1.15]),
            margin=dict(l=0,r=0,t=10,b=70), height=320)
        st.plotly_chart(fig2, use_container_width=True)

    with col2:
        st.markdown("### 🔗 Geo Risk vs ML Confidence")
        fig3 = go.Figure(go.Scatter(
            x=df["geo_risk_score"], y=df["final_confidence"],
            mode="markers",
            marker=dict(
                color=df["final_confidence"],
                colorscale=[[0,"#00f5a0"],[0.5,"#ffa500"],[1,"#ff4560"]],
                size=4, opacity=0.5,
            ),
            hovertemplate="Geo Risk: %{x:.0%}<br>ML Confidence: %{y:.0%}<extra></extra>",
        ))
        fig3.update_layout(paper_bgcolor="#050810", plot_bgcolor="#050810",
            font=dict(color="#c8d8f0", family="Rajdhani"),
            xaxis=dict(gridcolor="#1a2540", title="GeoIP Risk Score"),
            yaxis=dict(gridcolor="#1a2540", title="ML Confidence"),
            margin=dict(l=0,r=0,t=10,b=0), height=320)
        st.plotly_chart(fig3, use_container_width=True)

    st.markdown("### 📋 Country Risk Reference Table")
    risk_table = df.groupby(["country","country_code"]).agg(
        Attackers=("ip","count"),
        Avg_Confidence=("final_confidence","mean"),
        High_Risk=("risk_level", lambda x: (x=="HIGH").sum()),
        Geo_Risk=("geo_risk_score","first"),
    ).reset_index().sort_values("Geo_Risk", ascending=False)
    risk_table["Avg_Confidence"] = risk_table["Avg_Confidence"].map("{:.1%}".format)
    risk_table["Geo_Risk"]       = risk_table["Geo_Risk"].map("{:.0%}".format)
    risk_table.columns = ["Country","Code","Attackers","Avg Confidence","High Risk","Geo Risk"]
    st.dataframe(risk_table, use_container_width=True, height=350)
