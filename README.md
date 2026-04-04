# 🕵️ HoneypotAI — AI-Powered Adaptive Honeypot Dashboard

> Final Year Project | AI-Powered Adaptive Honeypot for Dynamic Cyber Threat Detection & Deception

---

## 📁 Project Structure

```
honeypot-project/
├── app.py                  ← Main Streamlit app (run this)
├── requirements.txt        ← Python dependencies
├── .streamlit/
│   └── config.toml         ← Dark theme config
├── data/
│   ├── generate_data.py    ← Generates the dataset
│   ├── attackers.json      ← 1,811 attacker profiles (auto-generated)
│   └── events.json         ← 5,000 attack events (auto-generated)
├── models/
│   ├── train.py            ← Trains all 4 ML models
│   └── models.pkl          ← Saved models (auto-generated)
├── pages/
│   ├── overview.py         ← KPIs, charts, system status
│   ├── attack_map.py       ← World map with attacker IPs
│   ├── profiles.py         ← Attacker intelligence cards
│   ├── ml_engine.py        ← Model performance & architecture
│   ├── timeline.py         ← Attack replay & heatmap
│   ├── alerts.py           ← High-risk detections feed
│   └── live_detector.py    ← Interactive ML predictor
└── utils/
    └── data_loader.py      ← Shared data utilities
```

---

## 🚀 Option A — Run Locally (VS Code / Terminal)

### Step 1 — Install Python (if not installed)
Download from https://python.org (3.10 or above)

### Step 2 — Open the project folder in VS Code
```
File → Open Folder → select honeypot-project/
```

### Step 3 — Open terminal in VS Code (Ctrl + ` )
```bash
pip install -r requirements.txt
```

### Step 4 — Run the app
```bash
streamlit run app.py
```

Your browser will open automatically at **http://localhost:8501**

---

## 🌐 Option B — Deploy Online Free (Streamlit Cloud)

### Step 1 — Push to GitHub
1. Create a free account at https://github.com
2. Create a new repository called `honeypot-ai`
3. Upload all files from this folder into that repo

### Step 2 — Deploy on Streamlit Cloud
1. Go to https://streamlit.io/cloud
2. Sign in with GitHub
3. Click **"New app"**
4. Select your `honeypot-ai` repo
5. Set **Main file path** to `app.py`
6. Click **Deploy**

Your app will be live at a public URL like:  
`https://your-name-honeypot-ai.streamlit.app`

Share this link with your teacher — no setup needed on their end.

---

## 🌐 Option C — Deploy on Hugging Face Spaces

1. Create account at https://huggingface.co
2. Click **New Space** → choose **Streamlit**
3. Upload all your files
4. It builds and deploys automatically

URL format: `https://huggingface.co/spaces/your-name/honeypot-ai`

---

## 🎯 Features

| Page | What It Shows |
|------|--------------|
| 🏠 Overview | KPI cards, event timeline, country breakdown, system status |
| 🌍 Attack Map | Interactive world map, filter by risk/type/sessions |
| 👤 Profiles | Attacker cards with ML scores, commands, credentials |
| 🤖 ML Engine | Model accuracies, feature importance, dual-path diagram |
| ⏱️ Timeline | Hour×Day heatmap, event replay, command frequency |
| 🔔 Alerts | High-risk feed with 4-model breakdown, blocked IP map |
| 🧪 Live Detector | Adjust sliders → all 4 models score in real-time + radar chart |

---

## 🤖 ML Models

| Model | Path | Accuracy |
|-------|------|----------|
| Random Forest | Session Detection | 100.00% |
| Logistic Regression | Session Detection | 99.67% |
| Random Forest | Attacker Profiling | 100.00% |
| SVM (LinearSVC) | Attacker Profiling | 100.00% |
| **ENSEMBLE** | **Final Confidence** | **99.43%** |

---

## 📊 Dataset

- 1,811 unique attacker IPs profiled
- 524,182 total events processed
- 44,082 unique sessions scored
- 939 IPs automatically blocked
- 16-day observation window (Nov 2022)
- Source: Kaggle Cowrie Honeypot Dataset (CC0 licensed)
