import json, pickle, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler

with open("data/attackers.json") as f:
    attackers = json.load(f)

def make_features(a):
    return [
        a["session_count"],
        a["total_events"],
        len(a["commands_tried"]),
        len(a["username_attempts"]),
        len(a["password_attempts"]),
        a["rf_score"],
        a["lr_score"],
        a["svm_score"],
    ]

X = np.array([make_features(a) for a in attackers])
y_session = np.array([1 if a["risk_level"] == "HIGH" else 0 for a in attackers])
y_attacker = np.array([1 if a["classification"] == "PERSISTENT" else 0 for a in attackers])

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

rf_session = RandomForestClassifier(n_estimators=100, random_state=42).fit(X, y_session)
lr_session = LogisticRegression(random_state=42, max_iter=500).fit(X_scaled, y_session)
rf_attacker = RandomForestClassifier(n_estimators=100, random_state=42).fit(X, y_attacker)
svm_attacker = LinearSVC(random_state=42, max_iter=1000).fit(X_scaled, y_attacker)

models = {
    "rf_session": rf_session,
    "lr_session": lr_session,
    "rf_attacker": rf_attacker,
    "svm_attacker": svm_attacker,
    "scaler": scaler,
}
with open("models/models.pkl", "wb") as f:
    pickle.dump(models, f)

# Accuracies
from sklearn.metrics import accuracy_score
print(f"RF Session:     {accuracy_score(y_session,  rf_session.predict(X)):.4f}")
print(f"LR Session:     {accuracy_score(y_session,  lr_session.predict(X_scaled)):.4f}")
print(f"RF Attacker:    {accuracy_score(y_attacker, rf_attacker.predict(X)):.4f}")
print(f"SVM Attacker:   {accuracy_score(y_attacker, svm_attacker.predict(X_scaled)):.4f}")
print("Models saved.")
