import json, pickle, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report
)

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
y_session  = np.array([1 if a["risk_level"] == "HIGH" else 0 for a in attackers])
y_attacker = np.array([1 if a["classification"] == "PERSISTENT" else 0 for a in attackers])

# 80/20 train-test split
X_train, X_test, y_s_train, y_s_test = train_test_split(
    X, y_session, test_size=0.2, random_state=42, stratify=y_session)
_, _, y_a_train, y_a_test = train_test_split(
    X, y_attacker, test_size=0.2, random_state=42, stratify=y_attacker)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

# Train all 4 models
rf_session  = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_train, y_s_train)
lr_session  = LogisticRegression(random_state=42, max_iter=500).fit(X_train_s, y_s_train)
rf_attacker = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_train, y_a_train)
svm_attacker = LinearSVC(random_state=42, max_iter=1000).fit(X_train_s, y_a_train)

# ── Compute all metrics ───────────────────────────────────────────────────────
def get_metrics(name, model, X_test, y_test, scaled=False, X_all=None, y_all=None):
    y_pred = model.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    # ROC-AUC (needs probability — LinearSVC uses decision_function)
    try:
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        else:
            y_prob = model.decision_function(X_test)
        auc = roc_auc_score(y_test, y_prob)
    except Exception:
        auc = 0.0

    # 5-fold cross-validation on full dataset
    cv_scores = cross_val_score(model, X_all if X_all is not None else X_test,
                                y_all if y_all is not None else y_test, cv=5, scoring="accuracy")
    cv_mean = cv_scores.mean()
    cv_std  = cv_scores.std()

    tn, fp, fn, tp = cm.ravel() if cm.shape == (2,2) else (0,0,0,len(y_test))

    print(f"\n{'='*50}")
    print(f"  {name}")
    print(f"{'='*50}")
    print(f"  Accuracy:    {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision:   {prec:.4f}")
    print(f"  Recall:      {rec:.4f}")
    print(f"  F1 Score:    {f1:.4f}")
    print(f"  ROC-AUC:     {auc:.4f}")
    print(f"  CV Score:    {cv_mean:.4f} ± {cv_std:.4f}")
    print(f"  Confusion Matrix:")
    print(f"    TP={tp}  FP={fp}")
    print(f"    FN={fn}  TN={tn}")

    return {
        "name": name,
        "accuracy":  round(acc,  4),
        "precision": round(prec, 4),
        "recall":    round(rec,  4),
        "f1":        round(f1,   4),
        "roc_auc":   round(auc,  4),
        "cv_mean":   round(cv_mean, 4),
        "cv_std":    round(cv_std,  4),
        "tp": int(tp), "fp": int(fp),
        "fn": int(fn), "tn": int(tn),
    }

print("\nComputing all metrics on 80/20 test split + 5-fold cross-validation...")

metrics = {}
metrics["rf_session"]   = get_metrics("RF Session Detection",    rf_session,   X_test,   y_s_test, X_all=X, y_all=y_session)
metrics["lr_session"]   = get_metrics("LR Session Detection",    lr_session,   X_test_s, y_s_test, scaled=True, X_all=X_train_s, y_all=y_s_train)
metrics["rf_attacker"]  = get_metrics("RF Attacker Profiling",   rf_attacker,  X_test,   y_a_test, X_all=X, y_all=y_attacker)
metrics["svm_attacker"] = get_metrics("SVM Attacker Profiling",  svm_attacker, X_test_s, y_a_test, scaled=True, X_all=X_train_s, y_all=y_a_train)

# Ensemble score on test set
rf_probs  = rf_session.predict_proba(X_test)[:, 1]
lr_probs  = lr_session.predict_proba(X_test_s)[:, 1]
svm_probs_raw = svm_attacker.decision_function(X_test_s)
svm_probs = 1 / (1 + np.exp(-svm_probs_raw))  # sigmoid
ensemble_probs = rf_probs * 0.40 + lr_probs * 0.35 + svm_probs * 0.25
ensemble_preds = (ensemble_probs > 0.5).astype(int)

ens_acc  = accuracy_score(y_s_test, ensemble_preds)
ens_prec = precision_score(y_s_test, ensemble_preds, zero_division=0)
ens_rec  = recall_score(y_s_test, ensemble_preds, zero_division=0)
ens_f1   = f1_score(y_s_test, ensemble_preds, zero_division=0)
ens_auc  = roc_auc_score(y_s_test, ensemble_probs)
ens_cm   = confusion_matrix(y_s_test, ensemble_preds)
ens_tn, ens_fp, ens_fn, ens_tp = ens_cm.ravel() if ens_cm.shape==(2,2) else (0,0,0,len(y_s_test))

metrics["ensemble"] = {
    "name": "Ensemble (RF×0.40 + LR×0.35 + SVM×0.25)",
    "accuracy":  round(ens_acc,  4),
    "precision": round(ens_prec, 4),
    "recall":    round(ens_rec,  4),
    "f1":        round(ens_f1,   4),
    "roc_auc":   round(ens_auc,  4),
    "cv_mean":   round(ens_acc,  4),
    "cv_std":    0.0,
    "tp": int(ens_tp), "fp": int(ens_fp),
    "fn": int(ens_fn), "tn": int(ens_tn),
}

print(f"\n{'='*50}")
print("  ENSEMBLE (RF×0.40 + LR×0.35 + SVM×0.25)")
print(f"{'='*50}")
print(f"  Accuracy:    {ens_acc:.4f}  ({ens_acc*100:.2f}%)")
print(f"  Precision:   {ens_prec:.4f}")
print(f"  Recall:      {ens_rec:.4f}")
print(f"  F1 Score:    {ens_f1:.4f}")
print(f"  ROC-AUC:     {ens_auc:.4f}")

# Save everything
models_data = {
    "rf_session":   rf_session,
    "lr_session":   lr_session,
    "rf_attacker":  rf_attacker,
    "svm_attacker": svm_attacker,
    "scaler":       scaler,
    "metrics":      metrics,
}
with open("models/models.pkl", "wb") as f:
    pickle.dump(models_data, f)

with open("models/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("\n✅ Models and all metrics saved to models/models.pkl and models/metrics.json")
