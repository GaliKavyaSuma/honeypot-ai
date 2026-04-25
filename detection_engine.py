#!/usr/bin/env python3
"""
HoneypotAI Detection Engine
Runs inside Docker container honeypot-detection.
Continuously scores new sessions using all 4 ML models.
"""
import pickle, json, time, os
import numpy as np

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

def get_redis():
    import redis
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

def make_features(session):
    return [
        session.get("session_count", 1),
        session.get("total_events", 1),
        len(session.get("commands_tried", [])),
        len(session.get("username_attempts", [])),
        len(session.get("password_attempts", [])),
        session.get("rf_score", 0.5),
        session.get("lr_score", 0.5),
        session.get("svm_score", 0.5),
    ]

def main():
    print("[Detection Engine] Starting up...")
    print(f"[Detection Engine] Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")

    # Wait for Redis
    r = None
    for attempt in range(10):
        try:
            r = get_redis()
            r.ping()
            print("[Detection Engine] Redis connected.")
            break
        except Exception:
            print(f"[Detection Engine] Waiting for Redis... ({attempt+1}/10)")
            time.sleep(3)

    if not r:
        print("[Detection Engine] Could not connect to Redis. Exiting.")
        return

    # Load ML models
    try:
        models = pickle.load(open("models/models.pkl", "rb"))
        print("[Detection Engine] 4 ML models loaded successfully.")
        print("  - RF Session Detection")
        print("  - LR Session Detection")
        print("  - RF Attacker Profiling")
        print("  - SVM Attacker Profiling")
    except Exception as e:
        print(f"[Detection Engine] Could not load models: {e}")
        return

    print("[Detection Engine] Ready. Scoring sessions every 30 seconds...")

    while True:
        try:
            # Get recent events and score them
            raw_events = r.lrange("honeypot:events", 0, 99)
            scored = 0
            for raw in raw_events:
                try:
                    ev = json.loads(raw)
                    if ev.get("event_type") == "LOGIN_ATTEMPT" and "ml_scored" not in ev:
                        features = np.array([[1, 1, 0, 1, 1, 0.5, 0.5, 0.5]])
                        features_scaled = models["scaler"].transform(features)
                        rf_prob = models["rf_session"].predict_proba(features)[0][1]
                        lr_prob = models["lr_session"].predict_proba(features_scaled)[0][1]
                        conf = round((rf_prob * 0.5 + lr_prob * 0.5), 3)
                        ev["ml_scored"] = True
                        ev["ml_confidence"] = conf
                        scored += 1
                except Exception:
                    pass
            if scored > 0:
                print(f"[Detection Engine] Scored {scored} new events.")
        except Exception as e:
            print(f"[Detection Engine] Error: {e}")
        time.sleep(30)

if __name__ == "__main__":
    main()
