#!/usr/bin/env python3
"""
HoneypotAI — Two-Way Redis Bridge (No Duplicates)
Uses event IDs to track what's already been synced.
Run: RENDER_REDIS_URL="rediss://..." python3 redis_bridge.py
"""
import time, json, os, sys, hashlib

RENDER_REDIS_URL = os.environ.get("RENDER_REDIS_URL", "")

def connect_local():
    import redis
    for port in [6380, 6379]:
        try:
            r = redis.Redis(host='127.0.0.1', port=port, db=0,
                           decode_responses=True, socket_timeout=2)
            r.ping()
            print(f"[Bridge] ✅ Local Redis: port {port}")
            return r
        except Exception:
            continue
    return None

def connect_render():
    if not RENDER_REDIS_URL:
        print("[Bridge] ❌ Set RENDER_REDIS_URL env var")
        return None
    try:
        import redis
        r = redis.from_url(RENDER_REDIS_URL, decode_responses=True,
                          ssl_cert_reqs=None, socket_timeout=5)
        r.ping()
        print(f"[Bridge] ✅ Render Redis: connected")
        return r
    except Exception as e:
        print(f"[Bridge] ❌ Render failed: {e}")
        return None

def event_id(ev_json):
    """Create a unique fingerprint for an event to detect duplicates."""
    return hashlib.md5(ev_json.encode()).hexdigest()

def run():
    print("=" * 55)
    print("  HoneypotAI — Two-Way Redis Bridge (No Duplicates)")
    print("=" * 55)

    local  = connect_local()
    render = connect_render()
    if not local or not render:
        sys.exit(1)

    # Use a Redis set to track synced event fingerprints
    SYNCED_KEY = "bridge:synced_ids"

    # Seed the synced set with ALL currently existing events on BOTH sides
    # so we don't re-push old events on startup
    print("[Bridge] Indexing existing events (won't re-push these)...")
    for ev in local.lrange("honeypot:events", 0, -1):
        local.sadd(SYNCED_KEY, event_id(ev))
    for ev in render.lrange("honeypot:events", 0, -1):
        local.sadd(SYNCED_KEY, event_id(ev))
    local.expire(SYNCED_KEY, 86400)  # 24hr TTL

    to_render = 0
    to_local  = 0
    print(f"[Bridge] Ready. Syncing new events only (both ways)...")

    while True:
        try:
            changed = False

            # ── Check local for NEW events not yet on Render ──────────────
            local_events = local.lrange("honeypot:events", 0, 199)
            new_for_render = []
            for ev in local_events:
                eid = event_id(ev)
                if not local.sismember(SYNCED_KEY, eid):
                    new_for_render.append((eid, ev))

            if new_for_render:
                for eid, ev in reversed(new_for_render):
                    render.lpush("honeypot:events", ev)
                    render.ltrim("honeypot:events", 0, 49999)
                    local.sadd(SYNCED_KEY, eid)
                    to_render += 1
                local.expire(SYNCED_KEY, 86400)
                print(f"[Bridge] ↑ {len(new_for_render)} new events → Render (total: {to_render})")
                changed = True

            # ── Check Render for NEW events not yet local ─────────────────
            render_events = render.lrange("honeypot:events", 0, 199)
            new_for_local = []
            for ev in render_events:
                eid = event_id(ev)
                if not local.sismember(SYNCED_KEY, eid):
                    new_for_local.append((eid, ev))

            if new_for_local:
                for eid, ev in reversed(new_for_local):
                    local.lpush("honeypot:events", ev)
                    local.ltrim("honeypot:events", 0, 99999)
                    local.sadd(SYNCED_KEY, eid)
                    to_local += 1
                local.expire(SYNCED_KEY, 86400)
                print(f"[Bridge] ↓ {len(new_for_local)} new events ← Render (total: {to_local})")
                changed = True

            # Sync adaptation profiles (always overwrite — no dedup needed)
            for key in list(local.scan_iter("adaptation:*"))[:50]:
                p = local.hgetall(key)
                if p:
                    render.hset(key, mapping=p)
                    render.expire(key, 3600)

            time.sleep(2)

        except KeyboardInterrupt:
            print(f"\n[Bridge] Done. ↑{to_render} to Render, ↓{to_local} to Local")
            break
        except Exception as e:
            print(f"[Bridge] Error: {e} — retrying in 5s...")
            time.sleep(5)
            local  = connect_local()
            render = connect_render()

if __name__ == "__main__":
    run()
