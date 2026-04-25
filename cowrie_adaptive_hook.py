#!/usr/bin/env python3
"""
HoneypotAI — Cowrie Adaptive Hook
Cowrie reads this to get per-IP behavioral profiles from Redis.

How it works:
1. Attacker connects to Cowrie on port 2222
2. Cowrie calls get_session_profile(ip) from this file
3. This file checks Redis for the attacker's profile
4. Returns delay, fs_profile, allow_login settings
5. Cowrie adjusts its behavior accordingly

To integrate with real Cowrie:
Copy this file to your Cowrie directory:
  sudo cp cowrie_adaptive_hook.py /opt/cowrie/src/cowrie/
Then import it in Cowrie's SSH server initialization.
"""
import os

def _get_redis():
    """Connect to Redis — tries multiple ports."""
    try:
        import redis as redis_lib
        for port in [6380, 6379]:
            try:
                r = redis_lib.Redis(host='127.0.0.1', port=port, db=0,
                                   decode_responses=True, socket_timeout=1)
                r.ping()
                return r
            except Exception:
                continue
    except ImportError:
        pass
    return None

def get_session_profile(ip):
    """
    Get behavioral profile for this attacker IP.
    Called by Cowrie when a new session connects.

    Returns dict with:
        delay       - seconds to wait before responding
        fs_profile  - which filesystem to show (minimal/developer/server/corporate)
        allow_login - whether to grant shell access
        decoy_level - deception intensity (1-3)
        response    - action type (SLOW_DOWN/THROTTLE/ENGAGE/CAPTURE/MONITOR/FULL_DECEPTION)

    Returns None if no profile exists (Cowrie uses default behavior).
    """
    r = _get_redis()
    if not r:
        return None

    try:
        profile = r.hgetall(f'adaptation:{ip}')
        if profile:
            # Convert string booleans back to Python types
            if 'allow_login' in profile:
                profile['allow_login'] = profile['allow_login'].lower() == 'true'
            if 'delay' in profile:
                profile['delay'] = float(profile['delay'])
            if 'decoy_level' in profile:
                profile['decoy_level'] = int(profile['decoy_level'])
            return profile
    except Exception:
        pass

    return None  # Fall back to default Cowrie behavior


def get_fake_files_for_profile(fs_profile):
    """
    Return list of fake files to show for this filesystem profile.
    Cowrie can use this to populate its fake directory listing.
    """
    FAKE_FILESYSTEMS = {
        'minimal': [
            '/etc/passwd',
            '/etc/hostname',
            '/tmp',
            '/var/log',
        ],
        'developer': [
            '/home/dev/projects/webapp/app.py',
            '/home/dev/projects/webapp/config.py',
            '/home/dev/.ssh/id_rsa',
            '/home/dev/.ssh/id_rsa.pub',
            '/home/dev/.gitconfig',
            '/home/dev/notes.txt',
            '/home/dev/TODO.md',
            '/etc/passwd',
            '/var/log/syslog',
        ],
        'server': [
            '/var/www/html/index.php',
            '/var/www/html/config.php',
            '/etc/apache2/sites-enabled/000-default.conf',
            '/etc/nginx/nginx.conf',
            '/home/ubuntu/.ssh/authorized_keys',
            '/home/ubuntu/db_backup.sql',
            '/var/log/apache2/access.log',
            '/etc/mysql/my.cnf',
            '/etc/passwd',
            '/home/ubuntu/.bash_history',
        ],
        'corporate': [
            '/home/admin/passwords.txt',
            '/home/admin/.aws/credentials',
            '/home/admin/backup.sql',
            '/home/admin/id_rsa',
            '/home/admin/salary_2024.xlsx',
            '/home/admin/employee_records.csv',
            '/home/admin/vpn_config.ovpn',
            '/home/admin/wallet.dat',
            '/home/admin/.bash_history',
            '/var/www/portal/config.php',
            '/etc/passwd',
            '/etc/shadow',
        ],
    }
    return FAKE_FILESYSTEMS.get(fs_profile, FAKE_FILESYSTEMS['minimal'])


if __name__ == '__main__':
    # Test the hook
    print("Testing Cowrie Adaptive Hook...")
    print()

    # Simulate getting profile for an IP
    test_ips = ['192.168.1.100', '10.0.0.50', '127.0.0.1']
    for ip in test_ips:
        profile = get_session_profile(ip)
        if profile:
            print(f"IP {ip}: {profile}")
        else:
            print(f"IP {ip}: No profile → using Cowrie defaults")

    print()
    print("Files for 'corporate' profile:")
    for f in get_fake_files_for_profile('corporate'):
        print(f"  {f}")
