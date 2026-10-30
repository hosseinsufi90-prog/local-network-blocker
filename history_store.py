"""
Keeps a small local JSON log of devices ever seen on the network:
first time seen, last time seen, and a friendly label the user can
set. Lets the GUI tell new devices apart from ones it already knows.
"""

import json
import os
import time

_PATH = os.path.join(os.path.dirname(__file__), "device_history.json")


def _load():
    if not os.path.exists(_PATH):
        return {}
    try:
        with open(_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data):
    try:
        with open(_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def touch(mac, ip, vendor, hostname):
    """Records that this MAC was just seen. Returns True if this is
    the first time we've ever seen it (a 'new device')."""
    data = _load()
    now = time.time()
    is_new = mac not in data
    if is_new:
        data[mac] = {
            "first_seen": now,
            "last_seen": now,
            "last_ip": ip,
            "vendor": vendor,
            "hostname": hostname,
            "label": "",
            "times_seen": 1,
        }
    else:
        data[mac]["last_seen"] = now
        data[mac]["last_ip"] = ip
        if vendor and vendor != "Unknown":
            data[mac]["vendor"] = vendor
        if hostname and hostname != "-":
            data[mac]["hostname"] = hostname
        data[mac]["times_seen"] = data[mac].get("times_seen", 0) + 1
    _save(data)
    return is_new


def get_entry(mac):
    return _load().get(mac)


def set_label(mac, label):
    data = _load()
    if mac in data:
        data[mac]["label"] = label
        _save(data)


def all_entries():
    return _load()
