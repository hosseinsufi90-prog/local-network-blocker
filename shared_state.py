"""
Thread-safe shared state between the Tkinter GUI and the Flask web
server, so the phone dashboard and the desktop window always agree
on which devices exist and which are currently blocked.
"""

import threading

_lock = threading.Lock()
_devices = []       # list of device dicts
_gateway = None
_block_requests = []   # queue of (ip, action) tuples the GUI consumes


def set_devices(devices, gateway):
    global _devices, _gateway
    with _lock:
        _devices = devices
        _gateway = gateway


def get_devices():
    with _lock:
        return list(_devices)


def get_gateway():
    with _lock:
        return _gateway


def set_blocked(ip, blocked):
    with _lock:
        for d in _devices:
            if d["ip"] == ip:
                d["blocked"] = blocked


def request_action(ip, action):
    """Called by the web server when the phone taps Block/Unblock.
    The GUI polls this queue and performs the real ARP spoofing,
    since only the GUI thread owns the BlockWorker threads."""
    with _lock:
        _block_requests.append((ip, action))


def pop_actions():
    global _block_requests
    with _lock:
        actions, _block_requests[:] = list(_block_requests), []
    return actions
