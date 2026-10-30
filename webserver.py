"""
Small local web dashboard so you can view and block/unblock devices
from your phone, as long as it's on the same Wi-Fi network as this
computer. Nothing is exposed to the internet - Flask only listens
on your local network.
"""

import socket
import threading
import os

from flask import Flask, jsonify, request, render_template_string
import qrcode

import shared_state as state

app = Flask(__name__)
_server_thread = None
_server_started = threading.Event()

PORT = 5000

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetGuard Mobile</title>
<style>
  :root {
    --bg: #1e1e2e; --card: #2a2a3d; --accent: #9d9dff;
    --green: #4caf50; --red: #e05c5c; --text: #e8e8f0;
  }
  body { margin:0; font-family: 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  header { padding: 18px 16px; text-align: center; }
  header h1 { margin: 0; font-size: 1.4rem; color: var(--accent); }
  #status { font-size: 0.85rem; color: #999; margin-top: 4px; }
  .device { background: var(--card); margin: 10px 14px; padding: 14px; border-radius: 12px;
             display:flex; justify-content: space-between; align-items: center; }
  .device.blocked { border-left: 4px solid var(--red); }
  .device.online { border-left: 4px solid var(--green); }
  .info b { display:block; font-size: 1rem; }
  .info span { font-size: 0.8rem; color: #aaa; }
  button { border:none; padding: 10px 16px; border-radius: 8px; font-weight:600; color:white; }
  button.block { background: var(--red); }
  button.unblock { background: var(--green); }
  .you { opacity: 0.6; }
</style>
</head>
<body>
<header>
  <h1>🛡 NetGuard</h1>
  <div id="status">Loading...</div>
</header>
<div id="list"></div>
<script>
async function refresh() {
  const res = await fetch('/api/devices');
  const data = await res.json();
  document.getElementById('status').textContent = data.length + ' devices found';
  const list = document.getElementById('list');
  list.innerHTML = '';
  data.forEach(d => {
    const div = document.createElement('div');
    div.className = 'device ' + (d.blocked ? 'blocked' : 'online') + (d.is_you ? ' you' : '');
    div.innerHTML = `
      <div class="info">
        <b>${d.hostname !== '-' ? d.hostname : d.vendor}</b>
        <span>${d.ip} · ${d.type}${d.is_you ? ' · this device' : ''}</span>
      </div>
      ${d.is_you ? '' : `<button class="${d.blocked ? 'unblock' : 'block'}" onclick="toggle('${d.ip}', ${d.blocked})">
        ${d.blocked ? 'Unblock' : 'Block'}
      </button>`}
    `;
    list.appendChild(div);
  });
}

async function toggle(ip, isBlocked) {
  await fetch('/api/action', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip: ip, action: isBlocked ? 'unblock' : 'block'})
  });
  setTimeout(refresh, 600);
}

refresh();
setInterval(refresh, 4000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/devices")
def api_devices():
    return jsonify(state.get_devices())


@app.route("/api/action", methods=["POST"])
def api_action():
    data = request.get_json()
    ip = data.get("ip")
    action = data.get("action")
    if ip and action in ("block", "unblock"):
        state.request_action(ip, action)
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 400


def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def _run_server():
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)


def ensure_server_running():
    """Starts the Flask server once (if not already running) and
    returns the URL + path to a freshly generated QR code image."""
    global _server_thread
    if _server_thread is None:
        _server_thread = threading.Thread(target=_run_server, daemon=True)
        _server_thread.start()
        _server_started.set()

    local_ip = _get_local_ip()
    url = f"http://{local_ip}:{PORT}"

    qr_dir = os.path.join(os.path.dirname(__file__), "qr_cache")
    os.makedirs(qr_dir, exist_ok=True)
    qr_path = os.path.join(qr_dir, "mobile_qr.png")

    img = qrcode.make(url)
    img.save(qr_path)

    return url, qr_path
