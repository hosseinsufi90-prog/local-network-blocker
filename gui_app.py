"""
NetGuard - Local Network Device Manager
A desktop GUI to scan devices on your own network, see details and
history about each one, and block/unblock them via ARP spoofing.
Use only on a network you own or administer.

Requirements:
    pip install scapy requests qrcode[pil] flask pillow

Run (Windows, as Administrator):
    python gui_app.py
"""

import csv
import socket
import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import concurrent.futures

import requests
from scapy.all import ARP, Ether, srp, send

import shared_state as state
import history_store as history


# ---------------- Network helpers ----------------

def get_local_ip_and_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    gateway = ".".join(local_ip.split(".")[:3]) + ".1"
    return local_ip, subnet, gateway


def scan_network(subnet, rounds=3):
    """Sends several ARP broadcast rounds instead of just one. Devices
    in power-saving mode (phones, some laptops) often miss a single
    broadcast, so repeating catches stragglers that a one-shot scan
    would report as 'not found'."""
    found = {}
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    for _ in range(rounds):
        result = srp(ether / arp, timeout=2, verbose=0)[0]
        for _, r in result:
            found[r.psrc] = r.hwsrc
        time.sleep(0.3)
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]


def get_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp, timeout=2, verbose=0)[0]
    return result[0][1].hwsrc if result else None


def get_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return "Unknown"


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


TYPE_ICONS = {
    "Apple": "🍎",
    "Android": "📱",
    "Computer": "💻",
    "Unknown": "❔",
}


def guess_type(vendor):
    v = vendor.lower()
    android = ["samsung", "xiaomi", "huawei", "oppo", "vivo", "oneplus",
               "google", "motorola", "lg electronics"]
    if "apple" in v:
        return "Apple"
    for name in android:
        if name in v:
            return "Android"
    if any(x in v for x in ["intel", "dell", "hp", "lenovo", "asus", "realtek", "tp-link", "netgear"]):
        return "Computer"
    return "Unknown"


def enrich_device(d, local_ip):
    vendor = get_vendor(d["mac"])
    hostname = get_hostname(d["ip"])
    is_new = history.touch(d["mac"], d["ip"], vendor, hostname)
    entry = history.get_entry(d["mac"]) or {}
    return {
        "ip": d["ip"],
        "mac": d["mac"],
        "vendor": vendor,
        "type": guess_type(vendor),
        "hostname": hostname,
        "label": entry.get("label", ""),
        "first_seen": entry.get("first_seen"),
        "times_seen": entry.get("times_seen", 1),
        "is_you": d["ip"] == local_ip,
        "is_new": is_new,
        "blocked": False,
    }


def enrich_all(devices, local_ip):
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(enrich_device, d, local_ip) for d in devices]
        return [f.result() for f in futures]


def fmt_timestamp(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def fmt_relative(ts):
    if not ts:
        return "-"
    delta = time.time() - ts
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


# ---------------- Blocking engine ----------------

class BlockWorker(threading.Thread):
    def __init__(self, target_ip, target_mac, gateway_ip, gateway_mac):
        super().__init__(daemon=True)
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                      psrc=self.gateway_ip), verbose=0)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                      psrc=self.target_ip), verbose=0)
            time.sleep(2)
        send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                  psrc=self.gateway_ip, hwsrc=self.gateway_mac), count=4, verbose=0)
        send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                  psrc=self.target_ip, hwsrc=self.target_mac), count=4, verbose=0)

    def stop(self):
        self.stop_event.set()


# ---------------- GUI ----------------

COLUMNS = ("icon", "ip", "mac", "vendor", "type", "name", "last_seen", "status")
HEADINGS = {
    "icon": "", "ip": "IP Address", "mac": "MAC Address", "vendor": "Vendor",
    "type": "Type", "name": "Name / Hostname", "last_seen": "First Seen", "status": "Status",
}
WIDTHS = {"icon": 30, "ip": 110, "mac": 140, "vendor": 140, "type": 80,
          "name": 150, "last_seen": 110, "status": 90}


class NetGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard - Network Device Manager")
        self.root.geometry("980x600")
        self.root.configure(bg="#1e1e2e")
        self.root.minsize(820, 480)

        self.local_ip = None
        self.subnet = None
        self.gateway = None
        self.devices = []
        self.filtered = []
        self.workers = {}
        self.ui_queue = queue.Queue()
        self.sort_col = "ip"
        self.sort_reverse = False
        self.auto_refresh = tk.BooleanVar(value=True)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_filter())

        self._build_style()
        self._build_widgets()
        self.root.after(100, self._poll_queue)
        self._schedule_auto_refresh()

        threading.Thread(target=self.refresh_scan, daemon=True).start()

    # ---- styling ----
    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background="#2a2a3d", fieldbackground="#2a2a3d",
                         foreground="#e0e0e0", rowheight=30, font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                         background="#3b3b55", foreground="white",
                         font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#5a5acb")])
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TEntry", fieldbackground="#2a2a3d")
        style.configure("TCheckbutton", background="#1e1e2e", foreground="#ccc")

    # ---- layout ----
    def _build_widgets(self):
        top = tk.Frame(self.root, bg="#1e1e2e")
        top.pack(fill="x", padx=12, pady=10)

        title_box = tk.Frame(top, bg="#1e1e2e")
        title_box.pack(side="left")
        tk.Label(title_box, text="🛡  NetGuard", font=("Segoe UI", 17, "bold"),
                  bg="#1e1e2e", fg="#9d9dff").pack(anchor="w")
        self.status_label = tk.Label(title_box, text="Scanning...", font=("Segoe UI", 9),
                                      bg="#1e1e2e", fg="#999")
        self.status_label.pack(anchor="w")

        btn_frame = tk.Frame(top, bg="#1e1e2e")
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="🔄 Rescan", command=self.start_rescan).pack(side="left", padx=3)
        self.block_btn = ttk.Button(btn_frame, text="⛔ Block", command=self.toggle_block)
        self.block_btn.pack(side="left", padx=3)
        ttk.Button(btn_frame, text="✏ Rename", command=self.rename_device).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="🌐 Mobile", command=self.show_mobile_info).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="⬇ Export CSV", command=self.export_csv).pack(side="left", padx=3)

        # search + auto-refresh row
        tools = tk.Frame(self.root, bg="#1e1e2e")
        tools.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(tools, text="🔍", bg="#1e1e2e", fg="#999").pack(side="left")
        entry = ttk.Entry(tools, textvariable=self.search_var, width=30)
        entry.pack(side="left", padx=(2, 12))
        ttk.Checkbutton(tools, text="Auto-refresh every 15s", variable=self.auto_refresh).pack(side="left")

        # Table
        table_frame = tk.Frame(self.root, bg="#1e1e2e")
        table_frame.pack(fill="both", expand=True, padx=12, pady=(0, 6))

        self.tree = ttk.Treeview(table_frame, columns=COLUMNS, show="headings")
        for col in COLUMNS:
            self.tree.heading(col, text=HEADINGS[col],
                               command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=WIDTHS[col], anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("you", background="#2d4d2d")
        self.tree.tag_configure("blocked", background="#4d2d2d")
        self.tree.tag_configure("new", background="#4d4420")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._on_right_click)

        # detail panel
        self.detail_label = tk.Label(self.root, text="Select a device to see details",
                                      bg="#16161e", fg="#ccc", font=("Segoe UI", 9),
                                      anchor="w", justify="left", padx=12, pady=8)
        self.detail_label.pack(fill="x", padx=12, pady=(0, 10))

    # ---- actions ----
    def start_rescan(self):
        self.status_label.config(text="Scanning...")
        threading.Thread(target=self.refresh_scan, daemon=True).start()

    def _schedule_auto_refresh(self):
        if self.auto_refresh.get():
            self.start_rescan()
        self.root.after(15000, self._schedule_auto_refresh)

    def refresh_scan(self):
        self.local_ip, self.subnet, self.gateway = get_local_ip_and_subnet()
        raw = scan_network(self.subnet, rounds=3)
        enriched = enrich_all(raw, self.local_ip)
        for d in enriched:
            d["blocked"] = d["ip"] in self.workers
        self.ui_queue.put(("devices", enriched))

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "devices":
                    new_ones = [d for d in payload if d["is_new"] and not d["is_you"]]
                    self.devices = payload
                    state.set_devices(payload, self.gateway)
                    self._apply_filter()
                    blocked_n = sum(1 for d in payload if d["ip"] in self.workers)
                    self.status_label.config(
                        text=f"{len(payload)} devices on {self.subnet}  ·  "
                             f"{blocked_n} blocked  ·  updated {time.strftime('%H:%M:%S')}")
                    for d in new_ones:
                        self._notify_new_device(d)
        except queue.Empty:
            pass

        for ip, action in state.pop_actions():
            if action == "block" and ip not in self.workers:
                self.block_ip(ip)
            elif action == "unblock" and ip in self.workers:
                self.unblock_ip(ip)

        self.root.after(500, self._poll_queue)

    def _notify_new_device(self, d):
        label = d["hostname"] if d["hostname"] != "-" else d["vendor"]
        self.status_label.config(text=f"⚠ New device joined: {label} ({d['ip']})")
        self.root.bell()

    def _apply_filter(self):
        q = self.search_var.get().strip().lower()
        if not q:
            self.filtered = list(self.devices)
        else:
            self.filtered = [
                d for d in self.devices
                if q in d["ip"].lower() or q in d["mac"].lower()
                or q in d["vendor"].lower() or q in d["hostname"].lower()
                or q in d.get("label", "").lower() or q in d["type"].lower()
            ]
        self._sort_devices()
        self._refresh_table()

    def _sort_by(self, col):
        if self.sort_col == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col = col
            self.sort_reverse = False
        self._sort_devices()
        self._refresh_table()

    def _sort_devices(self):
        key_map = {
            "icon": "type", "name": "hostname", "last_seen": "first_seen",
        }
        key = key_map.get(self.sort_col, self.sort_col)

        def sort_key(d):
            v = d.get(key)
            return (v is None, v if v is not None else "")

        try:
            self.filtered.sort(key=sort_key, reverse=self.sort_reverse)
        except TypeError:
            pass

    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for d in self.filtered:
            tags = []
            status = "Blocked" if d["ip"] in self.workers else "Online"
            if d["is_you"]:
                tags.append("you")
                status = "This device"
            if d["ip"] in self.workers:
                tags.append("blocked")
            elif d["is_new"]:
                tags.append("new")
            name = d["label"] or (d["hostname"] if d["hostname"] != "-" else "")
            icon = TYPE_ICONS.get(d["type"], "❔")
            self.tree.insert("", "end", iid=d["ip"], values=(
                icon, d["ip"], d["mac"], d["vendor"], d["type"], name,
                fmt_relative(d.get("first_seen")), status
            ), tags=tags)

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        d = next((x for x in self.devices if x["ip"] == ip), None)
        if not d:
            return
        label = d["label"] or d["hostname"]
        text = (f"{label}   |   IP: {d['ip']}   |   MAC: {d['mac']}   |   "
                f"Vendor: {d['vendor']}   |   First seen: {fmt_timestamp(d.get('first_seen'))}   |   "
                f"Seen {d.get('times_seen', 1)} time(s)")
        self.detail_label.config(text=text)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=0, bg="#2a2a3d", fg="white")
        d = next((x for x in self.devices if x["ip"] == iid), None)
        if d and not d["is_you"]:
            is_blocked = iid in self.workers
            menu.add_command(label="Unblock" if is_blocked else "Block",
                              command=self.toggle_block)
            menu.add_command(label="Rename...", command=self.rename_device)
        menu.add_command(label="Copy IP", command=lambda: self.root.clipboard_append(iid))
        menu.add_command(label="Copy MAC", command=lambda: self.root.clipboard_append(d["mac"]) if d else None)
        menu.tk_popup(event.x_root, event.y_root)

    def rename_device(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("NetGuard", "Select a device first.")
            return
        ip = sel[0]
        d = next((x for x in self.devices if x["ip"] == ip), None)
        if not d:
            return
        new_name = simpledialog.askstring("Rename device",
                                           f"Label for {d['ip']} ({d['vendor']}):",
                                           initialvalue=d.get("label", ""))
        if new_name is not None:
            history.set_label(d["mac"], new_name.strip())
            d["label"] = new_name.strip()
            self._refresh_table()

    def toggle_block(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("NetGuard", "Select a device first.")
            return
        ip = sel[0]
        device = next((d for d in self.devices if d["ip"] == ip), None)
        if not device:
            return
        if device["is_you"]:
            messagebox.showwarning("NetGuard", "You can't block your own device.")
            return
        if ip in self.workers:
            self.unblock_ip(ip)
        else:
            self.block_ip(ip)

    def block_ip(self, ip):
        device = next((d for d in self.devices if d["ip"] == ip), None)
        if not device:
            return
        gw_mac = get_mac(self.gateway)
        if not device["mac"] or not gw_mac:
            messagebox.showerror("NetGuard", "Could not resolve MAC addresses.")
            return
        worker = BlockWorker(ip, device["mac"], self.gateway, gw_mac)
        worker.start()
        self.workers[ip] = worker
        state.set_blocked(ip, True)
        self._refresh_table()

    def unblock_ip(self, ip):
        worker = self.workers.pop(ip, None)
        if worker:
            worker.stop()
        state.set_blocked(ip, False)
        self._refresh_table()

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files", "*.csv")],
                                             initialfile="netguard_devices.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "MAC", "Vendor", "Type", "Name", "First Seen", "Status"])
            for d in self.filtered:
                status = "Blocked" if d["ip"] in self.workers else "Online"
                writer.writerow([d["ip"], d["mac"], d["vendor"], d["type"],
                                  d["label"] or d["hostname"], fmt_timestamp(d.get("first_seen")), status])
        messagebox.showinfo("NetGuard", f"Exported to {path}")

    def show_mobile_info(self):
        try:
            import webserver
            url, qr_path = webserver.ensure_server_running()
        except ModuleNotFoundError as e:
            messagebox.showerror(
                "NetGuard - Missing dependency",
                f"A required package is missing: {e.name}\n\n"
                f"Open a terminal in this folder and run:\n"
                f"pip install -r requirements.txt"
            )
            return
        except Exception as e:
            messagebox.showerror("NetGuard", f"Could not start mobile server:\n{e}")
            return

        top = tk.Toplevel(self.root)
        top.title("Mobile Access")
        top.configure(bg="#1e1e2e")
        tk.Label(top, text="Scan this QR code from your phone\n(same Wi-Fi network):",
                  bg="#1e1e2e", fg="white", font=("Segoe UI", 11)).pack(pady=10)
        try:
            img = tk.PhotoImage(file=qr_path)
            lbl = tk.Label(top, image=img, bg="#1e1e2e")
            lbl.image = img
            lbl.pack(pady=10)
        except Exception:
            tk.Label(top, text="(QR image could not be loaded - use the link below)",
                      bg="#1e1e2e", fg="#e05c5c").pack(pady=10)
        tk.Label(top, text=url, bg="#1e1e2e", fg="#9d9dff",
                  font=("Consolas", 11, "bold")).pack(pady=(0, 10))


def main():
    root = tk.Tk()
    app = NetGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
