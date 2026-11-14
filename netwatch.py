# NetWatch PRO — Neon LAN Monitor
# Python 3.9+
# Windows 10/11
# Запуск: python netwatch.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import socket
import sqlite3
import threading
import ipaddress
import platform
import re
import csv
import json
import time
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


APP_NAME = "NetWatch PRO"
DB_FILE = "netwatch.db"

BG = "#080d18"
PANEL = "#101a2b"
PANEL2 = "#142238"
CYAN = "#00e5ff"
GREEN = "#00ff9c"
RED = "#ff426d"
PURPLE = "#a879ff"
TEXT = "#e8f3ff"
MUTED = "#8497b2"
YELLOW = "#ffd166"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"


def get_default_subnet():
    ip = get_local_ip()
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"


def ping_host(ip):
    try:
        if platform.system().lower() == "windows":
            command = ["ping", "-n", "1", "-w", "450", ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=2
        )

        output = result.stdout + result.stderr

        if result.returncode == 0:
            match = re.search(r"time[=<]\s*([\d.,]+)\s*ms", output, re.I)
            if match:
                latency = float(match.group(1).replace(",", "."))
            else:
                latency = 1.0
            return True, latency

        return False, None

    except Exception:
        return False, None


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def get_arp_table():
    result = {}

    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            errors="ignore",
            timeout=5
        )

        for line in output.splitlines():
            match = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"([0-9a-fA-F-]{17})",
                line
            )

            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                result[ip] = mac

    except Exception:
        pass

    return result


class Database:

    def __init__(self):
        self.conn = sqlite3.connect(
            DB_FILE,
            check_same_thread=False
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.Lock()
        self.create_tables()

    def create_tables(self):
        with self.lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    label TEXT DEFAULT '',
                    favorite INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT DEFAULT 'Offline'
                )
            """)

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    status TEXT,
                    latency REAL,
                    timestamp TEXT
                )
            """)

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT,
                    timestamp TEXT
                )
            """)

            self.conn.commit()

    def save_device(self, device):
        with self.lock:
            old = self.conn.execute(
                "SELECT ip FROM devices WHERE ip=?",
                (device["ip"],)
            ).fetchone()

            if old:
                self.conn.execute("""
                    UPDATE devices
                    SET mac=?, hostname=?, last_seen=?, status=?
                    WHERE ip=?
                """, (
                    device["mac"],
                    device["hostname"],
                    device["last_seen"],
                    device["status"],
                    device["ip"]
                ))
            else:
                self.conn.execute("""
                    INSERT INTO devices
                    (ip, mac, hostname, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    device["ip"],
                    device["mac"],
                    device["hostname"],
                    device["last_seen"],
                    device["last_seen"],
                    device["status"]
                ))

            self.conn.commit()

    def save_history(self, ip, status, latency):
        with self.lock:
            self.conn.execute("""
                INSERT INTO history (ip, status, latency, timestamp)
                VALUES (?, ?, ?, ?)
            """, (ip, status, latency, now()))
            self.conn.commit()

    def event(self, message):
        with self.lock:
            self.conn.execute(
                "INSERT INTO events (message, timestamp) VALUES (?, ?)",
                (message, now())
            )
            self.conn.commit()

    def get_devices(self):
        with self.lock:
            rows = self.conn.execute("""
                SELECT ip, mac, hostname, label, favorite,
                       first_seen, last_seen, status
                FROM devices
                ORDER BY favorite DESC, ip
            """).fetchall()

        keys = [
            "ip", "mac", "hostname", "label", "favorite",
            "first_seen", "last_seen", "status"
        ]

        return [dict(zip(keys, row)) for row in rows]

    def get_history(self, limit=200):
        with self.lock:
            return self.conn.execute("""
                SELECT ip, status, latency, timestamp
                FROM history
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()

    def get_events(self, limit=100):
        with self.lock:
            return self.conn.execute("""
                SELECT message, timestamp
                FROM events
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()

    def update_label(self, ip, label):
        with self.lock:
            self.conn.execute(
                "UPDATE devices SET label=? WHERE ip=?",
                (label, ip)
            )
            self.conn.commit()

    def toggle_favorite(self, ip):
        with self.lock:
            self.conn.execute("""
                UPDATE devices
                SET favorite = CASE WHEN favorite=1 THEN 0 ELSE 1 END
                WHERE ip=?
            """, (ip,))
            self.conn.commit()

    def close(self):
        self.conn.close()


class NetWatchApp:

    def __init__(self, root):
        self.root = root
        self.db = Database()

        self.devices = {}
        self.previous_online = set()

        self.scanning = False
        self.auto_scan = True
        self.scan_interval = 30
        self.subnet = get_default_subnet()

        self.selected_ip = None
        self.latency_points = []

        self.setup_window()
        self.setup_style()
        self.build_interface()

        self.refresh_devices()
        self.refresh_history()
        self.refresh_events()

        self.root.after(1000, self.auto_scan_loop)
        self.root.after(1500, self.start_scan)

    def setup_window(self):
        self.root.title(APP_NAME)
        self.root.geometry("1250x790")
        self.root.minsize(1000, 650)
        self.root.configure(bg=BG)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=PANEL2,
            foreground=CYAN,
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        )

        style.map(
            "Treeview",
            background=[("selected", "#17405b")],
            foreground=[("selected", "#ffffff")]
        )

    def neon_button(self, parent, text, command, color=CYAN):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=PANEL2,
            fg=color,
            activebackground=color,
            activeforeground=BG,
            relief="flat",
            bd=0,
            padx=14,
            pady=9,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2"
        )

    def build_interface(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=22, pady=(18, 8))

        tk.Label(
            header,
            text="NETWATCH",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI", 24, "bold")
        ).pack(side="left")

        tk.Label(
            header,
            text=" PRO",
            bg=BG,
            fg=PURPLE,
            font=("Segoe UI", 24, "bold")
        ).pack(side="left")

        self.status_label = tk.Label(
            header,
            text="● SYSTEM READY",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 10, "bold")
        )
        self.status_label.pack(side="right", pady=10)

        self.build_stats()

        toolbar = tk.Frame(self.root, bg=BG)
        toolbar.pack(fill="x", padx=22, pady=10)

        self.neon_button(
            toolbar, "⟳  SCAN NETWORK", self.start_scan
        ).pack(side="left", padx=(0, 8))

        self.neon_button(
            toolbar, "★  FAVORITES", self.show_favorites, PURPLE
        ).pack(side="left", padx=5)

        self.neon_button(
            toolbar, "↓  EXPORT CSV", self.export_csv, GREEN
        ).pack(side="left", padx=5)

        self.neon_button(
            toolbar, "↓  EXPORT JSON", self.export_json, GREEN
        ).pack(side="left", padx=5)

        self.notif_label = tk.Label(
            toolbar,
            text="Automatic scan: ON",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 9)
        )
        self.notif_label.pack(side="right")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(
            fill="both",
            expand=True,
            padx=22,
            pady=(5, 15)
        )

        self.tab_devices = tk.Frame(self.notebook, bg=BG)
        self.tab_history = tk.Frame(self.notebook, bg=BG)
        self.tab_events = tk.Frame(self.notebook, bg=BG)
        self.tab_analytics = tk.Frame(self.notebook, bg=BG)
        self.tab_settings = tk.Frame(self.notebook, bg=BG)

        self.notebook.add(self.tab_devices, text="  DEVICES  ")
        self.notebook.add(self.tab_history, text="  HISTORY  ")
        self.notebook.add(self.tab_events, text="  EVENTS  ")
        self.notebook.add(self.tab_analytics, text="  ANALYTICS  ")
        self.notebook.add(self.tab_settings, text="  SETTINGS  ")

        self.build_devices_tab()
        self.build_history_tab()
        self.build_events_tab()
        self.build_analytics_tab()
        self.build_settings_tab()

    def build_stats(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", padx=22, pady=8)

        self.stat_total = self.stat_card(frame, "DEVICES", "0", CYAN)
        self.stat_online = self.stat_card(frame, "ONLINE", "0", GREEN)
        self.stat_offline = self.stat_card(frame, "OFFLINE", "0", RED)
        self.stat_latency = self.stat_card(frame, "AVG PING", "—", PURPLE)

    def stat_card(self, parent, title, value, color):
        card = tk.Frame(
            parent,
            bg=PANEL,
            highlightbackground=color,
            highlightthickness=1
        )
        card.pack(side="left", fill="x", expand=True, padx=5)

        tk.Label(
            card,
            text=title,
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(pady=(10, 2))

        label = tk.Label(
            card,
            text=value,
            bg=PANEL,
            fg=color,
            font=("Segoe UI", 22, "bold")
        )
        label.pack(pady=(0, 10))

        return label

    def build_devices_tab(self):
        top = tk.Frame(self.tab_devices, bg=BG)
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(
            top,
            text="Search:",
            bg=BG,
            fg=TEXT
        ).pack(side="left")

        self.search_var = tk.StringVar()
        search = tk.Entry(
            top,
            textvariable=self.search_var,
            bg=PANEL,
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            font=("Segoe UI", 11)
        )
        search.pack(side="left", fill="x", expand=True, padx=10)
        search.bind("<KeyRelease>", lambda e: self.refresh_devices())

        self.filter_var = tk.StringVar(value="All")
        filter_box = ttk.Combobox(
            top,
            textvariable=self.filter_var,
            values=["All", "Online", "Offline", "Favorites"],
            state="readonly",
            width=12
        )
        filter_box.pack(side="right")
        filter_box.bind(
            "<<ComboboxSelected>>",
            lambda e: self.refresh_devices()
        )

        columns = (
            "ip", "hostname", "mac", "label",
            "status", "latency", "last_seen"
        )

        self.device_tree = ttk.Treeview(
            self.tab_devices,
            columns=columns,
            show="headings"
        )

        headings = {
            "ip": "IP ADDRESS",
            "hostname": "HOSTNAME",
            "mac": "MAC ADDRESS",
            "label": "CUSTOM NAME",
            "status": "STATUS",
            "latency": "PING",
            "last_seen": "LAST SEEN"
        }

        widths = {
            "ip": 120,
            "hostname": 150,
            "mac": 145,
            "label": 130,
            "status": 90,
            "latency": 80,
            "last_seen": 145
        }

        for col in columns:
            self.device_tree.heading(col, text=headings[col])
            self.device_tree.column(col, width=widths[col], anchor="center")

        self.device_tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        self.device_tree.tag_configure(
            "online",
            foreground=GREEN
        )
        self.device_tree.tag_configure(
            "offline",
            foreground=RED
        )
        self.device_tree.tag_configure(
            "favorite",
            foreground=PURPLE
        )

        self.device_tree.bind(
            "<Double-1>",
            self.device_details
        )

        bottom = tk.Frame(self.tab_devices, bg=BG)
        bottom.pack(fill="x", padx=10, pady=8)

        self.neon_button(
            bottom, "★ Favorite", self.toggle_favorite, PURPLE
        ).pack(side="left", padx=4)

        self.neon_button(
            bottom, "✎ Rename", self.rename_device, CYAN
        ).pack(side="left", padx=4)

        self.neon_button(
            bottom, "Details", self.device_details, GREEN
        ).pack(side="left", padx=4)

    def build_history_tab(self):
        columns = ("ip", "status", "latency", "timestamp")

        self.history_tree = ttk.Treeview(
            self.tab_history,
            columns=columns,
            show="headings"
        )

        for col, title, width in [
            ("ip", "IP ADDRESS", 180),
            ("status", "STATUS", 130),
            ("latency", "LATENCY MS", 130),
            ("timestamp", "TIMESTAMP", 230)
        ]:
            self.history_tree.heading(col, text=title)
            self.history_tree.column(col, width=width, anchor="center")

        self.history_tree.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=12
        )

        self.neon_button(
            self.tab_history,
            "Refresh history",
            self.refresh_history
        ).pack(pady=5)

    def build_events_tab(self):
        self.events_text = tk.Text(
            self.tab_events,
            bg=PANEL,
            fg=GREEN,
            insertbackground=CYAN,
            font=("Consolas", 10),
            relief="flat",
            wrap="word"
        )
        self.events_text.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=12
        )

        self.neon_button(
            self.tab_events,
            "Refresh events",
            self.refresh_events
        ).pack(pady=5)

    def build_analytics_tab(self):
        self.analytics_canvas = tk.Canvas(
            self.tab_analytics,
            bg=PANEL,
            highlightthickness=1,
            highlightbackground=CYAN
        )
        self.analytics_canvas.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        self.analytics_canvas.bind(
            "<Configure>",
            lambda e: self.draw_graph()
        )

        self.neon_button(
            self.tab_analytics,
            "Refresh graph",
            self.draw_graph
        ).pack(pady=5)

    def build_settings_tab(self):
        frame = tk.Frame(self.tab_settings, bg=BG)
        frame.pack(anchor="nw", padx=30, pady=25)

        tk.Label(
            frame,
            text="NETWORK SETTINGS",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI", 16, "bold")
        ).pack(anchor="w", pady=(0, 20))

        tk.Label(
            frame,
            text="Subnet (CIDR):",
            bg=BG,
            fg=TEXT
        ).pack(anchor="w")

        self.subnet_var = tk.StringVar(value=self.subnet)

        tk.Entry(
            frame,
            textvariable=self.subnet_var,
            bg=PANEL,
            fg=TEXT,
            insertbackground=CYAN,
            width=35,
            relief="flat"
        ).pack(anchor="w", pady=7)

        tk.Label(
            frame,
            text="Scan interval (seconds):",
            bg=BG,
            fg=TEXT
        ).pack(anchor="w", pady=(15, 0))

        self.interval_var = tk.StringVar(value="30")

        tk.Entry(
            frame,
            textvariable=self.interval_var,
            bg=PANEL,
            fg=TEXT,
            insertbackground=CYAN,
            width=15,
            relief="flat"
        ).pack(anchor="w", pady=7)

        self.auto_var = tk.BooleanVar(value=True)

        tk.Checkbutton(
            frame,
            text="Enable automatic scanning",
            variable=self.auto_var,
            bg=BG,
            fg=GREEN,
            selectcolor=PANEL,
            activebackground=BG,
            activeforeground=CYAN
        ).pack(anchor="w", pady=12)

        self.neon_button(
            frame,
            "SAVE SETTINGS",
            self.save_settings
        ).pack(anchor="w", pady=10)

        tk.Label(
            frame,
            text="Database: netwatch.db\n"
                 "Scan method: ICMP ping + ARP table\n"
                 "Platform: " + platform.system(),
            bg=BG,
            fg=MUTED,
            justify="left"
        ).pack(anchor="w", pady=20)

    def save_settings(self):
        try:
            network = ipaddress.ip_network(
                self.subnet_var.get().strip(),
                strict=False
            )

            interval = int(self.interval_var.get())

            if interval < 5 or interval > 3600:
                raise ValueError("Interval must be 5–3600 seconds.")

            if network.num_addresses > 1024:
                raise ValueError("Subnet is too large. Maximum: 1024 addresses.")

            self.subnet = str(network)
            self.scan_interval = interval
            self.auto_scan = self.auto_var.get()

            self.db.event(
                f"Settings changed: {self.subnet}, interval {interval}s"
            )

            messagebox.showinfo(
                APP_NAME,
                "Settings saved successfully."
            )

        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def start_scan(self):
        if self.scanning:
            return

        self.scanning = True
        self.status_label.config(
            text="● SCANNING NETWORK...",
            fg=YELLOW
        )

        threading.Thread(
            target=self.scan_network,
            daemon=True
        ).start()

    def scan_network(self):
        try:
            network = ipaddress.ip_network(
                self.subnet,
                strict=False
            )

            hosts = list(network.hosts())

            found = []

            with ThreadPoolExecutor(max_workers=64) as executor:
                futures = {
                    executor.submit(ping_host, str(ip)): str(ip)
                    for ip in hosts
                }

                for future in as_completed(futures):
                    ip = futures[future]

                    try:
                        online, latency = future.result()
                    except Exception:
                        online, latency = False, None

                    if online:
                        found.append((ip, latency))

            arp = get_arp_table()
            current_online = set()

            for ip, latency in found:
                current_online.add(ip)

                hostname = get_hostname(ip)
                mac = arp.get(ip, "Unknown")

                previous = self.devices.get(ip)

                device = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "last_seen": now(),
                    "status": "Online",
                    "latency": latency
                }

                self.devices[ip] = device
                self.db.save_device(device)
                self.db.save_history(ip, "Online", latency)

                if ip not in self.previous_online:
                    if previous is None:
                        self.db.event(f"NEW DEVICE DETECTED: {ip}")
                    else:
                        self.db.event(f"DEVICE ONLINE: {ip}")

            for ip in list(self.devices.keys()):
                if ip not in current_online:
                    if self.devices[ip]["status"] != "Offline":
                        self.db.event(f"DEVICE OFFLINE: {ip}")

                    self.devices[ip]["status"] = "Offline"
                    self.db.save_history(ip, "Offline", None)

                    stored = next(
                        (
                            d for d in self.db.get_devices()
                            if d["ip"] == ip
                        ),
                        None
                    )

                    if stored:
                        self.db.save_device({
                            "ip": ip,
                            "mac": stored["mac"],
                            "hostname": stored["hostname"],
                            "last_seen": stored["last_seen"],
                            "status": "Offline"
                        })

            self.previous_online = current_online

            self.root.after(0, self.scan_complete)

        except Exception as e:
            self.root.after(
                0,
                lambda: self.scan_error(str(e))
            )

    def scan_complete(self):
        self.scanning = False
        self.status_label.config(
            text="● SYSTEM ONLINE",
            fg=GREEN
        )

        self.refresh_devices()
        self.refresh_history()
        self.refresh_events()
        self.update_stats()
        self.draw_graph()

    def scan_error(self, error):
        self.scanning = False
        self.status_label.config(
            text="● SCAN ERROR",
            fg=RED
        )
        self.db.event("SCAN ERROR: " + error)
        self.refresh_events()

    def auto_scan_loop(self):
        if self.auto_scan and not self.scanning:
            self.start_scan()

        self.root.after(
            max(5, self.scan_interval) * 1000,
            self.auto_scan_loop
        )

    def refresh_devices(self):
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        stored = self.db.get_devices()
        search = self.search_var.get().lower()
        filter_mode = self.filter_var.get()

        for d in stored:
            ip = d["ip"]
            live = self.devices.get(ip)

            status = live["status"] if live else d["status"]
            latency = live.get("latency") if live else None

            if filter_mode == "Online" and status != "Online":
                continue
            if filter_mode == "Offline" and status != "Offline":
                continue
            if filter_mode == "Favorites" and not d["favorite"]:
                continue

            text = " ".join([
                str(d["ip"]),
                str(d["hostname"]),
                str(d["mac"]),
                str(d["label"])
            ]).lower()

            if search and search not in text:
                continue

            latency_text = (
                f"{latency:.1f} ms"
                if latency is not None else "—"
            )

            tag = "favorite" if d["favorite"] else (
                "online" if status == "Online" else "offline"
            )

            self.device_tree.insert(
                "",
                "end",
                iid=ip,
                values=(
                    ip,
                    d["hostname"],
                    d["mac"],
                    d["label"],
                    status,
                    latency_text,
                    d["last_seen"]
                ),
                tags=(tag,)
            )

        self.update_stats()

    def update_stats(self):
        all_devices = self.db.get_devices()

        online = [
            d for d in all_devices
            if d["status"] == "Online"
        ]

        latencies = [
            d.get("latency")
            for d in self.devices.values()
            if d.get("latency") is not None
        ]

        self.stat_total.config(text=str(len(all_devices)))
        self.stat_online.config(text=str(len(online)))
        self.stat_offline.config(
            text=str(max(0, len(all_devices) - len(online)))
        )

        if latencies:
            avg = sum(latencies) / len(latencies)
            self.stat_latency.config(text=f"{avg:.1f} ms")
        else:
            self.stat_latency.config(text="—")

    def get_selected_ip(self):
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showwarning(
                APP_NAME,
                "Select a device first."
            )
            return None
        return selected[0]

    def toggle_favorite(self):
        ip = self.get_selected_ip()
        if not ip:
            return

        self.db.toggle_favorite(ip)
        self.refresh_devices()

    def rename_device(self):
        ip = self.get_selected_ip()
        if not ip:
            return

        current = next(
            (
                d["label"] for d in self.db.get_devices()
                if d["ip"] == ip
            ),
            ""
        )

        dialog = tk.Toplevel(self.root)
        dialog.title("Rename device")
        dialog.geometry("350x150")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="Enter custom device name:",
            bg=BG,
            fg=TEXT
        ).pack(pady=12)

        var = tk.StringVar(value=current)

        entry = tk.Entry(
            dialog,
            textvariable=var,
            bg=PANEL,
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat"
        )
        entry.pack(fill="x", padx=20)
        entry.focus_set()

        def save():
            self.db.update_label(ip, var.get().strip())
            self.db.event(f"DEVICE RENAMED: {ip}")
            dialog.destroy()
            self.refresh_devices()
            self.refresh_events()

        self.neon_button(
            dialog,
            "SAVE",
            save
        ).pack(pady=12)

    def device_details(self, event=None):
        ip = self.get_selected_ip()
        if not ip:
            return

        stored = next(
            (
                d for d in self.db.get_devices()
                if d["ip"] == ip
            ),
            None
        )

        if not stored:
            return

        live = self.devices.get(ip, {})

        details = (
            f"IP ADDRESS: {ip}\n\n"
            f"HOSTNAME: {stored['hostname']}\n\n"
            f"MAC ADDRESS: {stored['mac']}\n\n"
            f"CUSTOM NAME: {stored['label']}\n\n"
            f"STATUS: {live.get('status', stored['status'])}\n\n"
            f"FIRST SEEN: {stored['first_seen']}\n\n"
            f"LAST SEEN: {stored['last_seen']}\n\n"
            f"FAVORITE: {'YES' if stored['favorite'] else 'NO'}\n\n"
            f"LATENCY: {live.get('latency', 'Unknown')}"
        )

        messagebox.showinfo("Device details", details)

    def show_favorites(self):
        self.filter_var.set("Favorites")
        self.notebook.select(self.tab_devices)
        self.refresh_devices()

    def refresh_history(self):
        if not hasattr(self, "history_tree"):
            return

        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        for row in self.db.get_history(300):
            ip, status, latency, timestamp = row

            self.history_tree.insert(
                "",
                "end",
                values=(
                    ip,
                    status,
                    f"{latency:.1f}" if latency is not None else "—",
                    timestamp
                )
            )

    def refresh_events(self):
        if not hasattr(self, "events_text"):
            return

        self.events_text.delete("1.0", "end")

        for message, timestamp in self.db.get_events(200):
            self.events_text.insert(
                "end",
                f"[{timestamp}]  {message}\n"
            )

        self.events_text.see("end")

    def draw_graph(self):
        if not hasattr(self, "analytics_canvas"):
            return

        canvas = self.analytics_canvas
        canvas.delete("all")

        width = canvas.winfo_width()
        height = canvas.winfo_height()

        if width < 100 or height < 100:
            return

        canvas.create_text(
            20, 20,
            text="NETWORK LATENCY HISTORY",
            fill=CYAN,
            anchor="nw",
            font=("Segoe UI", 13, "bold")
        )

        rows = self.db.get_history(50)
        values = [
            float(row[2])
            for row in reversed(rows)
            if row[2] is not None
        ]

        left, right = 55, width - 25
        top, bottom = 70, height - 55

        for i in range(5):
            y = top + (bottom - top) * i / 4
            canvas.create_line(
                left, y, right, y,
                fill="#24354b",
                dash=(3, 5)
            )

        if len(values) < 2:
            canvas.create_text(
                width / 2,
                height / 2,
                text="Waiting for latency data...",
                fill=MUTED,
                font=("Segoe UI", 12)
            )
            return

        max_value = max(max(values), 5)

        points = []

        for i, value in enumerate(values):
            x = left + (right - left) * i / (len(values) - 1)
            y = bottom - (value / max_value) * (bottom - top)
            points.extend([x, y])

        canvas.create_line(
            *points,
            fill=CYAN,
            width=3,
            smooth=True
        )

        for i in range(0, len(points), 2):
            canvas.create_oval(
                points[i] - 3,
                points[i + 1] - 3,
                points[i] + 3,
                points[i + 1] + 3,
                fill=GREEN,
                outline=""
            )

        canvas.create_text(
            left,
            height - 25,
            text="Older",
            fill=MUTED,
            anchor="w"
        )

        canvas.create_text(
            right,
            height - 25,
            text="Newer",
            fill=MUTED,
            anchor="e"
        )

        canvas.create_text(
            right,
            top,
            text=f"MAX {max_value:.1f} ms",
            fill=PURPLE,
            anchor="ne"
        )

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="netwatch_devices.csv"
        )

        if not path:
            return

        devices = self.db.get_devices()

        try:
            with open(
                path,
                "w",
                newline="",
                encoding="utf-8-sig"
            ) as file:
                writer = csv.writer(file)

                writer.writerow([
                    "IP", "MAC", "Hostname", "Label",
                    "Favorite", "Status", "First seen", "Last seen"
                ])

                for d in devices:
                    writer.writerow([
                        d["ip"],
                        d["mac"],
                        d["hostname"],
                        d["label"],
                        d["favorite"],
                        d["status"],
                        d["first_seen"],
                        d["last_seen"]
                    ])

            messagebox.showinfo(
                APP_NAME,
                "CSV export completed."
            )

        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="netwatch_devices.json"
        )

        if not path:
            return

        try:
            data = {
                "application": APP_NAME,
                "exported_at": now(),
                "subnet": self.subnet,
                "devices": self.db.get_devices(),
                "history": self.db.get_history(1000),
                "events": self.db.get_events(500)
            }

            with open(path, "w", encoding="utf-8") as file:
                json.dump(
                    data,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

            messagebox.showinfo(
                APP_NAME,
                "JSON export completed."
            )

        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def close(self):
        self.db.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = NetWatchApp(root)

    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()


if __name__ == "__main__":
    main()