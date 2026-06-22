# -*- coding: utf-8 -*-
import sqlite3
import os
import json
import time

DB_FILE = os.path.join("core", "models", "history.sqlite")
CACHE_FILE = os.path.join("core", "models", "geoip_cache.json")

class TelemetryLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        self.conn = sqlite3.connect(DB_FILE)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS run_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT,
                asn TEXT,
                connect_lat REAL,
                loss REAL,
                config_key TEXT,
                success_rate REAL,
                zapret_version TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def get_network_info_cached(self):
        now = time.time()
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    cache = json.load(f)
                    if now - cache.get("cached_at", 0) < 86400:
                        return cache["provider"], cache["asn"]
            except Exception:
                pass

        provider, asn = "unknown", "unknown"
        try:
            import urllib.request
            req = urllib.request.Request("http://ip-api.com/json/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3.0) as r:
                data = json.loads(r.read().decode('utf-8'))
                provider = data.get("org", "unknown")
                asn = data.get("asn", "unknown")
                
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump({"provider": provider, "asn": asn, "cached_at": now}, f)
        except Exception:
            pass
        return provider, asn

    def log_run(self, features, config_key, success_rate, zapret_ver):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO run_history (provider, asn, connect_lat, loss, config_key, success_rate, zapret_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (features["provider"], features["asn"], features["connect_latency"], 
              features["packet_loss"], config_key, success_rate, zapret_ver))
        self.conn.commit()