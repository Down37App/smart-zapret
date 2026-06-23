# -*- coding: utf-8 -*-
import sqlite3
import os
import json
import time
import re
import csv

DB_FILE = os.path.join("core", "models", "history.sqlite")
CACHE_FILE = os.path.join("core", "models", "geoip_cache.json")

class TelemetryLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        self.conn = sqlite3.connect(DB_FILE)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        # 1. Таблица истории запусков
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS run_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT,
                asn TEXT,
                connect_lat REAL,
                loss REAL,
                config_key TEXT,
                success_rate REAL,
                yt_score REAL,
                discord_score REAL,
                general_score REAL,
                zapret_version TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 2. НОВАЯ ТАБЛИЦА: Высокоэнтропийный датасет для обучения будущих нейросетей и реверс-инжиниринга ТСПУ
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS future_ai_dataset (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                provider TEXT,
                asn TEXT,
                os TEXT,
                zapret_version TEXT,
                features_json TEXT,  -- Входные параметры сети, стратегии и времени (ИИ-признаки)
                targets_json TEXT    -- Выходные параметры замеров доступности и L7-аномалий (ИИ-цели)
            )
        """)
        self.conn.commit()
        
        # Мигратор колонок для run_history
        columns_to_add = [
            ("yt_score", "REAL"),
            ("discord_score", "REAL"),
            ("general_score", "REAL")
        ]
        for col_name, col_type in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE run_history ADD COLUMN {col_name} {col_type}")
                self.conn.commit()
            except sqlite3.OperationalError:
                pass

    def get_network_info_cached(self):
        """Каскадный резолвер провайдера/ASN с защитой от блокировок ТСПУ."""
        now = time.time()
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    cache = json.load(f)
                    if now - cache.get("cached_at", 0) < 86400:
                        if cache.get("provider") and cache.get("asn") != "unknown":
                            return cache["provider"], cache["asn"]
            except Exception:
                pass

        provider, asn = "unknown", "unknown"
        services = [
            {"url": "http://ip-api.com/json/", "prov_key": "org", "asn_key": "as"},
            {"url": "https://ipapi.co/json/", "prov_key": "org", "asn_key": "asn"},
            {"url": "https://ipinfo.io/json", "prov_key": "org", "asn_key": "org"}
        ]
        
        import urllib.request
        for srv in services:
            try:
                req = urllib.request.Request(srv["url"], headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3.0) as r:
                    data = json.loads(r.read().decode('utf-8'))
                    
                    raw_provider = data.get(srv["prov_key"], "")
                    raw_asn = str(data.get(srv["asn_key"], ""))
                    
                    asn_match = re.search(r'(AS\d+)', raw_asn, re.IGNORECASE)
                    parsed_asn = asn_match.group(1).upper() if asn_match else raw_asn
                    parsed_provider = re.sub(r'^AS\d+\s+', '', raw_provider).strip()
                    
                    if parsed_provider and parsed_asn and parsed_asn != "unknown":
                        provider = parsed_provider
                        asn = parsed_asn
                        break
            except Exception:
                continue
                
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({"provider": provider, "asn": asn, "cached_at": now}, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
            
        return provider, asn

    def log_run_detailed(self, features, config_key, success_rate, yt_score, discord_score, general_score, zapret_ver):
        """Записывает подробные детальные результаты по каждому сетевому сервису в базу."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO run_history (provider, asn, connect_lat, loss, config_key, success_rate, yt_score, discord_score, general_score, zapret_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (features["provider"], features["asn"], features["connect_latency"], 
              features["packet_loss"], config_key, success_rate, yt_score, discord_score, general_score, zapret_ver))
        self.conn.commit()

    def log_ai_training_entry(self, provider, asn, os_platform, zapret_ver, features_dict, targets_dict):
        """
        Записывает полную многомерную структуру замера в базу ИИ-обучения.
        features_dict: содержит состояние времени, среды и параметров десинхронизации.
        targets_dict: содержит раздельные успехи/ошибки/L7-симптомы по каждой цели.
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO future_ai_dataset (provider, asn, os, zapret_version, features_json, targets_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                provider, asn, os_platform, zapret_ver,
                json.dumps(features_dict, ensure_ascii=False),
                json.dumps(targets_dict, ensure_ascii=False)
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"[-] Ошибка записи ИИ-датасета: {e}")

    def get_best_local_strategy(self, provider, asn):
        """Ищет лучшую общую стратегию в истории для текущего провайдера."""
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                SELECT config_key, success_rate 
                FROM run_history 
                WHERE (provider = ? OR asn = ?) AND success_rate >= 80.0
                ORDER BY success_rate DESC, timestamp DESC 
                LIMIT 1
            """, (provider, asn))
            row = cursor.fetchone()
            if row:
                return row[0], row[1]
        except sqlite3.Error as e:
            print(f"[-] Ошибка обращения к локальной БД: {e}")
        return None, 0.0

    def get_top_historical_strategies(self, provider, asn, limit=5):
        """B4: Извлекает ТОП-5 лучших исторических стратегий."""
        cursor = self.conn.cursor()
        strategies = []
        try:
            cursor.execute("""
                SELECT DISTINCT config_key, success_rate
                FROM run_history
                WHERE (provider = ? OR asn = ?) AND success_rate > 0
                ORDER BY success_rate DESC, timestamp DESC
                LIMIT ?
            """, (provider, asn, limit))
            rows = cursor.fetchall()
            for r in rows:
                strategies.append({"key": r[0], "score": r[1]})
        except sqlite3.Error:
            pass
        return strategies

    def get_provider_stats(self, provider, asn):
        """Извлекает историческую статистику запусков на данном провайдере."""
        cursor = self.conn.cursor()
        stats = {"total_runs": 0, "avg_success": 0.0, "best_key": None}
        try:
            cursor.execute("""
                SELECT COUNT(*), AVG(success_rate)
                FROM run_history
                WHERE provider = ? OR asn = ?
            """, (provider, asn))
            row = cursor.fetchone()
            if row and row[0] > 0:
                stats["total_runs"] = row[0]
                stats["avg_success"] = round(row[1], 1)
                
            cursor.execute("""
                SELECT config_key
                FROM run_history
                WHERE provider = ? OR asn = ?
                ORDER BY success_rate DESC, timestamp DESC
                LIMIT 1
            """, (provider, asn))
            best_row = cursor.fetchone()
            if best_row:
                stats["best_key"] = best_row[0]
        except sqlite3.Error:
            pass
        return stats

    def export_to_csv(self, filepath):
        """B3: Экспортирует всю локальную историю базы данных в читаемый формат CSV."""
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM run_history ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            headers = [description[0] for description in cursor.description]
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            return True
        except Exception as e:
            print(f"[-] Ошибка экспорта CSV: {e}")
            return False