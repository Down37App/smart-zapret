# -*- coding: utf-8 -*-
import sqlite3

class StatisticsEngine:
    def __init__(self, db_logger):
        self.db = db_logger

    def check_dpi_evolution_alerts(self, current_key, current_rate, provider, asn):
        """
        Сравнивает текущий замер со средними показателями за прошлые 30 дней.
        Если успешность упала более чем на 30%, возвращает сигнал тревоги (DPI Alert).
        """
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT AVG(success_rate), COUNT(*)
            FROM run_history
            WHERE config_key = ? AND provider = ? AND asn = ? 
              AND timestamp >= datetime('now', '-30 days') AND timestamp < datetime('now', '-1 hour')
        """, (current_key, provider, asn))
        row = cursor.fetchone()

        if row and row[0] is not None and row[1] >= 3:
            historical_avg = row[0]
            if historical_avg - current_rate >= 30.0:
                return True, historical_avg
        return False, 0.0