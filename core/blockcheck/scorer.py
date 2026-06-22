# -*- coding: utf-8 -*-
import math

class StrategyScorer:
    @staticmethod
    def calculate_score(test_results):
        """Классический расчет оценки стабильности."""
        if not test_results:
            return 0.0, {}

        total_success = 0.0
        all_latencies = []
        error_counters = {
            "timeout": 0, "dns_error": 0, "tls_error": 0, "reset": 0, "eof": 0, "http_error": 0
        }
        target_count = len(test_results)

        for res in test_results.values():
            total_success += res["success_rate"]
            all_latencies.extend(res["latencies"])
            for err_type, count in res.get("errors", {}).items():
                if err_type in error_counters:
                    error_counters[err_type] += count

        avg_success = total_success / target_count
        success_factor = avg_success / 100.0

        if len(all_latencies) >= 2:
            mean_lat = sum(all_latencies) / len(all_latencies)
            variance = sum((x - mean_lat) ** 2 for x in all_latencies) / len(all_latencies)
            std_dev = math.sqrt(variance)
            cov = std_dev / mean_lat if mean_lat > 0 else 1.0
            stability_factor = max(0.0, 1.0 - cov)
        elif len(all_latencies) == 1:
            stability_factor = 0.5
        else:
            stability_factor = 0.0

        if all_latencies:
            avg_lat = sum(all_latencies) / len(all_latencies)
            latency_factor = max(0.0, 1.0 - (avg_lat / 2000.0))
        else:
            latency_factor = 0.0

        final_score = (0.6 * success_factor) + (0.3 * stability_factor) + (0.1 * latency_factor)
        return round(final_score * 100.0, 2), error_counters

    @staticmethod
    def analyze_success_factors(leaderboard):
        """
        Вычисляет статистический вклад каждого признака в успешность обхода.
        Определяет средние оценки по параметрам.
        """
        dimensions = ["mode", "fooling", "split_pos", "ttl"]
        stats = {dim: {} for dim in dimensions}

        for item in leaderboard:
            strat = item["strategy"]
            score = item["score"]
            for dim in dimensions:
                val = getattr(strat, dim, None)
                # Кодируем строковое представление для None параметров (например, TTL)
                val_key = str(val) if val is not None else "None"
                if val_key not in stats[dim]:
                    stats[dim][val_key] = []
                stats[dim][val_key].append(score)

        # Вычисление средних средневзвешенных оценок
        averages = {dim: {} for dim in dimensions}
        best_of = {}

        for dim in dimensions:
            for val_key, scores in stats[dim].items():
                averages[dim][val_key] = round(sum(scores) / len(scores), 1) if scores else 0.0
            
            if averages[dim]:
                best_val = max(averages[dim], key=averages[dim].get)
                best_of[dim] = {
                    "value": best_val,
                    "avg_score": averages[dim][best_val]
                }
            else:
                best_of[dim] = {"value": "None", "avg_score": 0.0}

        return averages, best_of