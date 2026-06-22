# -*- coding: utf-8 -*-

class AdaptiveStrategyScheduler:
    def __init__(self):
        # Хранилище динамических весов для каждого сетевого признака
        self.weights = {
            "mode": {},
            "fooling": {},
            "split_pos": {},
            "ttl": {}
        }
        # Счетчики полных провалов для текущей фазы
        self.failure_counters = {}

    def reset_phase_metrics(self):
        """Сбрасывает счетчики ошибок при переходе на новую фазу, предотвращая загрязнение истории."""
        self.failure_counters = {}

    def record_result(self, strategy, score):
        """Корректирует веса признаков стратегии на основе полученного скора."""
        delta = (score - 40.0) / 100.0

        for attr in ["mode", "fooling", "split_pos", "ttl"]:
            val = getattr(strategy, attr, None)
            if val is not None:
                self.weights[attr][val] = self.weights[attr].get(val, 0.0) + delta

        # Фиксируем отказы desync-режима строго в рамках текущей фазы
        if score == 0.0:
            self.failure_counters[strategy.mode] = self.failure_counters.get(strategy.mode, 0) + 1

    def prioritize_queue(self, remaining_strategies):
        """Пересортировывает очередь тестов на основе накопленного веса признаков."""
        def calc_priority(strat):
            score_sum = 0.0
            for attr in ["mode", "fooling", "split_pos", "ttl"]:
                val = getattr(strat, attr, None)
                if val is not None:
                    score_sum += self.weights[attr].get(val, 0.0)
            return score_sum

        filtered = []
        for s in remaining_strategies:
            # Отсекаем семейство параметров только если оно отказало более 3 раз внутри текущей фазы
            if self.failure_counters.get(s.mode, 0) >= 3:
                continue
            filtered.append(s)

        # Сортируем по весу признаков успешности
        filtered.sort(key=calc_priority, reverse=True)
        return filtered