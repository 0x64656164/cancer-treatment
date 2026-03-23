import requests
import re
import json
import os
import time
import ipaddress
import socket
import base64
import sys
import concurrent.futures
from urllib.parse import urlparse, unquote, parse_qs
from base import SingBoxProxy
from lib.wildcard_matcher import match as wc_match
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

# ---------------------------------------------------------------------------
# СИСТЕМА РЕЙТИНГА
# ---------------------------------------------------------------------------
SERVERS_DB_FILE = 'servers_ratings.json'

# Веса компонентов рейтинга (сумма должна быть 1.0)
# UPTIME в приоритете, но FRESHNESS тоже важен для быстро умирающих серверов
RATING_WEIGHTS = {
    'speed':       0.20,   # Скорость соединения (было 0.25)
    'stability':   0.15,   # Стабильность (было 0.20)
    'uptime':      0.40,   # Время жизни сервера (ВЫСОКИЙ ПРИОРИТЕТ)
    'consistency': 0.10,   # Постоянство скорости
    'freshness':   0.15,   # Бонус за недавнюю активность (УВЕЛИЧЕН с 0.05)
}

# Параметры рейтинговой системы
RATING_MIN_TESTS = 2              # Минимум тестов для полного рейтинга (было 3)
RATING_DECAY_HOURS = 12           # Период полураспада freshness бонуса (было 24 - теперь быстрее)
RATING_STABILITY_THRESHOLD = 0.3  # Минимальная стабильность для сохранения (было 0.6 - СЛИШКОМ СТРОГО)

# Параметры отбора серверов
TOP_SERVERS_PERCENT = 0.7         # Топ 70% по рейтингу попадают в конфиг
MIN_RATING_THRESHOLD = 0.15       # Минимальный рейтинг для включения (было 0.3 - СЛИШКОМ СТРОГО)
MAX_SERVERS_IN_CONFIG = 30        # Максимум серверов в конфиге на группу

# Параметры очистки базы
MAX_SERVER_AGE_HOURS = 168        # Удаление через 7 дней без активности (было 120 = 5 дней)
MIN_TESTS_TO_KEEP = 1             # Минимум успешных тестов для сохранения (было 2 - СТРОГО)
MAX_SERVERS_IN_DB = 150           # Максимум серверов в базе на группу (было 100 - увеличили пул)

# Параметры тестирования
TEST_NEW_SERVERS_COUNT = 40       # Сколько новых серверов тестировать за раз (было 20 - МАЛО)
RETEST_OLD_SERVERS_COUNT = 20     # Сколько старых ретестировать за раз (было 10 - МАЛО)
RETEST_LOW_RATING_FIRST = True    # Приоритет ретеста серверам с низким рейтингом

# ОПТИМИЗИРОВАННЫЕ НАСТРОЙКИ (как в index.html)
MAX_NEW_SERVERS_TO_TEST = 5000      # Максимум новых серверов для тестирования
MAX_WORKERS_FAST = 64              # Количество параллельных потоков
FAST_MODE_THRESHOLD = 50           # Порог для включения быстрого режима
MIN_WORKING_SERVERS_FAST = 10      # Минимальное количество рабочих серверов

# ---------------------------------------------------------------------------
# ПРОФИЛИ ВЫВОДА
# ---------------------------------------------------------------------------
PROFILES = {
    "srs": {
        "output_file":         "config.json",
        "github_raw_base":     "https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/srs/",
        "ruleset_folder":      "ruleset/srs/",
        "route_final":         "direct",
        "proxy_rule_outbound": "proxy",
        "file_header":         None,
        "enabled_groups":      ["EUROPE"],
        "remote_rule_sets": [
            "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
            "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs",
        ],
        "remote_block_rule_sets": [
            "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs",
        ],
    },
    "hiddify": {
        "output_file":         "hiddify_config.json",
        "github_raw_base":     "https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/hiddify/",
        "ruleset_folder":      "ruleset/hiddify/",
        "route_final":         "proxy",
        "proxy_rule_outbound": "direct",
        "file_header":         "//profile-title: Cancer-Treatment\n//profile-update-interval: 1\n",
        "enabled_groups":      ["EUROPE"],
        "remote_rule_sets":    [],
        "remote_block_rule_sets": [
            "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs",
        ],
    },
}

# ---------------------------------------------------------------------------
# ОБЩИЕ НАСТРОЙКИ
# ---------------------------------------------------------------------------
SUB_LINKS = [
    'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt',
    'https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt',
    'https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt',
    'https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/3.txt',
    'https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt',
    'https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt'
]
CIDR_WHITELIST_FILE = 'cidr_whitelist2.txt'

REGEXP_RUSSIA  = r'(?:\bRussia\b|\bRU\b|🇷🇺)'

COUNTRY_API_URL = 'https://api.country.is/'
COUNTRY_CHECK_TIMEOUT = 3

MIN_SERVERS    = 5
MIN_BEST_SPEED = 1.5
MAX_WORKERS    = 64

PROBE_ROUNDS = 3
PROBE_DELAY  = 30
PROBE_URL    = 'https://cachefly.cachefly.net/10mb.test'
CONN_TIMEOUT = 3
READ_TIMEOUT = 8

MIN_SUCCESS_ROUNDS  = 1     # из PROBE_ROUNDS=3 нужно пройти минимум 1 (было 2 - строго для нестабильных)
SCORE_FLOOR_RATIO   = 0.25
MIN_KEEP_PER_GROUP  = 5

# ---------------------------------------------------------------------------
# ФИЛЬТР ПО ПАРАМЕТРАМ ПРОТОКОЛА
# ---------------------------------------------------------------------------
#
# Ключ словаря — протокол (vless/vmess/trojan/hy2/hysteria2).
# Если протокол отсутствует в словаре — все его серверы отсеиваются.
#
# ┌─────────────────┬───────────────────────────────────────────────────────────────────────────┐
# │ Поле            │ Описание                                                                  │
# ├─────────────────┼───────────────────────────────────────────────────────────────────────────┤
# │ logic           │ "AND" (все условия, по умолчанию) / "OR" (хватит одного)                  │
# │ transport       │ тип транспорта: tcp / ws / grpc / httpupgrade / xhttp / quic              │
# │ security        │ tls / reality / none                                                      │
# │ flow            │ flow-значение: "" / "xtls-rprx-vision" / ...                              │
# │ sni             │ SNI: точное, "*.example.com" wildcard, или путь к файлу (.txt/.json)      │
# │ fp              │ fingerprint браузера: chrome / firefox / safari / edge / ios / qq / ...   │
# │ port            │ порт: число, строка "443", или диапазон "8000-9000"                       │
# │ host            │ Host-заголовок (ws/httpupgrade): точное или wildcard "*.cdn.com"          │
# │ path            │ путь: точное, префикс "/cdn*", или regex "/re:^/api/.*"                   │
# │ alpn            │ ALPN: "h2" / "http/1.1" / "h3" — проходит если хоть одно совпало         │
# │ encryption      │ (vmess) метод шифрования: auto / aes-128-gcm / chacha20-poly1305 / none  │
# │ pbk             │ (reality) публичный ключ — whitelist конкретных ключей                    │
# │ sid             │ (reality) short ID — whitelist конкретных ID                              │
# │ service_name    │ (grpc) имя сервиса                                                        │
# │ obfs            │ (hy2) тип обфускации: none / salamander                                   │
# │ obfs_password   │ (hy2) regex-паттерн на пароль обфускации: "^secret.*"                    │
# └─────────────────┴───────────────────────────────────────────────────────────────────────────┘
#
# Пустой список [] = ограничение снято (разрешено всё).
#
# В полях-списках можно указать путь к файлу (.txt или .json) — он будет
# раскрыт при старте:
#   .txt  — каждая непустая строка (без # комментариев) становится элементом
#   .json — ожидается JSON-массив строк
#
# Условия выставлены на основе реально работающих серверов из подписок:
#   - vless/reality/tcp/xtls-rprx-vision — основной рабочий паттерн
#   - fp: chrome, random, qq — встречаются на рабочих серверах
#   - Остальные протоколы: пропускаем всё (пустые условия)
#
PROTOCOL_FILTERS = {
    "vless": {
        "logic":        "AND",
        "transport":    ["tcp", "xhttp", "ws"],
        "security":     ["tls", "reality"],
        "flow":         ["xtls-rprx-vision", ""],
        "fp":           ["chrome", "random", "qq", "firefox", "safari", "edge", "ios", "android", "360"],
        "sni":          [],
        "port":         [],
        "host":         [],
        "path":         [],
        "alpn":         [],
        "pbk":          [],
        "sid":          [],
        "service_name": [],
    },
    "vmess": {
        "logic":      "AND",
        "transport":  [],
        "security":   [],
        "sni":        ["domain_whitelist.txt"],
        "host":       [],
        "path":       [],
        "alpn":       [],
        "port":       [],
        "encryption": [],
    },
    "trojan": {
        "logic":        "AND",
        "transport":    [],
        "security":     [],
        "sni":          [],
        "host":         [],
        "path":         [],
        "alpn":         [],
        "port":         [],
        "service_name": [],
    },
    "hy2": {
        "logic":         "AND",
        "transport":     [],
        "security":      [],
        "sni":           [],
        "port":          [],
        "obfs":          [],
        "obfs_password": [],
    },
}


# ===========================================================================
# СИСТЕМА РЕЙТИНГА СЕРВЕРОВ
# ===========================================================================

class ServerRatingSystem:
    """
    Продвинутая система рейтинга серверов.
    
    Рейтинг вычисляется из 5 компонентов (0-1 каждый):
    
    1. SPEED (скорость) - 25% - нормализованная скорость относительно лучшего
    2. STABILITY (стабильность) - 20% - % успешных проверок
    3. UPTIME (время жизни) - 40% - как долго сервер работает (ВЫСОКИЙ ПРИОРИТЕТ)
    4. CONSISTENCY (постоянство) - 10% - обратная вариация скорости
    5. FRESHNESS (свежесть) - 5% - бонус за недавнюю активность
    
    Итоговый рейтинг = взвешенная сумма компонентов
    
    Логика uptime (агрессивная шкала):
    - < 6 мин:   ~0.01 (почти ноль)
    - 15 мин:    ~0.08 (очень мало)
    - 30 мин:    ~0.20
    - 1 час:     0.35
    - 2 часа:    0.50
    - 6 часов:   0.70
    - 12 часов:  0.82
    - 24 часа:   0.90
    - 48 часов:  0.95
    - 72+ часа:  1.00 (максимум)
    """
    
    def __init__(self, db_file=SERVERS_DB_FILE):
        self.db_file = db_file
        self.data = self._load()
        
    def _load(self) -> dict:
        """Загрузка базы рейтингов."""
        if not os.path.exists(self.db_file):
            return {"servers": {}, "metadata": {"last_cleanup": None}}
        
        try:
            with open(self.db_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠ Ошибка чтения базы рейтингов: {e}")
            return {"servers": {}, "metadata": {"last_cleanup": None}}
    
    def _save(self):
        """Сохранение базы рейтингов."""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠ Ошибка записи базы рейтингов: {e}")
    
    def _get_server_key(self, outbound: dict) -> str:
        """Генерация уникального ключа сервера."""
        key_parts = [
            outbound.get('type', ''),
            outbound.get('server', ''),
            str(outbound.get('server_port', '')),
            outbound.get('uuid', outbound.get('password', ''))[:8]
        ]
        return '|'.join(key_parts)
    
    def _calculate_rating(self, server_data: dict, group_max_speed: float = 100.0) -> Tuple[float, dict]:
        """
        Вычисление рейтинга сервера.
        
        Returns:
            (rating, components) - итоговый рейтинг и его компоненты
        """
        now = datetime.now()
        
        # Извлекаем данные
        speeds = server_data.get('speed_history', [])
        total_tests = server_data.get('total_tests', 0)
        successful_tests = server_data.get('successful_tests', 0)
        first_seen = datetime.fromisoformat(server_data.get('first_seen', now.isoformat()))
        last_seen = datetime.fromisoformat(server_data.get('last_seen', now.isoformat()))
        
        # Инициализация компонентов
        components = {
            'speed': 0.0,
            'stability': 0.0,
            'uptime': 0.0,
            'consistency': 0.0,
            'freshness': 0.0,
        }
        
        # Если данных недостаточно - возвращаем минимальный рейтинг
        if not speeds or total_tests == 0:
            return 0.0, components
        
        # 1. SPEED - средняя скорость относительно максимума в группе
        avg_speed = sum(speeds) / len(speeds)
        components['speed'] = min(1.0, avg_speed / max(group_max_speed, 1.0))
        
        # 2. STABILITY - процент успешных проверок
        components['stability'] = successful_tests / max(total_tests, 1)
        
        # 3. UPTIME - время жизни сервера (от первого появления до СЕЙЧАС)
        # Важно: считаем от first_seen до NOW, а не до last_seen
        # Это позволяет накапливать uptime даже если сервер временно недоступен
        uptime_hours = (now - first_seen).total_seconds() / 3600
        
        # Агрессивная шкала с приоритетом долгожителям:
        # 15 мин (0.25ч) = 0.05
        # 30 мин (0.5ч)  = 0.15
        # 1 час          = 0.35
        # 2 часа         = 0.50
        # 6 часов        = 0.70
        # 12 часов       = 0.82
        # 24 часа        = 0.90
        # 48 часов       = 0.95
        # 72+ часа       = 1.00
        if uptime_hours < 0.1:  # Менее 6 минут - почти ноль
            components['uptime'] = 0.01
        elif uptime_hours < 1.0:  # До часа - очень медленный рост
            components['uptime'] = 0.05 + (uptime_hours / 1.0) * 0.30  # 0.05 -> 0.35
        elif uptime_hours < 6.0:  # 1-6 часов - умеренный рост
            components['uptime'] = 0.35 + ((uptime_hours - 1.0) / 5.0) * 0.35  # 0.35 -> 0.70
        elif uptime_hours < 24.0:  # 6-24 часа - замедление роста
            components['uptime'] = 0.70 + ((uptime_hours - 6.0) / 18.0) * 0.20  # 0.70 -> 0.90
        elif uptime_hours < 72.0:  # 24-72 часа - финальный рост
            components['uptime'] = 0.90 + ((uptime_hours - 24.0) / 48.0) * 0.10  # 0.90 -> 1.00
        else:  # 72+ часов - максимум
            components['uptime'] = 1.0
        
        # 4. CONSISTENCY - стабильность скорости (низкая дисперсия = хорошо)
        if len(speeds) >= 2:
            mean = sum(speeds) / len(speeds)
            variance = sum((s - mean) ** 2 for s in speeds) / len(speeds)
            cv = (variance ** 0.5) / max(mean, 1)  # коэффициент вариации
            # CV < 0.2 = отлично, CV > 1.0 = плохо
            components['consistency'] = max(0.0, 1.0 - min(cv / 0.5, 2.0))
        else:
            components['consistency'] = 0.5  # нейтральное значение
        
        # 5. FRESHNESS - бонус за недавнюю активность (экспоненциальный decay)
        hours_since_last = (now - last_seen).total_seconds() / 3600
        decay_factor = 0.5 ** (hours_since_last / RATING_DECAY_HOURS)
        components['freshness'] = decay_factor
        
        # Взвешенная сумма
        rating = sum(components[k] * RATING_WEIGHTS[k] for k in components)
        
        # Штраф за малое количество тестов (confidence penalty)
        if total_tests < RATING_MIN_TESTS:
            confidence = total_tests / RATING_MIN_TESTS
            rating *= confidence
        
        return rating, components
    
    def add_test_result(self, outbound: dict, speed: Optional[float], 
                       country: Optional[str], group: str, link: Optional[str] = None) -> bool:
        """
        Добавление результата теста.
        
        Args:
            outbound: Конфигурация сервера
            speed: Скорость (Mbps) или None при провале
            country: Код страны выхода
            group: Группа сервера (EUROPE/RUSSIA)
            link: Оригинальный link (vless://, vmess://, и т.д.)
        
        Returns:
            True если тест успешен, False если провален
        """
        key = self._get_server_key(outbound)
        now = datetime.now().isoformat()
        
        servers = self.data.setdefault("servers", {})
        
        if key not in servers:
            # Новый сервер
            servers[key] = {
                'outbound': outbound,
                'link': link,  # Сохраняем оригинальный link
                'group': group,
                'country': country,
                'first_seen': now,
                'last_seen': now,
                'total_tests': 0,
                'successful_tests': 0,
                'speed_history': [],
                'rating': 0.0,
                'rating_components': {},
            }
        
        server = servers[key]
        server['total_tests'] += 1
        
        # Обновляем link если передан (может обновиться при изменении параметров)
        if link:
            server['link'] = link
        
        if speed is not None and speed > 0:
            # Успешный тест
            server['successful_tests'] += 1
            server['last_seen'] = now
            server['country'] = country or server.get('country')
            
            # Обновляем историю скоростей (храним последние 10)
            speed_history = server.get('speed_history', [])
            speed_history.append(speed)
            server['speed_history'] = speed_history[-10:]
            
            self._save()
            return True
        else:
            # Провальный тест - не обновляем last_seen
            self._save()
            return False
    
    def recalculate_all_ratings(self):
        """
        Пересчёт рейтингов всех серверов.
        Вызывается после добавления новых результатов.
        """
        servers = self.data.get("servers", {})
        
        # Группируем серверы и находим максимальную скорость в каждой группе
        groups_max_speed = {}
        for server_data in servers.values():
            group = server_data.get('group', 'UNKNOWN')
            speeds = server_data.get('speed_history', [])
            if speeds:
                avg_speed = sum(speeds) / len(speeds)
                groups_max_speed[group] = max(groups_max_speed.get(group, 0), avg_speed)
        
        # Пересчитываем рейтинги
        for key, server_data in servers.items():
            group = server_data.get('group', 'UNKNOWN')
            max_speed = groups_max_speed.get(group, 100.0)
            rating, components = self._calculate_rating(server_data, max_speed)
            
            server_data['rating'] = rating
            server_data['rating_components'] = components
        
        self._save()
    
    def get_top_servers(self, group: Optional[str] = None, 
                       limit: Optional[int] = None,
                       min_rating: float = MIN_RATING_THRESHOLD) -> List[dict]:
        """
        Получить топ серверов по рейтингу.
        
        Args:
            group: Фильтр по группе
            limit: Максимальное количество серверов
            min_rating: Минимальный рейтинг для включения
        """
        servers = self.data.get("servers", {})
        
        # Фильтрация
        filtered = []
        for key, server_data in servers.items():
            # Проверка группы
            if group and server_data.get('group') != group:
                continue
            
            # Проверка минимального рейтинга
            rating = server_data.get('rating', 0)
            if rating < min_rating:
                continue
            
            # Проверка минимальной стабильности
            stability = server_data.get('rating_components', {}).get('stability', 0)
            if stability < RATING_STABILITY_THRESHOLD:
                continue
            
            filtered.append({
                'key': key,
                'outbound': server_data['outbound'],
                'link': server_data.get('link'),  # Добавляем link
                'rating': rating,
                'components': server_data.get('rating_components', {}),
                'country': server_data.get('country'),
                'total_tests': server_data.get('total_tests', 0),
                'successful_tests': server_data.get('successful_tests', 0),
                'last_seen': server_data.get('last_seen'),
            })
        
        # Сортировка по рейтингу
        filtered.sort(key=lambda x: x['rating'], reverse=True)
        
        # FALLBACK: если серверов слишком мало, смягчаем критерии
        if len(filtered) < MIN_SERVERS and group:
            print(f"⚠️  [{group}] Мало серверов ({len(filtered)}), смягчаем критерии...")
            
            # Пробуем без проверки стабильности
            filtered_relaxed = []
            for key, server_data in servers.items():
                if group and server_data.get('group') != group:
                    continue
                
                rating = server_data.get('rating', 0)
                if rating < min_rating * 0.5:  # Вдвое мягче
                    continue
                
                filtered_relaxed.append({
                    'key': key,
                    'outbound': server_data['outbound'],
                    'link': server_data.get('link'),  # Добавляем link
                    'rating': rating,
                    'components': server_data.get('rating_components', {}),
                    'country': server_data.get('country'),
                    'total_tests': server_data.get('total_tests', 0),
                    'successful_tests': server_data.get('successful_tests', 0),
                    'last_seen': server_data.get('last_seen'),
                })
            
            filtered_relaxed.sort(key=lambda x: x['rating'], reverse=True)
            
            if len(filtered_relaxed) > len(filtered):
                print(f"✓ Найдено {len(filtered_relaxed)} серверов с мягкими критериями")
                filtered = filtered_relaxed
        
        if limit:
            filtered = filtered[:limit]
        
        return filtered
    
    def get_servers_for_retest(self, group: Optional[str] = None, 
                               count: int = RETEST_OLD_SERVERS_COUNT) -> List[dict]:
        """
        Выбор серверов для повторного тестирования.
        Приоритет: старые серверы с низким freshness или низким рейтингом.
        """
        servers = self.data.get("servers", {})
        now = datetime.now()
        
        candidates = []
        for key, server_data in servers.items():
            if group and server_data.get('group') != group:
                continue
            
            last_seen = datetime.fromisoformat(server_data.get('last_seen', now.isoformat()))
            hours_since = (now - last_seen).total_seconds() / 3600
            
            # Приоритет тем, кого давно не проверяли или с низким рейтингом
            rating = server_data.get('rating', 0)
            
            if RETEST_LOW_RATING_FIRST:
                priority = hours_since * (1.1 - rating)  # Больше часов и ниже рейтинг = выше приоритет
            else:
                priority = hours_since
            
            candidates.append({
                'key': key,
                'outbound': server_data['outbound'],
                'link': server_data.get('link'),  # Добавляем link для ретеста
                'group': server_data.get('group'),
                'priority': priority,
                'hours_since_last': hours_since,
                'rating': rating,
            })
        
        # Сортируем по приоритету
        candidates.sort(key=lambda x: x['priority'], reverse=True)
        
        return candidates[:count]
    
    def cleanup(self):
        """Очистка базы от устаревших и плохих серверов."""
        servers = self.data.get("servers", {})
        now = datetime.now()
        cutoff = now - timedelta(hours=MAX_SERVER_AGE_HOURS)
        
        to_remove = []
        
        for key, server_data in servers.items():
            last_seen = datetime.fromisoformat(server_data.get('last_seen', now.isoformat()))
            total_tests = server_data.get('total_tests', 0)
            successful_tests = server_data.get('successful_tests', 0)
            rating = server_data.get('rating', 0)
            
            # Удаляем если:
            # 1. Слишком старый и давно не виден
            # 2. Мало успешных тестов
            # 3. Очень низкий рейтинг
            should_remove = (
                (last_seen < cutoff) or
                (successful_tests < MIN_TESTS_TO_KEEP) or
                (rating < MIN_RATING_THRESHOLD * 0.5 and total_tests >= 3)
            )
            
            if should_remove:
                to_remove.append(key)
        
        for key in to_remove:
            del servers[key]
        
        # Ограничиваем размер базы по группам
        for group in ['EUROPE', 'RUSSIA', 'ALL']:
            group_servers = [(k, v['rating']) for k, v in servers.items() 
                           if v.get('group') == group]
            
            if len(group_servers) > MAX_SERVERS_IN_DB:
                # Сортируем по рейтингу и удаляем худшие
                group_servers.sort(key=lambda x: x[1], reverse=True)
                
                for key, _ in group_servers[MAX_SERVERS_IN_DB:]:
                    if key in servers:
                        del servers[key]
        
        self.data['metadata']['last_cleanup'] = now.isoformat()
        self._save()
        
        if to_remove:
            print(f"🗑️  Очистка: удалено {len(to_remove)} серверов")
    
    def print_stats(self):
        """Вывод статистики по базе."""
        servers = self.data.get("servers", {})
        
        print("\n" + "="*80)
        print("📊 СТАТИСТИКА БАЗЫ РЕЙТИНГОВ")
        print("="*80)
        
        for group in ['EUROPE', 'RUSSIA']:
            group_servers = [v for v in servers.values() if v.get('group') == group]
            if not group_servers:
                continue
            
            ratings = [s.get('rating', 0) for s in group_servers]
            avg_rating = sum(ratings) / len(ratings) if ratings else 0
            
            print(f"\n{group}:")
            print(f"  Всего серверов: {len(group_servers)}")
            print(f"  Средний рейтинг: {avg_rating:.3f}")
            print(f"  Топ-5 серверов:")
            
            # Сортируем и показываем топ-5
            group_servers.sort(key=lambda x: x.get('rating', 0), reverse=True)
            for i, server in enumerate(group_servers[:5], 1):
                tag = server['outbound'].get('tag', 'Unknown')[:40]
                rating = server.get('rating', 0)
                comp = server.get('rating_components', {})
                
                print(f"    {i}. {tag:<40} R={rating:.3f} "
                      f"[sp={comp.get('speed', 0):.2f} st={comp.get('stability', 0):.2f} "
                      f"up={comp.get('uptime', 0):.2f} cs={comp.get('consistency', 0):.2f} "
                      f"fr={comp.get('freshness', 0):.2f}]")


# ===========================================================================
# РАСКРЫТИЕ ФАЙЛОВ В ФИЛЬТРАХ
# ===========================================================================

def _load_domain_file(path: str) -> list:
    if not os.path.exists(path):
        print(f"⚠ Файл доменов '{path}' не найден — условие SNI по файлу отключено.")
        return []
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, encoding='utf-8') as f:
            if ext == '.json':
                data = json.load(f)
                if isinstance(data, list):
                    return [str(d).strip() for d in data if str(d).strip()]
                print(f"⚠ {path}: ожидался JSON-массив, получено {type(data).__name__} — пропускаем.")
                return []
            else:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith('#')
                ]
    except Exception as e:
        print(f"⚠ Ошибка чтения файла доменов '{path}': {e}")
        return []


def _expand_filter_files(filters: dict) -> dict:
    expanded = {}
    for proto, rules in filters.items():
        new_rules = {}
        for field, value in rules.items():
            if not isinstance(value, list):
                new_rules[field] = value
                continue
            new_list = []
            for entry in value:
                if isinstance(entry, str) and entry.lower().endswith(('.txt', '.json')):
                    domains = _load_domain_file(entry)
                    if domains:
                        print(f"  Фильтр [{proto}.{field}]: загружено {len(domains)} записей из '{entry}'")
                    new_list.extend(domains)
                else:
                    new_list.append(entry)
            new_rules[field] = new_list
        expanded[proto] = new_rules
    return expanded


PROTOCOL_FILTERS["hysteria2"] = PROTOCOL_FILTERS["hy2"]
PROTOCOL_FILTERS = _expand_filter_files(PROTOCOL_FILTERS)


# ===========================================================================
# ФИЛЬТР ПО ПАРАМЕТРАМ
# ===========================================================================

def _parse_link_params(link: str) -> dict:
    p = {
        "protocol": "", "transport": "", "security": "", "flow": "",
        "sni": "", "fp": "", "port": "", "host": "", "path": "",
        "alpn": [], "encryption": "", "pbk": "", "sid": "",
        "service_name": "", "obfs": "", "obfs_password": "",
    }
    try:
        parsed = urlparse(link)
        proto = parsed.scheme.lower()
        p["protocol"] = proto
        p["port"] = str(parsed.port or "")

        if proto == "vmess":
            raw = link[len("vmess://"):]
            if '#' in raw:
                raw = raw[:raw.index('#')]
            padded = raw + '=' * (-len(raw) % 4)
            data = json.loads(base64.b64decode(padded).decode('utf-8', errors='ignore'))
            net = data.get("net", data.get("type", "tcp"))
            tls = data.get("tls", "")
            p["transport"]  = net if net else "tcp"
            p["security"]   = tls if tls else "none"
            p["sni"]        = data.get("sni", "")
            p["fp"]         = data.get("fp", "")
            p["host"]       = data.get("host", "")
            p["path"]       = data.get("path", "")
            p["encryption"] = data.get("scy", data.get("security", "auto"))
            alpn_raw        = data.get("alpn", "")
            p["alpn"]       = [a.strip() for a in alpn_raw.split(",") if a.strip()] if alpn_raw else []
            if not p["port"] and data.get("port"):
                p["port"] = str(data["port"])
            return p

        qs = parse_qs(parsed.query, keep_blank_values=True)

        def q(key): return qs.get(key, [""])[0]

        p["transport"]     = q("type") or "tcp"
        p["security"]      = q("security") or ("tls" if proto == "trojan" else "none")
        p["flow"]          = q("flow")
        p["sni"]           = q("sni")
        p["fp"]            = q("fp")
        p["host"]          = q("host")
        p["path"]          = q("path")
        p["pbk"]           = q("pbk")
        p["sid"]           = q("sid")
        p["service_name"]  = q("serviceName")
        p["obfs"]          = q("obfs") or q("obfsType")
        p["obfs_password"] = q("obfs-password") or q("obfsParam")
        alpn_raw           = q("alpn")
        p["alpn"]          = [a.strip() for a in unquote(alpn_raw).split(",") if a.strip()] if alpn_raw else []
    except Exception:
        pass
    return p


def _str_matches(value: str, allowed: list) -> bool:
    return any(wc_match(value, pattern) for pattern in allowed)


def _path_matches(path: str, allowed: list) -> bool:
    for pattern in allowed:
        if pattern.startswith("/re:"):
            if re.match(pattern[4:], path):
                return True
        elif pattern.endswith("*"):
            if path.startswith(pattern[:-1]):
                return True
        elif path == pattern:
            return True
    return False


def _port_matches(port_str: str, allowed: list) -> bool:
    try:
        port = int(port_str)
    except (ValueError, TypeError):
        return False
    for entry in allowed:
        s = str(entry)
        if '-' in s:
            lo, hi = s.split('-', 1)
            if int(lo) <= port <= int(hi):
                return True
        elif int(s) == port:
            return True
    return False


def _alpn_matches(alpn_list: list, allowed: list) -> bool:
    return any(a in allowed for a in alpn_list)


def _regex_matches(value: str, patterns: list) -> bool:
    return any(re.search(pat, value) for pat in patterns)


def passes_protocol_filter(link: str) -> bool:
    p = _parse_link_params(link)
    proto = p["protocol"]
    if proto not in PROTOCOL_FILTERS:
        return False
    rules = PROTOCOL_FILTERS[proto]
    logic = rules.get("logic", "AND").upper()
    checks = []

    def check(field, matcher_fn, *args):
        if rules.get(field):
            checks.append(matcher_fn(*args))

    check("transport",     _str_matches,   p["transport"],     rules.get("transport", []))
    check("security",      _str_matches,   p["security"],      rules.get("security", []))
    check("flow",          _str_matches,   p["flow"],          rules.get("flow", []))
    check("sni",           _str_matches,   p["sni"],           rules.get("sni", []))
    check("fp",            _str_matches,   p["fp"],            rules.get("fp", []))
    check("host",          _str_matches,   p["host"],          rules.get("host", []))
    check("encryption",    _str_matches,   p["encryption"],    rules.get("encryption", []))
    check("pbk",           _str_matches,   p["pbk"],           rules.get("pbk", []))
    check("sid",           _str_matches,   p["sid"],           rules.get("sid", []))
    check("service_name",  _str_matches,   p["service_name"],  rules.get("service_name", []))
    check("obfs",          _str_matches,   p["obfs"],          rules.get("obfs", []))
    check("port",          _port_matches,  p["port"],          rules.get("port", []))
    check("path",          _path_matches,  p["path"],          rules.get("path", []))
    check("alpn",          _alpn_matches,  p["alpn"],          rules.get("alpn", []))
    check("obfs_password", _regex_matches, p["obfs_password"], rules.get("obfs_password", []))

    if not checks:
        return True
    return any(checks) if logic == "OR" else all(checks)


def filter_by_params(links: list) -> list:
    before = len(links)
    passed = [l for l in links if passes_protocol_filter(l)]
    print(f"Фильтр параметров: прошло {len(passed)} из {before} "
          f"(отсеяно {before - len(passed)})\n")
    return passed


# ===========================================================================
# CIDR-ФИЛЬТР
# ===========================================================================

def load_cidr_whitelist(path: str) -> list:
    if not os.path.exists(path):
        print(f"⚠ Файл {path} не найден — CIDR-фильтр отключён.")
        return []
    networks, errors = [], 0
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                errors += 1
    print(f"CIDR-whitelist загружен: {len(networks)} сетей"
          + (f", пропущено некорректных строк: {errors}" if errors else ""))
    return networks


CIDR_NETWORKS = load_cidr_whitelist(CIDR_WHITELIST_FILE)
_dns_cache: dict = {}


def _resolve(host: str):
    if host not in _dns_cache:
        try:
            _dns_cache[host] = socket.gethostbyname(host)
        except Exception:
            _dns_cache[host] = None
    return _dns_cache[host]


def is_in_cidr_whitelist(host: str) -> bool:
    if not CIDR_NETWORKS:
        return True
    ip_str = _resolve(host)
    if ip_str is None:
        return False
    try:
        return any(ipaddress.ip_address(ip_str) in net for net in CIDR_NETWORKS)
    except ValueError:
        return False


def extract_host_from_link(link: str) -> str:
    return urlparse(link).hostname or ""


def filter_by_cidr(links: list) -> list:
    if not CIDR_NETWORKS:
        return links
    print(f"CIDR-фильтрация: проверяем {len(links)} серверов...")
    hosts = list({extract_host_from_link(l) for l in links if extract_host_from_link(l)})
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS * 2) as ex:
        ex.map(_resolve, hosts)
    passed = [l for l in links if is_in_cidr_whitelist(extract_host_from_link(l))]
    print(f"CIDR-фильтр: прошло {len(passed)} из {len(links)} серверов\n")
    return passed


# ===========================================================================
# ЗАГРУЗКА ПОДПИСОК
# ===========================================================================

def fetch_links_from_subscriptions() -> list:
    links, seen = [], set()
    for url in SUB_LINKS:
        print(f"Загрузка подписки: {url}")
        try:
            raw = requests.get(url, timeout=15).text
            found = re.findall(r'^(?:vless|vmess|trojan|hy2|hysteria2):\/\/.+$', raw, re.MULTILINE)
            new = 0
            for link in found:
                if link not in seen:
                    seen.add(link)
                    links.append(link)
                    new += 1
            print(f"  → Найдено: {len(found)}, новых: {new}")
        except Exception as e:
            print(f"  ✗ Ошибка загрузки {url}: {e}")
    print(f"\nИтого уникальных: {len(links)}\n")
    return links


# ===========================================================================
# ЗОНДИРОВАНИЕ (адаптировано под рейтинги)
# ===========================================================================

def parse_link(proxy, link):
    if link.startswith("vmess://"):              return proxy._parse_vmess_link(link)
    if link.startswith("vless://"):              return proxy._parse_vless_link(link)
    if link.startswith("trojan://"):             return proxy._parse_trojan_link(link)
    if link.startswith(("hy2://","hysteria2://")): return proxy._parse_hysteria2_link(link)
    raise ValueError(f"Неизвестный протокол: {link[:20]}")


def _fix_outbound(outbound: dict) -> dict:
    if "transport" in outbound and outbound["transport"].get("type") == "xhttp":
        outbound["transport"]["type"] = "httpupgrade"
        if isinstance(outbound["transport"].get("host"), list):
            outbound["transport"]["host"] = (
                outbound["transport"]["host"][0]
                if outbound["transport"]["host"] else ""
            )
    return outbound


def check_exit_country(proxy_session) -> str | None:
    try:
        response = proxy_session.get(COUNTRY_API_URL, timeout=COUNTRY_CHECK_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', '').upper()
    except Exception:
        pass
    return None


def _single_probe(link: str) -> float | None:
    try:
        with SingBoxProxy(link) as proxy:
            # Устанавливаем ограничение на 1 попытку (0 повторов)
            adapter = requests.adapters.HTTPAdapter(max_retries=0)
            proxy.mount("https://", adapter)
            proxy.mount("http://", adapter)
            
            start = time.perf_counter()
            r = proxy.get(PROBE_URL, timeout=(CONN_TIMEOUT, READ_TIMEOUT), stream=True)
            if r.status_code == 200:
                total = sum(len(c) for c in r.iter_content(chunk_size=8192) if c)
                duration = time.perf_counter() - start
                if duration > 0 and total > 0:
                    return (total * 8) / (duration * 1_000_000)
    except Exception:
        pass
    return None


def _harmonic_mean(values: list) -> float:
    if not values:
        return 0.0
    return len(values) / sum(1.0 / v for v in values if v > 0)


def probe_server(link: str):
    """
    Полное зондирование нового сервера.
    
    Проверка страны выхода выполняется ОДИН РАЗ при первом успешном раунде.
    Если первый раунд не прошёл, страна не определяется.
    """
    tag = unquote(urlparse(link).fragment) or "Unnamed"
    speeds = []
    outbound = None
    exit_country = None

    for round_num in range(PROBE_ROUNDS):
        if round_num > 0:
            time.sleep(PROBE_DELAY)

        mbps = _single_probe(link)
        if mbps is not None:
            speeds.append(mbps)
            
            # Определяем страну выхода при ЛЮБОМ успешном раунде, не только первом
            if outbound is None or exit_country is None:
                try:
                    with SingBoxProxy(link) as proxy:
                        if outbound is None:
                            outbound = _fix_outbound(parse_link(proxy, link))
                            outbound["tag"] = tag
                            outbound["domain_strategy"] = "prefer_ipv4"
                        
                        # Проверяем страну если ещё не определили
                        if exit_country is None:
                            exit_country = check_exit_country(proxy)
                            if exit_country:
                                print(f"  → Определена страна: {exit_country}")
                except Exception as e:
                    print(f"  ⚠️  Ошибка определения страны: {e}")

    if len(speeds) < MIN_SUCCESS_ROUNDS or outbound is None:
        tag_short = tag[:48]
        stability = "".join("✓" if i < len(speeds) else "✗" for i in range(PROBE_ROUNDS))
        print(f"[{stability}] {tag_short:<48}  — отсеян")
        return None, 0, None

    score = _harmonic_mean(speeds)

    stability = "".join("✓" if i < len(speeds) else "✗" for i in range(PROBE_ROUNDS))
    country_mark = f" [{exit_country}]" if exit_country else " [??]"
    print(f"[{stability}] {tag[:48]:<48} "
          f"hmean={score:.1f} Mbps{country_mark}")
    return outbound, score, exit_country


def quick_probe_server(outbound: dict, link: str = None) -> Optional[float]:
    """
    Быстрая проверка существующего сервера (1 раунд).
    
    Если link не передан, пропускаем проверку (невозможно восстановить из outbound).
    """
    tag = outbound.get('tag', 'Unknown')
    
    if not link:
        # Без исходного link невозможно провести тест
        # TODO: реализовать восстановление link из outbound
        print(f"[⊘] {tag[:48]:<48} пропущен (нет link)")
        return None
    
    mbps = _single_probe(link)
    
    if mbps:
        print(f"[✓] {tag[:48]:<48} {mbps:.1f} Mbps (ретест)")
    else:
        print(f"[✗] {tag[:48]:<48} не отвечает (ретест)")
    
    return mbps


# ===========================================================================
# БЫСТРОЕ ЗОНДИРОВАНИЕ (как в index.html)
# ===========================================================================

def _quick_single_probe(link: str, timeout: int = 3) -> float | None:
    """
    БЫСТРАЯ ОДНОРАУНДОВАЯ ПРОВЕРКА для ретеста
    """
    try:
        with SingBoxProxy(link) as proxy:
            adapter = requests.adapters.HTTPAdapter(max_retries=0)
            proxy.mount("https://", adapter)
            proxy.mount("http://", adapter)
            
            start = time.perf_counter()
            r = proxy.get(PROBE_URL, timeout=(timeout, timeout), stream=True)
            
            if r.status_code == 200:
                total = sum(len(c) for c in r.iter_content(chunk_size=8192) if c)
                duration = time.perf_counter() - start
                
                if duration > 0 and total > 0:
                    return (total * 8) / (duration * 1_000_000)
    except Exception:
        pass
    
    return None


def quick_probe_single(link: str, timeout: int = 3) -> Tuple[Optional[float], Optional[str], Optional[dict]]:
    """
    БЫСТРАЯ ОДНОРАУНДОВАЯ ПРОВЕРКА (как в index.html)
    Возвращает (скорость, страна, outbound) или (None, None, None)
    """
    tag = unquote(urlparse(link).fragment) or "Unnamed"
    
    try:
        with SingBoxProxy(link) as proxy:
            adapter = requests.adapters.HTTPAdapter(max_retries=0)
            proxy.mount("https://", adapter)
            proxy.mount("http://", adapter)
            
            start = time.perf_counter()
            r = proxy.get(PROBE_URL, timeout=(timeout, timeout), stream=True)
            
            if r.status_code == 200:
                total = sum(len(c) for c in r.iter_content(chunk_size=8192) if c)
                duration = time.perf_counter() - start
                
                if duration > 0 and total > 0:
                    speed = (total * 8) / (duration * 1_000_000)
                    
                    # Парсим outbound
                    outbound = _fix_outbound(parse_link(proxy, link))
                    outbound["tag"] = tag
                    outbound["domain_strategy"] = "prefer_ipv4"
                    
                    # Определяем страну
                    exit_country = check_exit_country(proxy)
                    
                    return speed, exit_country, outbound
    except Exception as e:
        pass
    
    return None, None, None


def test_servers_batch_parallel(links: List[str], group: str, max_workers: int = MAX_WORKERS_FAST) -> List[dict]:
    """
    ПАРАЛЛЕЛЬНОЕ ТЕСТИРОВАНИЕ ПАЧКИ СЕРВЕРОВ (как в index.html)
    """
    results = []
    total = len(links)
    completed = 0
    
    print(f"  → Тестируем {total} серверов ({group}) параллельно...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(quick_probe_single, link): link for link in links}
        
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            link = futures[future]
            
            try:
                speed, country, outbound = future.result(timeout=10)
                
                if speed is not None and outbound is not None:
                    # Определяем финальную группу
                    final_group = group
                    if group == 'EUROPE' and country == 'RU':
                        final_group = 'RUSSIA'
                    elif group == 'RUSSIA' and country and country != 'RU':
                        final_group = 'EUROPE'
                    
                    results.append({
                        'outbound': outbound,
                        'speed': speed,
                        'country': country,
                        'group': final_group,
                        'link': link,
                        'tag': outbound.get('tag', 'Unknown')
                    })
                    
                    # Прогресс
                    if completed % 10 == 0 or completed == total:
                        print(f"    [{completed}/{total}] Найдено {len(results)} рабочих")
            
            except Exception as e:
                if completed % 20 == 0:
                    print(f"    [{completed}/{total}] Ошибка: {str(e)[:50]}")
    
    return results


def smart_server_search(all_links: List[str], rating_system: ServerRatingSystem) -> Dict[str, List[dict]]:
    """
    УМНЫЙ ПОИСК СЕРВЕРОВ (аналог логики из index.html)
    
    Особенности:
    1. Приоритет новых серверов
    2. Ограничение на количество тестируемых
    3. Параллельная проверка
    4. Минимальное количество рабочих
    """
    
    # Разделяем по группам
    europe_candidates = [l for l in all_links if not _is_russia(l)]
    russia_candidates = [l for l in all_links if _is_russia(l)]
    
    print(f"\n📊 Кандидатов для тестирования:")
    print(f"  EUROPE: {len(europe_candidates)}")
    print(f"  RUSSIA: {len(russia_candidates)}")
    
    # Ограничиваем количество для тестирования (быстрый режим)
    use_fast_mode = len(europe_candidates) + len(russia_candidates) > FAST_MODE_THRESHOLD
    
    if use_fast_mode:
        # Быстрый режим - тестируем ограниченное количество
        max_per_group = MAX_NEW_SERVERS_TO_TEST // 2
        europe_candidates = europe_candidates[:max_per_group]
        russia_candidates = russia_candidates[:max_per_group]
        print(f"\n⚡ БЫСТРЫЙ РЕЖИМ: тестируем максимум {MAX_NEW_SERVERS_TO_TEST} серверов")
        print(f"  EUROPE: {len(europe_candidates)}")
        print(f"  RUSSIA: {len(russia_candidates)}")
    else:
        print(f"\n📋 ОБЫЧНЫЙ РЕЖИМ: тестируем все серверы")
    
    found_servers = {"EUROPE": [], "RUSSIA": []}
    
    # Тестируем европейские серверы
    if europe_candidates:
        print(f"\n🌍 ТЕСТИРОВАНИЕ EUROPE ({len(europe_candidates)} серверов)")
        europe_results = test_servers_batch_parallel(europe_candidates, "EUROPE")
        
        for result in europe_results:
            found_servers[result['group']].append(result)
            
            # Добавляем в рейтинг систему
            rating_system.add_test_result(
                result['outbound'], 
                result['speed'], 
                result['country'], 
                result['group'],
                link=result['link']
            )
        
        print(f"  ✓ Найдено рабочих EUROPE: {len([r for r in europe_results if r['group'] == 'EUROPE'])}")
        print(f"  ✓ Найдено рабочих RUSSIA (переклассифицировано): {len([r for r in europe_results if r['group'] == 'RUSSIA'])}")
    
    # Тестируем российские серверы
    if russia_candidates:
        print(f"\n🇷🇺 ТЕСТИРОВАНИЕ RUSSIA ({len(russia_candidates)} серверов)")
        russia_results = test_servers_batch_parallel(russia_candidates, "RUSSIA")
        
        for result in russia_results:
            found_servers[result['group']].append(result)
            
            rating_system.add_test_result(
                result['outbound'], 
                result['speed'], 
                result['country'], 
                result['group'],
                link=result['link']
            )
        
        print(f"  ✓ Найдено рабочих RUSSIA: {len([r for r in russia_results if r['group'] == 'RUSSIA'])}")
        print(f"  ✓ Найдено рабочих EUROPE (переклассифицировано): {len([r for r in russia_results if r['group'] == 'EUROPE'])}")
    
    # Статистика
    print(f"\n📈 ИТОГО НАЙДЕНО РАБОЧИХ:")
    print(f"  EUROPE: {len(found_servers['EUROPE'])}")
    print(f"  RUSSIA: {len(found_servers['RUSSIA'])}")
    
    # Если мало рабочих серверов - пробуем добавить больше кандидатов
    if len(found_servers['EUROPE']) < MIN_WORKING_SERVERS_FAST and not use_fast_mode:
        print(f"\n⚠️  Мало рабочих EUROPE ({len(found_servers['EUROPE'])} < {MIN_WORKING_SERVERS_FAST})")
        print("  Рекомендуется увеличить MAX_NEW_SERVERS_TO_TEST")
    
    if len(found_servers['RUSSIA']) < MIN_WORKING_SERVERS_FAST and not use_fast_mode:
        print(f"\n⚠️  Мало рабочих RUSSIA ({len(found_servers['RUSSIA'])} < {MIN_WORKING_SERVERS_FAST})")
        print("  Рекомендуется увеличить MAX_NEW_SERVERS_TO_TEST")
    
    return found_servers


# ===========================================================================
# ЗАПИСЬ КОНФИГА
# ===========================================================================

def _dedup_tags(proxies: list) -> list:
    proxies = [dict(p) for p in proxies]
    seen: dict = {}
    for pb in proxies:
        t = pb["tag"]
        if t in seen:
            seen[t] += 1
            pb["tag"] = f"{t}-{seen[t]}"
        else:
            seen[t] = 0
    return proxies


def write_config(profile: dict, groups: dict):
    all_raw     = [dict(p) for p in groups["ALL"]]
    all_deduped = _dedup_tags(all_raw)
    n_europe         = len(groups["EUROPE"])
    europe_deduped   = all_deduped[:n_europe]
    russia_deduped   = all_deduped[n_europe:]

    europe_tags = [p["tag"] for p in europe_deduped]
    russia_tags = [p["tag"] for p in russia_deduped]

    enabled = set(profile.get("enabled_groups", ["EUROPE", "RUSSIA", "ALL"]))

    if "EUROPE" not in enabled:
        europe_deduped, europe_tags = [], []
    if "RUSSIA" not in enabled:
        russia_deduped, russia_tags = [], []

    all_tags = (europe_tags + russia_tags) if "ALL" in enabled else []

    proxies = europe_deduped + russia_deduped

    top_groups = []
    if europe_tags:
        top_groups.append("EUROPE")
    if russia_tags:
        top_groups.append("RUSSIA")
    if all_tags:
        top_groups.append("ALL")

    if not top_groups:
        print(f"  ⚠ Нет активных групп для профиля — конфиг не записан.")
        return

    formatted_rule_sets, proxy_routing_tags, block_routing_tags = [], [], []
    rule_tags: set = set()

    def add_rule(tag, url, is_block):
        if tag in rule_tags:
            return
        formatted_rule_sets.append({
            "type": "remote", "tag": tag, "format": "binary", "url": url,
            "download_detour": "direct"
        })
        (block_routing_tags if is_block else proxy_routing_tags).append(tag)
        rule_tags.add(tag)

    folder = profile["ruleset_folder"]
    base   = profile["github_raw_base"]
    if os.path.exists(folder):
        for subfolder, is_block in [(folder, False), (folder + "block/", True)]:
            if not os.path.exists(subfolder):
                continue
            for file in os.listdir(subfolder):
                if file.endswith('.srs'):
                    tag = file.replace('.srs', '')
                    url = f"{base}{'block/' if is_block else ''}{file}"
                    add_rule(tag, url, is_block)

    for url in profile["remote_block_rule_sets"]:
        add_rule(url.split('/')[-1].replace('.srs', ''), url, True)
    for url in profile["remote_rule_sets"]:
        add_rule(url.split('/')[-1].replace('.srs', ''), url, False)

    outbounds = [
        {"type": "selector", "tag": "proxy", "outbounds": top_groups},
    ]

    if europe_tags:
        outbounds += [
            {"type": "selector", "tag": "EUROPE",
             "outbounds": ["EUROPE-auto"] + europe_tags},
            {"type": "urltest",  "tag": "EUROPE-auto", "outbounds": europe_tags,
             "url": "http://cp.cloudflare.com/", "interval": "10m"},
        ]

    if russia_tags:
        outbounds += [
            {"type": "selector", "tag": "RUSSIA",
             "outbounds": ["RUSSIA-auto"] + russia_tags},
            {"type": "urltest",  "tag": "RUSSIA-auto", "outbounds": russia_tags,
             "url": "http://cp.cloudflare.com/", "interval": "10m"},
        ]

    if all_tags:
        outbounds += [
            {"type": "selector", "tag": "ALL",
             "outbounds": ["ALL-auto"] + all_tags},
            {"type": "urltest",  "tag": "ALL-auto", "outbounds": all_tags,
             "url": "http://cp.cloudflare.com/", "interval": "10m"},
        ]

    outbounds += [
        {"type": "direct", "tag": "direct"},
        {"type": "block",  "tag": "block"},
    ] + proxies

    config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "tls://1.1.1.1", "detour": "proxy"},
                {"tag": "local",  "address": "223.5.5.5",     "detour": "direct"}
            ],
            "rules":    [{"outbound": "any", "server": "local"}],
            "final":    "remote",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True}
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [r for r in [
                {"protocol": "dns", "action": "hijack-dns"},
                {"rule_set": block_routing_tags, "outbound": "block"}  if block_routing_tags else None,
                {"rule_set": proxy_routing_tags, "outbound": profile["proxy_rule_outbound"]} if proxy_routing_tags else None,
            ] if r is not None],
            "rule_set":              formatted_rule_sets,
            "final":                 profile["route_final"],
            "auto_detect_interface": True
        }
    }

    output = profile["output_file"]
    header = profile.get("file_header")
    with open(output, 'w', encoding='utf-8') as f:
        if header:
            f.write(header)
        json.dump(config, f, indent=2, ensure_ascii=False)

    active = " + ".join(top_groups)
    print(f"  ✓ {output} сохранён  "
          f"активные группы: [{active}]  "
          f"EUROPE={len(europe_tags)}  RUSSIA={len(russia_tags)}  ALL={len(all_tags)}")


# ===========================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ===========================================================================

def _is_russia(link: str, country: str | None = None) -> bool:
    tag = unquote(urlparse(link).fragment)
    
    if re.search(REGEXP_RUSSIA, tag):
        return True
    
    if country == 'RU':
        return True
    
    return False


def main(profile_names: list):
    print("="*80)
    print("🎯 СИСТЕМА РЕЙТИНГА СЕРВЕРОВ (УМНЫЙ ПОИСК)")
    print("="*80)
    
    # Инициализация рейтинговой системы
    rating_system = ServerRatingSystem()
    
    # Очистка базы
    rating_system.cleanup()
    
    # 1. Загрузка новых серверов
    print("\n" + "="*80)
    print("📥 ЗАГРУЗКА НОВЫХ СЕРВЕРОВ")
    print("="*80)
    
    all_links = fetch_links_from_subscriptions()
    
    if all_links:
        all_links = filter_by_params(all_links)
        all_links = filter_by_cidr(all_links)
        
        print(f"\n✅ После фильтрации: {len(all_links)} серверов")
    else:
        print("❌ Не удалось загрузить серверы")
        return
    
    # 2. Выбор старых серверов для ретеста
    print("\n" + "="*80)
    print("🔄 ВЫБОР СЕРВЕРОВ ДЛЯ РЕТЕСТА")
    print("="*80)
    
    europe_retest = rating_system.get_servers_for_retest(group='EUROPE', count=RETEST_OLD_SERVERS_COUNT)
    russia_retest = rating_system.get_servers_for_retest(group='RUSSIA', count=RETEST_OLD_SERVERS_COUNT)
    
    print(f"Ретест: EUROPE={len(europe_retest)}, RUSSIA={len(russia_retest)}")
    
    # 3. УМНЫЙ ПОИСК НОВЫХ СЕРВЕРОВ (как в index.html)
    print("\n" + "="*80)
    print("🧠 УМНЫЙ ПОИСК НОВЫХ СЕРВЕРОВ")
    print("="*80)
    
    found_servers = smart_server_search(all_links, rating_system)
    
    # 4. Ретест старых серверов
    if europe_retest or russia_retest:
        print("\n" + "="*80)
        print("🔄 РЕТЕСТ СТАРЫХ СЕРВЕРОВ")
        print("="*80)
        
        # Объединяем старые серверы для ретеста
        old_servers_to_test = []
        
        for server_info in europe_retest + russia_retest:
            outbound = server_info['outbound']
            link = server_info.get('link')
            group = server_info['group']
            
            if link:
                old_servers_to_test.append({
                    'outbound': outbound,
                    'link': link,
                    'group': group,
                    'tag': outbound.get('tag', 'Unknown')
                })
        
        if old_servers_to_test:
            print(f"  → Ретестируем {len(old_servers_to_test)} старых серверов...")
            
            # Параллельный ретест старых серверов
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_FAST) as executor:
                futures = {}
                for server in old_servers_to_test:
                    future = executor.submit(_quick_single_probe, server['link'], CONN_TIMEOUT)
                    futures[future] = server
                
                for future in concurrent.futures.as_completed(futures):
                    server = futures[future]
                    try:
                        speed = future.result(timeout=10)
                        rating_system.add_test_result(
                            server['outbound'], 
                            speed, 
                            None, 
                            server['group'],
                            link=server['link']
                        )
                        if speed:
                            print(f"    ✓ {server['tag'][:40]} - {speed:.1f} Mbps")
                        else:
                            print(f"    ✗ {server['tag'][:40]} - не отвечает")
                    except Exception as e:
                        print(f"    ⚠️ {server['tag'][:40]} - ошибка: {str(e)[:50]}")
    
    # 5. Пересчёт всех рейтингов
    print("\n" + "="*80)
    print("⚙️  ПЕРЕСЧЁТ РЕЙТИНГОВ")
    print("="*80)
    
    rating_system.recalculate_all_ratings()
    
    # 6. Статистика
    rating_system.print_stats()
    
    # 7. Отбор серверов для конфига
    print("\n" + "="*80)
    print("📋 ФОРМИРОВАНИЕ КОНФИГА")
    print("="*80)
    
    europe_servers = rating_system.get_top_servers(
        group='EUROPE',
        limit=MAX_SERVERS_IN_CONFIG,
        min_rating=MIN_RATING_THRESHOLD
    )
    
    russia_servers = rating_system.get_top_servers(
        group='RUSSIA',
        limit=MAX_SERVERS_IN_CONFIG,
        min_rating=MIN_RATING_THRESHOLD
    )
    
    print(f"\nОтобрано для конфига: EUROPE={len(europe_servers)}, RUSSIA={len(russia_servers)}")
    
    if not europe_servers and not russia_servers:
        print("\n❌ Критическая ошибка: нет серверов с достаточным рейтингом!")
        return
    
    # Выводим топ-10
    print("\n🏆 ТОП-10 СЕРВЕРОВ ПО РЕЙТИНГУ:")
    for group_name, servers in [("EUROPE", europe_servers), ("RUSSIA", russia_servers)]:
        if not servers:
            continue
        print(f"\n{group_name}:")
        for i, server in enumerate(servers[:10], 1):
            tag = server['outbound'].get('tag', 'Unknown')[:40]
            rating = server['rating']
            comp = server['components']
            country = f"[{server['country']}]" if server.get('country') else ""
            
            print(f"  {i:2}. {tag:<40} R={rating:.3f} {country}")
            print(f"      sp={comp.get('speed', 0):.2f} st={comp.get('stability', 0):.2f} "
                  f"up={comp.get('uptime', 0):.2f} cs={comp.get('consistency', 0):.2f} "
                  f"fr={comp.get('freshness', 0):.2f}")
    
    # 8. Формируем группы для конфига
    groups = {
        "EUROPE": [s['outbound'] for s in europe_servers],
        "RUSSIA": [s['outbound'] for s in russia_servers],
        "ALL":    [s['outbound'] for s in europe_servers] + [s['outbound'] for s in russia_servers],
    }
    
    # 9. Запись конфигов
    print("\n" + "="*80)
    print("💾 ЗАПИСЬ КОНФИГОВ")
    print("="*80)
    
    for name in profile_names:
        print(f"\n[{name}]")
        write_config(PROFILES[name], groups)
    
    print("\n✅ Обновление завершено успешно!")


if __name__ == "__main__":
    requested = sys.argv[1:] if len(sys.argv) > 1 else list(PROFILES.keys())
    unknown = [n for n in requested if n not in PROFILES]
    if unknown:
        print(f"Неизвестные профили: {unknown}")
        print(f"Доступные: {list(PROFILES.keys())}")
        sys.exit(1)
    main(requested)