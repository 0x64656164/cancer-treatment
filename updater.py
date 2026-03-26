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
import threading
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
RATING_WEIGHTS = {
    'speed':       0.20,
    'stability':   0.15,
    'uptime':      0.40,
    'consistency': 0.10,
    'freshness':   0.15,
}

# Параметры рейтинговой системы
RATING_MIN_TESTS = 2
RATING_DECAY_HOURS = 1
RATING_STABILITY_THRESHOLD = 0.3
RATING_SLIDING_WINDOW = 24  # количество последних проверок для анализа стабильности

# Параметры отбора серверов
TOP_SERVERS_PERCENT = 0.7
MIN_RATING_THRESHOLD = 0.15
MAX_SERVERS_IN_CONFIG = 50

# Параметры очистки базы
MAX_SERVER_AGE_HOURS = 6
MIN_TESTS_TO_KEEP = 1
MAX_SERVERS_IN_DB = 150

# Параметры тестирования
TEST_NEW_SERVERS_COUNT = 40
RETEST_OLD_SERVERS_COUNT = 50
RETEST_LOW_RATING_FIRST = True

# ОПТИМИЗИРОВАННЫЕ НАСТРОЙКИ
MAX_NEW_SERVERS_TO_TEST = 1000
MAX_WORKERS_FAST = 64
FAST_MODE_THRESHOLD = 300
MIN_WORKING_SERVERS_FAST = 10

# ---------------------------------------------------------------------------
# НОВЫЕ ПАРАМЕТРЫ ДЛЯ НЕСТАБИЛЬНЫХ СЕРВЕРОВ
# ---------------------------------------------------------------------------
CATEGORY_STABLE = "A"
CATEGORY_MEDIUM = "B"
CATEGORY_UNSTABLE = "C"

CATEGORY_THRESHOLDS = {
    CATEGORY_STABLE:   0.70,   # рейтинг >= 0.70 и стабильность >= 0.8
    CATEGORY_MEDIUM:   0.40,   # рейтинг >= 0.40
    CATEGORY_UNSTABLE: 0.00,   # остальные
}
STABILITY_FOR_CATEGORY_A = 0.8

# Карантин
QUARANTINE_DURATION_HOURS = 2
QUARANTINE_CONSECUTIVE_FAILS = 3

# Массовые падения
MASS_FAILURE_THRESHOLD = 0.40   # если упало >40% серверов
MASS_FAILURE_COOLDOWN_HOURS = 1
MASS_FAILURE_STATE_FILE = 'mass_failure_state.json'

# Зомби-серверы (работают только на момент проверки)
ZOMBIE_CONSECUTIVE_PASSES = 3    # если 3 проверки подряд успешны, то не зомби
ZOMBIE_STAGING_MINUTES = 60      # время, в течение которого сервер считается кандидатом (раньше было 15)
ZOMBIE_MAX_SPEED = 9.0           # скорость <1 Mbps - подозрение

# Прогнозирование (временные паттерны)
PATTERN_HOURS = 24
BAD_HOURS_THRESHOLD = 0.5        # если в час падает >50% проверок - метка

# Часовой пояс для временных паттернов (смещение от UTC в часах)
# Можно задать через переменную окружения TZ_OFFSET (по умолчанию 3 для MSK)
TZ_OFFSET = int(os.environ.get('TZ_OFFSET', '3'))

# Глобальные счетчики для массовых падений
_mass_failure_state = {
    "active": False,
    "timestamp": None,
    "previous_state": None
}

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
]
CIDR_WHITELIST_FILE = 'cidr_whitelist2.txt'

REGEXP_RUSSIA = r'(?:\bRussia\b|\bRU\b|🇷🇺)'

COUNTRY_API_URL = 'https://api.country.is/'
COUNTRY_CHECK_TIMEOUT = 3

MIN_SERVERS = 5
MIN_BEST_SPEED = 2.5
MAX_WORKERS = 64

PROBE_ROUNDS = 3
PROBE_DELAY = 30
PROBE_URL = 'https://cachefly.cachefly.net/10mb.test'
FAST_PROBE_URL = 'http://www.gstatic.com/generate_204'
CONN_TIMEOUT = 3
READ_TIMEOUT = 5

MIN_SUCCESS_ROUNDS = 1
SCORE_FLOOR_RATIO = 0.25
MIN_KEEP_PER_GROUP = 5

# ---------------------------------------------------------------------------
# ФИЛЬТР ПО ПАРАМЕТРАМ ПРОТОКОЛА
# ---------------------------------------------------------------------------
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
# СИСТЕМА РЕЙТИНГА СЕРВЕРОВ (РАСШИРЕННАЯ)
# ===========================================================================

# ===========================================================================
# СИСТЕМА РЕЙТИНГА СЕРВЕРОВ (РАСШИРЕННАЯ)
# ===========================================================================

class ServerRatingSystem:
    def __init__(self, db_file=SERVERS_DB_FILE):
        self.db_file = db_file
        self._lock = threading.Lock()  # для защиты записи в JSON
        self.data = self._load()
        self._migrate_old_data()
        
    def _load(self) -> dict:
        if not os.path.exists(self.db_file):
            return {"servers": {}, "metadata": {"last_cleanup": None}}
        try:
            with open(self.db_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data
        except Exception as e:
            print(f"⚠ Ошибка чтения базы рейтингов: {e}")
            return {"servers": {}, "metadata": {"last_cleanup": None}}
    
    def _save(self):
        try:
            with self._lock:
                # Запись во временный файл для атомарности
                tmp_file = self.db_file + '.tmp'
                with open(tmp_file, 'w', encoding='utf-8') as f:
                    json.dump(self.data, f, indent=2, ensure_ascii=False)
                os.replace(tmp_file, self.db_file)  # атомарная операция
        except Exception as e:
            print(f"⚠ Ошибка записи базы рейтингов: {e}")
    
    def _migrate_old_data(self):
        """Миграция старых записей: добавление отсутствующих полей"""
        servers = self.data.get("servers", {})
        migrated_count = 0
        
        for key, server_data in servers.items():
            changed = False
            
            # check_history - обязательно для работы
            if 'check_history' not in server_data:
                server_data['check_history'] = []
                # Переносим старую историю, если есть
                if 'history' in server_data:
                    server_data['check_history'] = server_data.get('history', [])
                changed = True
            
            # consecutive_successes - счётчик успешных проверок подряд
            if 'consecutive_successes' not in server_data:
                server_data['consecutive_successes'] = 0
                changed = True
            
            # active - статус активности (после 3 успешных проверок)
            if 'active' not in server_data:
                server_data['active'] = False
                changed = True
            
            # staging_until - время до которого сервер считается кандидатом
            if 'staging_until' not in server_data:
                server_data['staging_until'] = None
                changed = True
            
            # consecutive_failures - счётчик неудачных проверок подряд
            if 'consecutive_failures' not in server_data:
                server_data['consecutive_failures'] = 0
                changed = True
            
            # bad_hours - часы с плохой стабильностью
            if 'bad_hours' not in server_data:
                server_data['bad_hours'] = []
                changed = True
            
            # Обработка случая, когда check_history пустой, но есть speed_history
            # Создаём check_history из speed_history для обратной совместимости
            if not server_data['check_history'] and server_data.get('speed_history'):
                # Получаем время последней проверки
                last_seen = server_data.get('last_seen')
                if last_seen:
                    try:
                        last_seen_dt = datetime.fromisoformat(last_seen)
                    except:
                        last_seen_dt = datetime.now()
                else:
                    last_seen_dt = datetime.now()
                
                for i, speed in enumerate(server_data['speed_history']):
                    # Создаём время с небольшим сдвигом для каждой записи
                    check_time = last_seen_dt - timedelta(hours=(len(server_data['speed_history']) - i) * 2)
                    check_entry = {
                        'timestamp': check_time.isoformat(),
                        'success': speed > 0,
                        'speed': speed,
                        'latency': None,
                        'error': None
                    }
                    server_data['check_history'].append(check_entry)
                changed = True
            
            if changed:
                migrated_count += 1
        
        if migrated_count > 0:
            print(f"🔄 Миграция базы данных: обновлено {migrated_count} записей")
            self._save()
    
    def _get_server_key(self, outbound: dict) -> str:
        key_parts = [
            outbound.get('type', ''),
            outbound.get('server', ''),
            str(outbound.get('server_port', '')),
            outbound.get('uuid', outbound.get('password', ''))[:8]
        ]
        return '|'.join(key_parts)
    
    def _calculate_rating(self, server_data: dict, group_max_speed: float = 100.0) -> Tuple[float, dict]:
        now = datetime.now()
        speeds = server_data.get('speed_history', [])
        total_tests = server_data.get('total_tests', 0)
        successful_tests = server_data.get('successful_tests', 0)
        first_seen = datetime.fromisoformat(server_data.get('first_seen', now.isoformat()))
        last_seen = datetime.fromisoformat(server_data.get('last_seen', now.isoformat()))
        
        # Получаем историю проверок (временные метки и статусы)
        check_history = server_data.get('check_history', [])
        
        components = {'speed': 0.0, 'stability': 0.0, 'uptime': 0.0, 'consistency': 0.0, 'freshness': 0.0}
        
        if not speeds or total_tests == 0:
            return 0.0, components
        
        # Неактивные серверы (не прошедшие порог ZOMBIE_CONSECUTIVE_PASSES) получают нулевой рейтинг
        if not server_data.get('active', False):
            return 0.0, components
        
        # Скорость (средняя)
        avg_speed = sum(speeds) / len(speeds)
        components['speed'] = min(1.0, avg_speed / max(group_max_speed, 1.0))
        
        # Стабильность: учитываем скользящее окно последних RATING_SLIDING_WINDOW проверок
        if check_history:
            recent_checks = check_history[-RATING_SLIDING_WINDOW:]
            successful_recent = sum(1 for ch in recent_checks if ch.get('success', False))
            stability_recent = successful_recent / len(recent_checks) if recent_checks else 0
            # Смешиваем с общей успешностью
            overall_stability = successful_tests / max(total_tests, 1)
            components['stability'] = (stability_recent * 0.7 + overall_stability * 0.3)
        else:
            components['stability'] = successful_tests / max(total_tests, 1)
        
        # Время жизни
        uptime_hours = (now - first_seen).total_seconds() / 3600
        if uptime_hours < 0.1:
            components['uptime'] = 0.01
        elif uptime_hours < 1.0:
            components['uptime'] = 0.05 + (uptime_hours / 1.0) * 0.30
        elif uptime_hours < 6.0:
            components['uptime'] = 0.35 + ((uptime_hours - 1.0) / 5.0) * 0.35
        elif uptime_hours < 24.0:
            components['uptime'] = 0.70 + ((uptime_hours - 6.0) / 18.0) * 0.20
        elif uptime_hours < 72.0:
            components['uptime'] = 0.90 + ((uptime_hours - 24.0) / 48.0) * 0.10
        else:
            components['uptime'] = 1.0
        
        # Согласованность (коэффициент вариации)
        if len(speeds) >= 2:
            mean = sum(speeds) / len(speeds)
            variance = sum((s - mean) ** 2 for s in speeds) / len(speeds)
            cv = (variance ** 0.5) / max(mean, 1)
            components['consistency'] = max(0.0, 1.0 - min(cv / 0.5, 2.0))
        else:
            components['consistency'] = 0.5
        
        # Свежесть
        hours_since_last = (now - last_seen).total_seconds() / 3600
        components['freshness'] = 0.5 ** (hours_since_last / RATING_DECAY_HOURS)
        
        rating = sum(components[k] * RATING_WEIGHTS[k] for k in components)
        
        if total_tests < RATING_MIN_TESTS:
            rating *= total_tests / RATING_MIN_TESTS
        
        return rating, components
    
    def _update_category(self, server_data: dict) -> str:
        """Определение категории на основе рейтинга и стабильности"""
        rating = server_data.get('rating', 0)
        stability = server_data.get('rating_components', {}).get('stability', 0)
        
        # Если сервер в карантине, возвращаем "C" с пометкой
        if server_data.get('quarantine_until'):
            try:
                quarantine_until = datetime.fromisoformat(server_data['quarantine_until'])
                if quarantine_until > datetime.now():
                    return CATEGORY_UNSTABLE
            except (ValueError, TypeError):
                pass
        
        if rating >= CATEGORY_THRESHOLDS[CATEGORY_STABLE] and stability >= STABILITY_FOR_CATEGORY_A:
            return CATEGORY_STABLE
        elif rating >= CATEGORY_THRESHOLDS[CATEGORY_MEDIUM]:
            return CATEGORY_MEDIUM
        else:
            return CATEGORY_UNSTABLE
    
    def _check_mass_failure(self, results: List[dict]) -> bool:
        global _mass_failure_state
        total = len(results)
        if total == 0:
            return False
        dead = sum(1 for r in results if r.get('status') in ('dead', 'error'))
        failure_rate = dead / total
        
        now = datetime.now()
        if failure_rate > MASS_FAILURE_THRESHOLD:
            if not _mass_failure_state['active']:
                _mass_failure_state['active'] = True
                _mass_failure_state['timestamp'] = now.isoformat()
                # Сохраняем предыдущее состояние (список активных серверов)
                _mass_failure_state['previous_state'] = self.get_top_servers(limit=500)
                _save_mass_failure_state(_mass_failure_state)
                print(f"⚠️ МАССОВОЕ ПАДЕНИЕ: {failure_rate*100:.1f}% серверов не отвечают. Переход в режим защиты.")
                return True
            else:
                # Если уже в режиме защиты, но прошло больше cooldown, снимаем
                ts = datetime.fromisoformat(_mass_failure_state['timestamp'])
                if (now - ts).total_seconds() / 3600 > MASS_FAILURE_COOLDOWN_HOURS:
                    _mass_failure_state['active'] = False
                    _mass_failure_state['timestamp'] = None
                    _mass_failure_state['previous_state'] = None
                    _save_mass_failure_state(_mass_failure_state)
                    print("✅ Режим защиты снят.")
        else:
            if _mass_failure_state['active']:
                # Восстановление
                ts = datetime.fromisoformat(_mass_failure_state['timestamp'])
                if (now - ts).total_seconds() / 3600 > MASS_FAILURE_COOLDOWN_HOURS:
                    _mass_failure_state['active'] = False
                    _mass_failure_state['timestamp'] = None
                    _mass_failure_state['previous_state'] = None
                    _save_mass_failure_state(_mass_failure_state)
                    print("✅ Режим защиты снят.")
        return _mass_failure_state['active']
    
    def _analyze_patterns(self, server_data: dict):
        """Анализ временных паттернов падений с учётом часового пояса"""
        check_history = server_data.get('check_history', [])
        if len(check_history) < 24:
            return
        
        # Группируем по часам (с учётом смещения TZ_OFFSET)
        hour_stats = {}
        for check in check_history[-PATTERN_HOURS:]:
            try:
                ts = datetime.fromisoformat(check['timestamp'])
                # Применяем смещение часового пояса
                hour = (ts.hour + TZ_OFFSET) % 24
                if hour not in hour_stats:
                    hour_stats[hour] = {'total': 0, 'success': 0}
                hour_stats[hour]['total'] += 1
                if check.get('success', False):
                    hour_stats[hour]['success'] += 1
            except (ValueError, TypeError):
                continue
        
        # Определяем часы с плохой стабильностью
        bad_hours = []
        for hour, stats in hour_stats.items():
            if stats['total'] > 0:
                success_rate = stats['success'] / stats['total']
                if success_rate < BAD_HOURS_THRESHOLD:
                    bad_hours.append(hour)
        server_data['bad_hours'] = bad_hours
    
    def _apply_quarantine(self, server_data: dict):
        """Применение карантина при последовательных падениях"""
        check_history = server_data.get('check_history', [])
        if len(check_history) >= QUARANTINE_CONSECUTIVE_FAILS:
            recent = check_history[-QUARANTINE_CONSECUTIVE_FAILS:]
            if all(not ch.get('success', False) for ch in recent):
                now = datetime.now()
                quarantine_until = now + timedelta(hours=QUARANTINE_DURATION_HOURS)
                server_data['quarantine_until'] = quarantine_until.isoformat()
                print(f"  ⚠️ Сервер {server_data['outbound'].get('tag', 'unknown')} помещен в карантин до {quarantine_until}")
                return True
        return False
    
    def add_test_result(self, outbound: dict, speed: Optional[float], 
                       country: Optional[str], group: str, link: Optional[str] = None) -> bool:
        key = self._get_server_key(outbound)
        now = datetime.now().isoformat()
        servers = self.data.setdefault("servers", {})
        
        if key not in servers:
            servers[key] = {
                'outbound': outbound, 'link': link, 'group': group, 'country': country,
                'first_seen': now, 'last_seen': now, 'total_tests': 0, 'successful_tests': 0,
                'speed_history': [], 'check_history': [], 'rating': 0.0, 'rating_components': {},
                'category': CATEGORY_UNSTABLE, 'quarantine_until': None, 'bad_hours': [],
                'consecutive_successes': 0,   # для зомби-серверов
                'active': False,               # стал активным после 3 успешных проверок
                'staging_until': None,         # временная метка, до которой сервер считается кандидатом
                'consecutive_failures': 0
            }
        
        server = servers[key]
        server['total_tests'] += 1
        if link:
            server['link'] = link
        
        # Добавляем запись в историю проверок
        check_entry = {
            'timestamp': now,
            'success': speed is not None and speed > 0,
            'speed': speed if speed else 0,
            'latency': None,  # можно добавить позже
            'error': None
        }
        
        # Инициализируем check_history, если его нет (на случай проблем с миграцией)
        if 'check_history' not in server:
            server['check_history'] = []
        
        server['check_history'].append(check_entry)
        # Ограничиваем историю (например, 100 записей)
        if len(server['check_history']) > 100:
            server['check_history'] = server['check_history'][-100:]
        
        if speed is not None and speed > 0:
            server['successful_tests'] += 1
            server['last_seen'] = now
            server['country'] = country or server.get('country')
            speed_history = server.get('speed_history', [])
            speed_history.append(speed)
            server['speed_history'] = speed_history[-10:]
            
            # Снимаем карантин при успешной проверке
            if server.get('quarantine_until'):
                server['quarantine_until'] = None
                print(f"  ✓ Сервер {outbound.get('tag', 'unknown')} вышел из карантина")
            
            # --- Логика зомби-серверов (staging) ---
            # Увеличиваем счётчик успешных проверок
            server['consecutive_successes'] = server.get('consecutive_successes', 0) + 1
            # Если счётчик достиг порога, сервер становится активным
            if server['consecutive_successes'] >= ZOMBIE_CONSECUTIVE_PASSES:
                if not server.get('active', False):
                    server['active'] = True
                    server['staging_until'] = None
                    print(f"  ✨ Сервер {outbound.get('tag', 'unknown')} стал активным (3 успешные проверки подряд)")
            else:
                # Если ещё не активен, устанавливаем staging_until на ZOMBIE_STAGING_MINUTES вперёд
                if not server.get('active', False):
                    staging_until = datetime.now() + timedelta(minutes=ZOMBIE_STAGING_MINUTES)
                    server['staging_until'] = staging_until.isoformat()
            
            # Сбрасываем счётчик неудач
            server['consecutive_failures'] = 0
        else:
            # Неудачная проверка
            # Сбрасываем счётчик успешных и активность
            server['consecutive_successes'] = 0
            server['active'] = False
            server['staging_until'] = None
            # Увеличиваем счётчик неудач для карантина
            server['consecutive_failures'] = server.get('consecutive_failures', 0) + 1
            # Проверяем необходимость карантина
            self._apply_quarantine(server)
        
        self._save()
        return speed is not None and speed > 0
    
    def recalculate_all_ratings(self):
        servers = self.data.get("servers", {})
        groups_max_speed = {}
        for server_data in servers.values():
            group = server_data.get('group', 'UNKNOWN')
            speeds = server_data.get('speed_history', [])
            if speeds:
                avg_speed = sum(speeds) / len(speeds)
                groups_max_speed[group] = max(groups_max_speed.get(group, 0), avg_speed)
        
        for key, server_data in servers.items():
            group = server_data.get('group', 'UNKNOWN')
            max_speed = groups_max_speed.get(group, 100.0)
            rating, components = self._calculate_rating(server_data, max_speed)
            server_data['rating'] = rating
            server_data['rating_components'] = components
            server_data['category'] = self._update_category(server_data)
            self._analyze_patterns(server_data)
        self._save()
    
    def get_top_servers(self, group: Optional[str] = None, 
                       limit: Optional[int] = None,
                       min_rating: float = MIN_RATING_THRESHOLD,
                       include_categories: Optional[List[str]] = None,
                       current_hour: Optional[int] = None) -> List[dict]:
        servers = self.data.get("servers", {})
        if current_hour is None:
            # Текущий час с учётом смещения
            current_hour = (datetime.now().hour + TZ_OFFSET) % 24
        
        filtered = []
        added_keys = set()
        enabled_groups = _get_enabled_groups()
        for key, server_data in servers.items():
            if group and (server_data.get('group') != group or not group in enabled_groups):
                continue
            rating = server_data.get('rating', 0)
            if rating < min_rating:
                continue
            stability = server_data.get('rating_components', {}).get('stability', 0)
            if stability < RATING_STABILITY_THRESHOLD:
                continue
            category = server_data.get('category', CATEGORY_UNSTABLE)
            if include_categories and category not in include_categories:
                continue
            # Пропускаем серверы в карантине
            quarantine_until = server_data.get('quarantine_until')
            if quarantine_until:
                try:
                    if datetime.fromisoformat(quarantine_until) > datetime.now():
                        continue
                except (ValueError, TypeError):
                    pass
            
            # Использование временных паттернов: пропускаем, если текущий час в bad_hours
            bad_hours = server_data.get('bad_hours', [])
            if current_hour in bad_hours:
                continue
            
            # Используем только активные серверы
            if not server_data.get('active', False):
                continue
            
            filtered.append({
                'key': key, 'outbound': server_data['outbound'], 'link': server_data.get('link'),
                'rating': rating, 'components': server_data.get('rating_components', {}),
                'country': server_data.get('country'), 'total_tests': server_data.get('total_tests', 0),
                'successful_tests': server_data.get('successful_tests', 0), 'last_seen': server_data.get('last_seen'),
                'category': category, 'bad_hours': bad_hours
            })
            added_keys.add(key)
        
        filtered.sort(key=lambda x: x['rating'], reverse=True)
        
        if len(filtered) < MIN_SERVERS and group:
            print(f"⚠️  [{group}] Мало активных серверов ({len(filtered)}), смягчаем критерии...")
            # Включаем также серверы, которые находятся в стадии активации (staging)
            for key, server_data in servers.items():
                if group and server_data.get('group') != group:
                    continue
                if key in added_keys:
                    continue
                rating = server_data.get('rating', 0)
                if rating < min_rating * 0.5:
                    continue
                # Пропускаем в карантине
                quarantine_until = server_data.get('quarantine_until')
                if quarantine_until:
                    try:
                        if datetime.fromisoformat(quarantine_until) > datetime.now():
                            continue
                    except (ValueError, TypeError):
                        pass
                # Пропускаем, если час в bad_hours
                if current_hour in server_data.get('bad_hours', []):
                    continue
                
                # Включаем только серверы, которые либо активны, либо находятся в стадии активации (staging)
                active_flag = server_data.get('active', False)
                staging_until = server_data.get('staging_until')
                is_candidate = active_flag
                if not is_candidate and staging_until:
                    try:
                        is_candidate = datetime.fromisoformat(staging_until) > datetime.now()
                    except (ValueError, TypeError):
                        is_candidate = False
                if not is_candidate:
                    continue
                
                filtered_relaxed = {
                    'key': key, 'outbound': server_data['outbound'], 'link': server_data.get('link'),
                    'rating': rating, 'components': server_data.get('rating_components', {}),
                    'country': server_data.get('country'), 'total_tests': server_data.get('total_tests', 0),
                    'successful_tests': server_data.get('successful_tests', 0), 'last_seen': server_data.get('last_seen'),
                    'category': server_data.get('category', CATEGORY_UNSTABLE),
                }
                filtered.append(filtered_relaxed)
                added_keys.add(key)
            filtered.sort(key=lambda x: x['rating'], reverse=True)
            print(f"✓ Найдено {len(filtered)} серверов с мягкими критериями (активные + стадия активации)")
        
        if limit:
            filtered = filtered[:limit]
        return filtered
    
    def get_servers_for_retest(self, group: Optional[str] = None, 
                               count: int = RETEST_OLD_SERVERS_COUNT,
                               prioritize_low_rating: bool = RETEST_LOW_RATING_FIRST) -> List[dict]:
        servers = self.data.get("servers", {})
        now = datetime.now()
        candidates = []
        for key, server_data in servers.items():
            if group and server_data.get('group') != group:
                continue
            try:
                last_seen = datetime.fromisoformat(server_data.get('last_seen', now.isoformat()))
            except (ValueError, TypeError):
                last_seen = now
            hours_since = (now - last_seen).total_seconds() / 3600
            rating = server_data.get('rating', 0)
            category = server_data.get('category', CATEGORY_UNSTABLE)
            # Приоритет: сначала нестабильные (C), потом средние (B), потом стабильные (A)
            category_priority = {'C': 3, 'B': 2, 'A': 1}.get(category, 1)
            priority = category_priority * 10 + hours_since * (1.1 - rating) if prioritize_low_rating else hours_since
            candidates.append({
                'key': key, 'outbound': server_data['outbound'], 'link': server_data.get('link'),
                'group': server_data.get('group'), 'priority': priority,
                'hours_since_last': hours_since, 'rating': rating, 'category': category
            })
        candidates.sort(key=lambda x: x['priority'], reverse=True)
        return candidates[:count]
    
    def cleanup(self):
        servers = self.data.get("servers", {})
        now = datetime.now()
        cutoff = now - timedelta(hours=MAX_SERVER_AGE_HOURS)
        to_remove = []
        
        for key, server_data in servers.items():
            try:
                last_seen = datetime.fromisoformat(server_data.get('last_seen', now.isoformat()))
            except (ValueError, TypeError):
                last_seen = now
            total_tests = server_data.get('total_tests', 0)
            successful_tests = server_data.get('successful_tests', 0)
            rating = server_data.get('rating', 0)
            should_remove = ((last_seen < cutoff) or (successful_tests < MIN_TESTS_TO_KEEP) or
                            (rating < MIN_RATING_THRESHOLD * 0.5 and total_tests >= 3))
            if should_remove:
                to_remove.append(key)
        
        for key in to_remove:
            del servers[key]
        
        for group in ['EUROPE', 'RUSSIA', 'ALL']:
            group_servers = [(k, v['rating']) for k, v in servers.items() if v.get('group') == group]
            if len(group_servers) > MAX_SERVERS_IN_DB:
                group_servers.sort(key=lambda x: x[1], reverse=True)
                for key, _ in group_servers[MAX_SERVERS_IN_DB:]:
                    if key in servers:
                        del servers[key]
        
        self.data['metadata']['last_cleanup'] = now.isoformat()
        self._save()
        if to_remove:
            print(f"🗑️  Очистка: удалено {len(to_remove)} серверов")
    
    def print_stats(self):
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
            categories = {'A': 0, 'B': 0, 'C': 0}
            active_count = sum(1 for s in group_servers if s.get('active', False))
            for s in group_servers:
                categories[s.get('category', 'C')] += 1
            print(f"\n{group}:")
            print(f"  Всего серверов: {len(group_servers)}")
            print(f"  Активных: {active_count}")
            print(f"  Средний рейтинг: {avg_rating:.3f}")
            print(f"  Категории: A={categories['A']}, B={categories['B']}, C={categories['C']}")
            print(f"  Топ-5 серверов:")
            group_servers.sort(key=lambda x: x.get('rating', 0), reverse=True)
            for i, server in enumerate(group_servers[:5], 1):
                tag = server['outbound'].get('tag', 'Unknown')[:40]
                rating = server.get('rating', 0)
                comp = server.get('rating_components', {})
                cat = server.get('category', '?')
                active_mark = '✓' if server.get('active') else ' '
                print(f"    {i}. {tag:<40} [{cat}]{active_mark} R={rating:.3f} "
                      f"[sp={comp.get('speed', 0):.2f} st={comp.get('stability', 0):.2f} "
                      f"up={comp.get('uptime', 0):.2f} cs={comp.get('consistency', 0):.2f} "
                      f"fr={comp.get('freshness', 0):.2f}]")
    
    def get_statistics(self) -> dict:
        servers = self.data.get("servers", {})
        total = len(servers)
        active = sum(1 for s in servers.values() if s.get('active', False))
        europe = len([s for s in servers.values() if s.get('group') == 'EUROPE'])
        russia = len([s for s in servers.values() if s.get('group') == 'RUSSIA'])
        categories = {'A':0, 'B':0, 'C':0}
        for s in servers.values():
            categories[s.get('category', 'C')] += 1
        return {
            'total': total, 'active': active, 'europe': europe, 'russia': russia,
            'categories': categories
        }


# ===========================================================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С СОСТОЯНИЕМ МАССОВОГО ПАДЕНИЯ
# ===========================================================================

def _load_mass_failure_state():
    global _mass_failure_state
    if not os.path.exists(MASS_FAILURE_STATE_FILE):
        return
    try:
        with open(MASS_FAILURE_STATE_FILE, 'r') as f:
            data = json.load(f)
        _mass_failure_state.update(data)
    except Exception as e:
        print(f"⚠ Ошибка загрузки состояния массового падения: {e}")

def _save_mass_failure_state(state):
    try:
        with open(MASS_FAILURE_STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        print(f"⚠ Ошибка сохранения состояния массового падения: {e}")


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
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
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
            p["transport"] = net if net else "tcp"
            p["security"] = tls if tls else "none"
            p["sni"] = data.get("sni", "")
            p["fp"] = data.get("fp", "")
            p["host"] = data.get("host", "")
            p["path"] = data.get("path", "")
            p["encryption"] = data.get("scy", data.get("security", "auto"))
            alpn_raw = data.get("alpn", "")
            p["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()] if alpn_raw else []
            if not p["port"] and data.get("port"):
                p["port"] = str(data["port"])
            return p

        qs = parse_qs(parsed.query, keep_blank_values=True)
        def q(key): return qs.get(key, [""])[0]

        p["transport"] = q("type") or "tcp"
        p["security"] = q("security") or ("tls" if proto == "trojan" else "none")
        p["flow"] = q("flow")
        p["sni"] = q("sni")
        p["fp"] = q("fp")
        p["host"] = q("host")
        p["path"] = q("path")
        p["pbk"] = q("pbk")
        p["sid"] = q("sid")
        p["service_name"] = q("serviceName")
        p["obfs"] = q("obfs") or q("obfsType")
        p["obfs_password"] = q("obfs-password") or q("obfsParam")
        alpn_raw = q("alpn")
        p["alpn"] = [a.strip() for a in unquote(alpn_raw).split(",") if a.strip()] if alpn_raw else []
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

    check("transport", _str_matches, p["transport"], rules.get("transport", []))
    check("security", _str_matches, p["security"], rules.get("security", []))
    check("flow", _str_matches, p["flow"], rules.get("flow", []))
    check("sni", _str_matches, p["sni"], rules.get("sni", []))
    check("fp", _str_matches, p["fp"], rules.get("fp", []))
    check("host", _str_matches, p["host"], rules.get("host", []))
    check("encryption", _str_matches, p["encryption"], rules.get("encryption", []))
    check("pbk", _str_matches, p["pbk"], rules.get("pbk", []))
    check("sid", _str_matches, p["sid"], rules.get("sid", []))
    check("service_name", _str_matches, p["service_name"], rules.get("service_name", []))
    check("obfs", _str_matches, p["obfs"], rules.get("obfs", []))
    check("port", _port_matches, p["port"], rules.get("port", []))
    check("path", _path_matches, p["path"], rules.get("path", []))
    check("alpn", _alpn_matches, p["alpn"], rules.get("alpn", []))
    check("obfs_password", _regex_matches, p["obfs_password"], rules.get("obfs_password", []))

    if not checks:
        return True
    return any(checks) if logic == "OR" else all(checks)


def filter_by_params(links: list) -> list:
    before = len(links)
    passed = [l for l in links if passes_protocol_filter(l)]
    print(f"Фильтр параметров: прошло {len(passed)} из {before} (отсеяно {before - len(passed)})\n")
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
    print(f"CIDR-whitelist загружен: {len(networks)} сетей" + (f", пропущено некорректных строк: {errors}" if errors else ""))
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
# ЗОНДИРОВАНИЕ (ТРЁХЭТАПНОЕ)
# ===========================================================================

def parse_link(proxy, link):
    if link.startswith("vmess://"):
        return proxy._parse_vmess_link(link)
    if link.startswith("vless://"):
        return proxy._parse_vless_link(link)
    if link.startswith("trojan://"):
        return proxy._parse_trojan_link(link)
    if link.startswith(("hy2://", "hysteria2://")):
        return proxy._parse_hysteria2_link(link)
    raise ValueError(f"Неизвестный протокол: {link[:20]}")


def _fix_outbound(outbound: dict) -> dict:
    if "transport" in outbound and outbound["transport"].get("type") == "xhttp":
        outbound["transport"]["type"] = "httpupgrade"
        if isinstance(outbound["transport"].get("host"), list):
            outbound["transport"]["host"] = outbound["transport"]["host"][0] if outbound["transport"]["host"] else ""
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


def _check_connection(link: str, timeout: float = 1.0) -> bool:
    try:
        with SingBoxProxy(link) as proxy:
            r = proxy.get(FAST_PROBE_URL, timeout=(timeout, timeout), allow_redirects=True)
            return r.status_code in [200, 204, 301, 302]
    except Exception:
        return False


def _speed_test(link: str, timeout: float = 3.0) -> float | None:
    try:
        with SingBoxProxy(link) as proxy:
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


def _harmonic_mean(values: list) -> float:
    if not values:
        return 0.0
    return len(values) / sum(1.0 / v for v in values if v > 0)


def probe_server(link: str, category: Optional[str] = None):
    """
    ТРЁХЭТАПНОЕ ЗОНДИРОВАНИЕ СЕРВЕРА (компактный лог в 1 строку)
    Если category == 'A', выполняется двойная проверка (два полных цикла)
    """
    tag = unquote(urlparse(link).fragment) or "Unnamed"
    tag_short = tag[:35]
    
    # ЭТАП 1: Быстрая проверка соединения
    if not _check_connection(link, timeout=CONN_TIMEOUT):
        print(f"  ✗ {tag_short:<35} | соединение ✗")
        return None, 0, None
    
    # ЭТАП 2: Замеры скорости (один цикл)
    speeds = []
    outbound = None
    exit_country = None
    
    for round_num in range(PROBE_ROUNDS):
        if round_num > 0:
            time.sleep(PROBE_DELAY)
        
        mbps = _speed_test(link, timeout=READ_TIMEOUT)
        
        if mbps is None:
            print(f"  ✗ {tag_short:<35} | замер {round_num + 1}/{PROBE_ROUNDS} ✗")
            return None, 0, None
        
        speeds.append(mbps)
        
        if outbound is None:
            try:
                with SingBoxProxy(link) as proxy:
                    outbound = _fix_outbound(parse_link(proxy, link))
                    outbound["tag"] = tag
                    outbound["domain_strategy"] = "prefer_ipv4"
                    exit_country = check_exit_country(proxy)
            except Exception:
                return None, 0, None
    
    if len(speeds) >= MIN_SUCCESS_ROUNDS and outbound is not None:
        score = _harmonic_mean(speeds)
        country_mark = f" [{exit_country}]" if exit_country else ""
        speeds_str = "/".join(f"{s:.0f}" for s in speeds)
        print(f"  ✓ {tag_short:<35} | {speeds_str} = {score:.0f} Mbps{country_mark}")
        
        # Если категория A, выполняем дополнительную проверку (золотое дублирование)
        if category == CATEGORY_STABLE:
            print(f"  ⭐ {tag_short:<35} | Двойная проверка...")
            time.sleep(1)
            # Повторяем весь тест (сокращённо, только проверка соединения и 1 замер скорости)
            if _check_connection(link, timeout=CONN_TIMEOUT):
                extra_speed = _speed_test(link, timeout=READ_TIMEOUT)
                if extra_speed and extra_speed > 0:
                    # Если скорость упала более чем на 50%, считаем нестабильным
                    if extra_speed < score * 0.5:
                        print(f"  ⚠️ {tag_short:<35} | двойная проверка: скорость упала до {extra_speed:.0f} Mbps")
                        # Возвращаем меньшую скорость для более консервативной оценки
                        score = min(score, extra_speed)
                else:
                    print(f"  ⚠️ {tag_short:<35} | двойная проверка не удалась, игнорируем")
                    return None, 0, None
        
        return outbound, score, exit_country
    
    print(f"  ✗ {tag_short:<35} | недостаточно замеров")
    return None, 0, None


def quick_probe_server(outbound: dict, link: str = None) -> Optional[float]:
    tag = outbound.get('tag', 'Unknown')[:35]
    if not link:
        print(f"[⊘] {tag:<35} | пропущен (нет link)")
        return None
    mbps = _speed_test(link, timeout=READ_TIMEOUT)
    if mbps:
        print(f"[✓] {tag:<35} | {mbps:.0f} Mbps")
    else:
        print(f"[✗] {tag:<35} | не отвечает")
    return mbps


# ===========================================================================
# БЫСТРОЕ ЗОНДИРОВАНИЕ (для ретеста)
# ===========================================================================

def _quick_single_probe(link: str, timeout: int = 3) -> float | None:
    try:
        with SingBoxProxy(link) as proxy:
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


def test_servers_batch_parallel(links: List[str], group: str, rating_system: ServerRatingSystem) -> List[dict]:
    results = []
    total = len(links)
    completed = 0
    
    # Для приоритизации нужно знать категорию сервера (если он уже есть в базе)
    category_map = {}
    servers_data = rating_system.data.get("servers", {})
    for key, data in servers_data.items():
        outbound = data.get('outbound', {})
        for link in links:
            if data.get('link') == link:
                category_map[link] = data.get('category', CATEGORY_UNSTABLE)
                break
    
    def link_priority(link):
        cat = category_map.get(link, CATEGORY_UNSTABLE)
        return {'A': 0, 'B': 1, 'C': 2}.get(cat, 2)
    links_sorted = sorted(links, key=link_priority)
    
    print(f"\n  → Тестируем {total} {'старых' if group == 'RETEST' else 'новых'} серверов ({group})...")
    print("  " + "-" * 70)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_FAST) as executor:
        futures = {executor.submit(probe_server, link, category_map.get(link, None)): link for link in links_sorted}
        
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            link = futures[future]
            
            try:
                outbound, score, country = future.result(timeout=60)
                
                if outbound is not None and score > 0:
                    final_group = group
                    if group == 'EUROPE' and country == 'RU':
                        final_group = 'RUSSIA'
                    elif group == 'RUSSIA' and country and country != 'RU':
                        final_group = 'EUROPE'
                    
                    results.append({
                        'outbound': outbound, 'speed': score, 'country': country,
                        'group': final_group, 'link': link, 'tag': outbound.get('tag', 'Unknown')
                    })
            except Exception:
                pass
            
            if completed % 20 == 0 or completed == total:
                print(f"    📊 [{completed}/{total}] найдено: {len(results)}")
    
    print("  " + "-" * 70)
    return results


def _get_enabled_groups():
    enabled = set()
    for profile in PROFILES.values():
        enabled.update(set(profile.get("enabled_groups", ["EUROPE", "RUSSIA", "ALL"])))
    return enabled


def smart_server_search(all_links: List[str], rating_system: ServerRatingSystem) -> Dict[str, List[dict]]:
    enabled_groups = _get_enabled_groups()
    europe_candidates = []
    russia_candidates = []
    
    if 'EUROPE' in enabled_groups:
        europe_candidates = [l for l in all_links if not _is_russia(l)]
    if 'RUSSIA' in enabled_groups:
        russia_candidates = [l for l in all_links if _is_russia(l)]
    
    print(f"\n📊 Кандидатов для тестирования:")
    print(f"  EUROPE: {len(europe_candidates)}")
    print(f"  RUSSIA: {len(russia_candidates)}")
    
    use_fast_mode = len(europe_candidates) + len(russia_candidates) > FAST_MODE_THRESHOLD
    
    if use_fast_mode:
        max_per_group = MAX_NEW_SERVERS_TO_TEST // 2
        europe_candidates = europe_candidates[:max_per_group]
        russia_candidates = russia_candidates[:max_per_group]
        print(f"\n⚡ БЫСТРЫЙ РЕЖИМ: тестируем максимум {MAX_NEW_SERVERS_TO_TEST} серверов")
        print(f"  EUROPE: {len(europe_candidates)}")
        print(f"  RUSSIA: {len(russia_candidates)}")
    else:
        print(f"\n📋 ОБЫЧНЫЙ РЕЖИМ: тестируем все серверы")
    
    found_servers = {"EUROPE": [], "RUSSIA": []}
    
    if europe_candidates:
        print(f"\n🌍 ТЕСТИРОВАНИЕ EUROPE ({len(europe_candidates)} серверов)")
        europe_results = test_servers_batch_parallel(europe_candidates, "EUROPE", rating_system)
        for result in europe_results:
            found_servers[result['group']].append(result)
            rating_system.add_test_result(
                result['outbound'], result['speed'], result['country'], 
                result['group'], link=result['link']
            )
        print(f"\n  ✓ Найдено рабочих EUROPE: {len([r for r in europe_results if r['group'] == 'EUROPE'])}")
        print(f"  ✓ Найдено рабочих RUSSIA: {len([r for r in europe_results if r['group'] == 'RUSSIA'])}")
    
    if russia_candidates:
        print(f"\n🇷🇺 ТЕСТИРОВАНИЕ RUSSIA ({len(russia_candidates)} серверов)")
        russia_results = test_servers_batch_parallel(russia_candidates, "RUSSIA", rating_system)
        for result in russia_results:
            found_servers[result['group']].append(result)
            rating_system.add_test_result(
                result['outbound'], result['speed'], result['country'], 
                result['group'], link=result['link']
            )
        print(f"\n  ✓ Найдено рабочих RUSSIA: {len([r for r in russia_results if r['group'] == 'RUSSIA'])}")
        print(f"  ✓ Найдено рабочих EUROPE: {len([r for r in russia_results if r['group'] == 'EUROPE'])}")
    
    print(f"\n📈 ИТОГО НАЙДЕНО РАБОЧИХ:")
    print(f"  EUROPE: {len(found_servers['EUROPE'])}")
    print(f"  RUSSIA: {len(found_servers['RUSSIA'])}")
    
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
    all_raw = [dict(p) for p in groups["ALL"]]
    all_deduped = _dedup_tags(all_raw)
    n_europe = len(groups["EUROPE"])
    europe_deduped = all_deduped[:n_europe]
    russia_deduped = all_deduped[n_europe:]

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
    base = profile["github_raw_base"]
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

    outbounds = [{"type": "selector", "tag": "proxy", "outbounds": top_groups}]

    if europe_tags:
        outbounds += [
            {"type": "selector", "tag": "EUROPE", "outbounds": ["EUROPE-auto"] + europe_tags},
            {"type": "urltest", "tag": "EUROPE-auto", "outbounds": europe_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
        ]

    if russia_tags:
        outbounds += [
            {"type": "selector", "tag": "RUSSIA", "outbounds": ["RUSSIA-auto"] + russia_tags},
            {"type": "urltest", "tag": "RUSSIA-auto", "outbounds": russia_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
        ]

    if all_tags:
        outbounds += [
            {"type": "selector", "tag": "ALL", "outbounds": ["ALL-auto"] + all_tags},
            {"type": "urltest", "tag": "ALL-auto", "outbounds": all_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
        ]

    outbounds += [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}] + proxies

    config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "tls://1.1.1.1", "detour": "proxy"},
                {"tag": "local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "remote",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True}],
        "outbounds": outbounds,
        "route": {
            "rules": [r for r in [
                {"protocol": "dns", "action": "hijack-dns"},
                {"rule_set": block_routing_tags, "outbound": "block"} if block_routing_tags else None,
                {"rule_set": proxy_routing_tags, "outbound": profile["proxy_rule_outbound"]} if proxy_routing_tags else None,
            ] if r is not None],
            "rule_set": formatted_rule_sets,
            "final": profile["route_final"],
            "auto_detect_interface": True
        }
    }

    output = profile["output_file"]
    header = profile.get("file_header")
    tmp_output = output + '.tmp'
    with open(tmp_output, 'w', encoding='utf-8') as f:
        if header:
            f.write(header)
        json.dump(config, f, indent=2, ensure_ascii=False)
    os.replace(tmp_output, output)

    active = " + ".join(top_groups)
    print(f"  ✓ {output} сохранён | активные: [{active}] | EUROPE={len(europe_tags)} RUSSIA={len(russia_tags)} ALL={len(all_tags)}")


# ===========================================================================
# ОТПРАВКА УВЕДОМЛЕНИЙ В TELEGRAM
# ===========================================================================

def send_telegram_message(text: str) -> bool:
    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    if not bot_token or not chat_id:
        print("⚠️ Telegram токен или chat_id не заданы в окружении. Сообщение не отправлено.")
        return False
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }
        r = requests.post(url, data=payload, timeout=10)
        if r.status_code == 200:
            return True
        else:
            print(f"⚠️ Ошибка отправки в Telegram: {r.status_code} {r.text}")
            return False
    except Exception as e:
        print(f"⚠️ Ошибка отправки в Telegram: {e}")
        return False


def send_telegram_report(stats: dict, rating_system: ServerRatingSystem, elapsed_seconds: float, 
                         groups: dict = None, profile_names: list = None, top_servers: dict = None):
    """
    Формирует детальное сообщение о смене конфига с топ-серверами и статистикой.
    """
    # Получаем текущую дату и время
    now = datetime.now()
    date_str = now.strftime("%d.%m.%Y %H:%M")
    
    # Подсчитываем общее количество серверов в конфиге
    servers_in_config = 0
    europe_count = len(groups.get("EUROPE", [])) if groups else stats.get('europe', 0)
    russia_count = len(groups.get("RUSSIA", [])) if groups else stats.get('russia', 0)
    servers_in_config = europe_count + russia_count
    
    # Получаем топ-3 сервера по рейтингу (если переданы)
    top1 = top2 = top3 = "Нет данных"
    top1_rating = top2_rating = top3_rating = 0
    
    if top_servers:
        all_servers = []
        if top_servers.get("EUROPE"):
            all_servers.extend([(s['outbound'].get('tag', 'Unknown'), s['rating']) for s in top_servers["EUROPE"]])
        if top_servers.get("RUSSIA"):
            all_servers.extend([(s['outbound'].get('tag', 'Unknown'), s['rating']) for s in top_servers["RUSSIA"]])
        
        all_servers.sort(key=lambda x: x[1], reverse=True)
        
        if len(all_servers) >= 1:
            top1, top1_rating = all_servers[0]
        if len(all_servers) >= 2:
            top2, top2_rating = all_servers[1]
        if len(all_servers) >= 3:
            top3, top3_rating = all_servers[2]
    
    # Рассчитываем качество конфига (упрощенная метрика)
    # Используем процент активных серверов, средний рейтинг и стабильность
    active_ratio = stats.get('active', 0) / max(stats.get('total', 1), 1)
    
    # Получаем средний рейтинг активных серверов
    servers_data = rating_system.data.get("servers", {})
    active_ratings = []
    for server in servers_data.values():
        if server.get('active', False):
            active_ratings.append(server.get('rating', 0))
    
    avg_rating = sum(active_ratings) / len(active_ratings) if active_ratings else 0
    avg_stability = sum(s.get('rating_components', {}).get('stability', 0) for s in servers_data.values() if s.get('active', False)) / max(len(active_ratings), 1)
    
    # Качество конфига (0-100)
    quality_score = int((active_ratio * 0.4 + avg_rating * 0.4 + avg_stability * 0.2) * 100)
    quality_score = min(100, max(0, quality_score))
    
    # Определяем иконку качества
    if quality_score >= 80:
        quality_icon = "🟢"
        quality_text = "Отлично"
    elif quality_score >= 60:
        quality_icon = "🟡"
        quality_text = "Хорошо"
    elif quality_score >= 40:
        quality_icon = "🟠"
        quality_text = "Удовлетворительно"
    else:
        quality_icon = "🔴"
        quality_text = "Плохо"
    
    # Формируем список профилей
    profiles_str = ", ".join(profile_names) if profile_names else "srs, hiddify"
    
    # Ссылка на скачивание конфига (если используется GitHub Actions)
    github_repo = os.environ.get('GITHUB_REPOSITORY', '')
    github_run_id = os.environ.get('GITHUB_RUN_ID', '')
    
    download_url = f"https://github.com/{github_repo}/actions/runs/{github_run_id}" if github_repo and github_run_id else ""
    
    # Основное сообщение
    message = (
        f"🔄 <b>КОНФИГ ОБНОВЛЕН</b> 🔄\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📅 <b>Время:</b> {date_str}\n"
        f"📁 <b>Профили:</b> {profiles_str}\n"
        f"📦 <b>Серверов в конфиге:</b> {servers_in_config}\n"
        f"   🌍 EUROPE: {europe_count} | 🇷🇺 RUSSIA: {russia_count}\n"
        f"\n"
        f"🏆 <b>Топ-3 по качеству:</b>\n"
        f"   {top1[:35]} — {top1_rating:.2f}\n"
        f"   {top2[:35]} — {top2_rating:.2f}\n"
        f"   {top3[:35]} — {top3_rating:.2f}\n"
        f"\n"
        f"<b>Качество конфига:</b> {quality_icon} {quality_score} / 100 ({quality_text})\n"
        f"   Активные серверы: {stats.get('active', 0)}/{stats.get('total', 0)} ({int(active_ratio*100)}%)\n"
        f"   Средний рейтинг: {avg_rating:.3f}\n"
        f"   Стабильность: {avg_stability*100:.1f}%\n"
        f"\n"
        f"⏱️ <b>Время выполнения:</b> {elapsed_seconds:.1f} сек.\n"
    )
    
    # Добавляем ссылку на скачивание, если доступна
    if download_url:
        message += f"\n🔗 <a href=\"{download_url}\">Детали в GitHub Actions</a>\n"
    
    # Добавляем информацию о категориях серверов
    categories = stats.get('categories', {'A': 0, 'B': 0, 'C': 0})
    message += (
        f"\n📈 <b>Распределение по категориям:</b>\n"
        f"   🟢 Стабильные (A): {categories.get('A', 0)}\n"
        f"   🟡 Средние (B): {categories.get('B', 0)}\n"
        f"   🔴 Нестабильные (C): {categories.get('C', 0)}\n"
    )
    
    # Отправляем сообщение
    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    
    if not bot_token or not chat_id:
        print("⚠️ Telegram токен или chat_id не заданы в окружении. Сообщение не отправлено.")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }
        r = requests.post(url, data=payload, timeout=10)
        if r.status_code == 200:
            print("✅ Отчет отправлен в Telegram")
            return True
        else:
            print(f"⚠️ Ошибка отправки в Telegram: {r.status_code} {r.text}")
            return False
    except Exception as e:
        print(f"⚠️ Ошибка отправки в Telegram: {e}")
        return False

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
    start_time = time.time()
    print("="*80)
    print("🎯 СИСТЕМА РЕЙТИНГА СЕРВЕРОВ (ТРЁХЭТАПНЫЙ ПОИСК + КАТЕГОРИИ)")
    print("="*80)
    
    _load_mass_failure_state()
    rating_system = ServerRatingSystem()
    
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
    
    print("\n" + "="*80)
    print("🔄 ВЫБОР СЕРВЕРОВ ДЛЯ РЕТЕСТА")
    print("="*80)
    
    europe_retest = rating_system.get_servers_for_retest(group='EUROPE', count=RETEST_OLD_SERVERS_COUNT)
    russia_retest = rating_system.get_servers_for_retest(group='RUSSIA', count=RETEST_OLD_SERVERS_COUNT)
    print(f"Ретест: EUROPE={len(europe_retest)}, RUSSIA={len(russia_retest)}")
    
    print("\n" + "="*80)
    print("🧠 УМНЫЙ ПОИСК НОВЫХ СЕРВЕРОВ (3 ЭТАПА)")
    print("="*80)
    
    found_servers = smart_server_search(all_links, rating_system)
    
    # Проверка на массовые падения
    all_results = []
    for grp in found_servers:
        for res in found_servers[grp]:
            all_results.append({'status': 'alive' if res['speed'] > 0 else 'dead'})
    if rating_system._check_mass_failure(all_results):
        print("⚠️ Режим защиты активен, используем предыдущий стабильный конфиг")
        stats = rating_system.get_statistics()
        send_telegram_report(stats, rating_system, time.time() - start_time)
        return
    
    if europe_retest or russia_retest:
        print("\n" + "="*80)
        print("🔄 РЕТЕСТ СТАРЫХ СЕРВЕРОВ")
        print("="*80)
        
        old_servers_to_test = []
        for server_info in europe_retest + russia_retest:
            outbound = server_info['outbound']
            link = server_info.get('link')
            group = server_info['group']
            if link:
                old_servers_to_test.append({
                    'outbound': outbound, 'link': link, 'group': group, 
                    'tag': outbound.get('tag', 'Unknown'),
                    'category': server_info.get('category', CATEGORY_UNSTABLE)
                })
        
        if old_servers_to_test:
            print(f"  → Ретестируем {len(old_servers_to_test)} старых серверов...")
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
                            server['outbound'], speed, None, server['group'], link=server['link']
                        )
                        if speed:
                            print(f"    ✓ {server['tag'][:35]} | {speed:.0f} Mbps")
                        else:
                            print(f"    ✗ {server['tag'][:35]} | не отвечает")
                    except Exception as e:
                        print(f"    ⚠️ {server['tag'][:35]} | ошибка: {str(e)[:30]}")
                        
    rating_system.cleanup()
    
    print("\n" + "="*80)
    print("⚙️  ПЕРЕСЧЁТ РЕЙТИНГОВ")
    print("="*80)
    rating_system.recalculate_all_ratings()
    rating_system.print_stats()
    
    print("\n" + "="*80)
    print("📋 ФОРМИРОВАНИЕ КОНФИГА")
    print("="*80)
    
    current_hour = (datetime.now().hour + TZ_OFFSET) % 24
    europe_servers = rating_system.get_top_servers(group='EUROPE', limit=MAX_SERVERS_IN_CONFIG, min_rating=MIN_RATING_THRESHOLD, current_hour=current_hour)
    russia_servers = rating_system.get_top_servers(group='RUSSIA', limit=MAX_SERVERS_IN_CONFIG, min_rating=MIN_RATING_THRESHOLD, current_hour=current_hour)
    
    print(f"\nОтобрано для конфига (текущий час {current_hour}): EUROPE={len(europe_servers)}, RUSSIA={len(russia_servers)}")
    
    if not europe_servers and not russia_servers:
        print("\n❌ Критическая ошибка: нет серверов с достаточным рейтингом!")
        send_telegram_message("🚨 <b>КРИТИЧЕСКАЯ ОШИБКА:</b> Нет серверов с достаточным рейтингом для формирования конфига!")
        return
    
    print("\n🏆 ТОП-10 СЕРВЕРОВ ПО РЕЙТИНГУ (с категориями):")
    for group_name, servers in [("EUROPE", europe_servers), ("RUSSIA", russia_servers)]:
        if not servers:
            continue
        print(f"\n{group_name}:")
        for i, server in enumerate(servers[:10], 1):
            tag = server['outbound'].get('tag', 'Unknown')[:35]
            rating = server['rating']
            comp = server['components']
            cat = server.get('category', '?')
            country = f"[{server['country']}]" if server.get('country') else ""
            print(f"  {i:2}. {tag:<35} [{cat}] R={rating:.3f} {country}")
            print(f"      sp={comp.get('speed', 0):.2f} st={comp.get('stability', 0):.2f} up={comp.get('uptime', 0):.2f}")
    
    groups = {
        "EUROPE": [s['outbound'] for s in europe_servers],
        "RUSSIA": [s['outbound'] for s in russia_servers],
        "ALL": [s['outbound'] for s in europe_servers] + [s['outbound'] for s in russia_servers],
    }

    # Сохраняем топ-серверы для отчета
    top_servers_for_report = {
        "EUROPE": europe_servers[:10],  # топ-10 для отчета
        "RUSSIA": russia_servers[:10]
    }
    
    print("\n" + "="*80)
    print("💾 ЗАПИСЬ КОНФИГОВ")
    print("="*80)
    
    for name in profile_names:
        print(f"\n[{name}]")
        write_config(PROFILES[name], groups)
    
    elapsed = time.time() - start_time
    print(f"\n✅ Обновление завершено успешно! Время выполнения: {elapsed:.1f} сек.")
    
    stats = rating_system.get_statistics()
        # Получаем статистику и отправляем улучшенный отчет
    stats = rating_system.get_statistics()
    send_telegram_report(
        stats=stats,
        rating_system=rating_system,
        elapsed_seconds=elapsed,
        groups=groups,
        profile_names=profile_names,
        top_servers=top_servers_for_report
    )


if __name__ == "__main__":
    requested = sys.argv[1:] if len(sys.argv) > 1 else list(PROFILES.keys())
    unknown = [n for n in requested if n not in PROFILES]
    if unknown:
        print(f"Неизвестные профили: {unknown}")
        print(f"Доступные: {list(PROFILES.keys())}")
        sys.exit(1)
    main(requested)
