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
        # Балансеры, которые попадут в конфиг.
        # Убери любой элемент из списка чтобы отключить соответствующую группу.
        # Допустимые значения: "EUROPE", "RUSSIA", "ALL"
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
        # Hiddify: Russia-серверы и ALL отключены — только зарубежные
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
    #'https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist',
    #'https://whiteprime.github.io/xraycheck/configs/white-list_available(top100)',
    'https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt'
]
CIDR_WHITELIST_FILE = 'cidr_whitelist2.txt'

REGEXP_RUSSIA  = r'(?:\bRussia\b|\bRU\b|🇷🇺)'   # тег считается "российским"

COUNTRY_API_URL = 'https://api.country.is/'
COUNTRY_CHECK_TIMEOUT = 3

MIN_SERVERS    = 5
MIN_BEST_SPEED = 1.5
MAX_WORKERS    = 64   # увеличено: зонды тратят время на паузы, потоков нужно больше

# --- Параметры зондирования ---
PROBE_ROUNDS = 3     # количество замеров на сервер
PROBE_DELAY  = 60    # секунд между замерами
PROBE_URL    = 'https://cachefly.cachefly.net/10mb.test'
TIMEOUT      = 8     # секунд на один замер

# --- Параметры отбора ---
#
# MIN_SUCCESS_ROUNDS  — жёсткий порог: сервер должен ответить хотя бы в этом
#                       количестве раундов, иначе отсеивается до скоринга.
#                       Рекомендуется ceil(PROBE_ROUNDS / 2), т.е. большинство.
#
# SCORE_FLOOR_RATIO   — мягкий порог относительно лучшего сервера в группе:
#                       проходят серверы с score >= best_score * SCORE_FLOOR_RATIO.
#                       0.25 = отбрасываем только тех, кто хуже лучшего в 4+ раза.
#                       Меньше -> шире пул, больше -> строже.
#
# MIN_KEEP_PER_GROUP  — гарантированный минимум серверов в группе.
#                       Если после SCORE_FLOOR_RATIO осталось меньше — порог
#                       смягчается и берутся лучшие MIN_KEEP_PER_GROUP.
#
MIN_SUCCESS_ROUNDS  = 2     # из PROBE_ROUNDS=3 нужно пройти минимум 2
SCORE_FLOOR_RATIO   = 0.25  # отсекаем тех, кто хуже лучшего более чем в 4 раза
MIN_KEEP_PER_GROUP  = 5     # минимум серверов в каждой группе


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
        "sni":           ["domain_whitelist.txt"],
        "port":          [],
        "obfs":          [],
        "obfs_password": [],
    },
}


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
# ФИЛЬТР ПО ПАРАМЕТРАМ — реализация
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
# ЗОНДИРОВАНИЕ С ПАУЗАМИ
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
    """
    Определяет страну выхода через уже открытую прокси-сессию.
    Возвращает код страны (например, 'RU', 'NL') или None при ошибке.
    """
    try:
        response = proxy_session.get(COUNTRY_API_URL, timeout=COUNTRY_CHECK_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', '').upper()
    except Exception:
        pass
    return None


def _single_probe(link: str) -> float | None:
    """Один замер скорости. Возвращает Mbps или None при ошибке."""
    try:
        with SingBoxProxy(link) as proxy:
            start = time.perf_counter()
            r = proxy.get(PROBE_URL, timeout=TIMEOUT, stream=True)
            if r.status_code == 200:
                total = sum(len(c) for c in r.iter_content(chunk_size=8192) if c)
                duration = time.perf_counter() - start
                if duration > 0 and total > 0:
                    return (total * 8) / (duration * 1_000_000)
    except Exception:
        pass
    return None


def _harmonic_mean(values: list) -> float:
    """
    Гармоническое среднее скоростей.

    Почему не медиана и не среднее арифметическое:
    - Среднее арифм. завышает оценку серверов с одним случайным всплеском.
    - Медиана игнорирует реальный разброс.
    - Гармоническое среднее даёт низкий результат при одном медленном замере,
      т.е. штрафует нестабильность — именно то, что нужно для VPN-серверов.
    """
    if not values:
        return 0.0
    return len(values) / sum(1.0 / v for v in values if v > 0)


def probe_server(link: str):
    """
    Зондирует сервер PROBE_ROUNDS раз с паузой PROBE_DELAY секунд между замерами.
    Дополнительно определяет страну выхода через API.

    Жёсткий фильтр: сервер должен ответить минимум MIN_SUCCESS_ROUNDS раз,
    иначе возвращает (None, 0, None) — до стадии скоринга не доходит.

    score = harmonic_mean(speeds)
      Гармоническое среднее штрафует нестабильность сильнее медианы:
      сервер с замерами [100, 100, 1] получит score ≈ 2.9, а не 100.
    
    Возвращает: (outbound, score, country_code)
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
            if outbound is None:
                try:
                    with SingBoxProxy(link) as proxy:
                        outbound = _fix_outbound(parse_link(proxy, link))
                        outbound["tag"] = tag
                        outbound["domain_strategy"] = "prefer_ipv4"
                        
                        # Проверяем страну выхода через уже открытое соединение
                        if exit_country is None:
                            exit_country = check_exit_country(proxy)
                except Exception:
                    pass

    # Жёсткий порог по количеству успешных раундов
    if len(speeds) < MIN_SUCCESS_ROUNDS or outbound is None:
        tag_short = tag[:48]
        stability = "".join("✓" if i < len(speeds) else "✗" for i in range(PROBE_ROUNDS))
        print(f"[{stability}] {tag_short:<48}  — отсеян (< {MIN_SUCCESS_ROUNDS} успешных раундов)")
        return None, 0, None

    score = _harmonic_mean(speeds)

    stability = "".join("✓" if i < len(speeds) else "✗" for i in range(PROBE_ROUNDS))
    country_mark = f" [{exit_country}]" if exit_country else ""
    print(f"[{stability}] {tag[:48]:<48} "
          f"hmean={score:.1f} Mbps  rounds={len(speeds)}/{PROBE_ROUNDS}{country_mark}")
    return outbound, score, exit_country


def run_probes_grouped(groups: dict) -> dict:
    """
    Зондирует несколько групп серверов в ОДНОМ общем пуле потоков.

    groups = {"EUROPE": [...links], "RUSSIA": [...links], ...}
    Возвращает {"EUROPE": [(outbound, score, country), ...], "RUSSIA": [...], ...}

    Ключевое ускорение: вместо последовательного запуска отдельного пула
    на каждую группу все серверы (EUROPE + RUSSIA) попадают в один
    ThreadPoolExecutor. Потоки заняты sleep(PROBE_DELAY) большую часть
    времени, поэтому общий wall-time = max(time_europe, time_russia)
    вместо time_europe + time_russia.
    """
    total_links = sum(len(v) for v in groups.values())
    total_minutes = (PROBE_ROUNDS - 1) * PROBE_DELAY / 60
    print(f"\nЗондирование: {total_links} серверов суммарно "
          f"({', '.join(f'{k}={len(v)}' for k, v in groups.items())})")
    print(f"Схема: {PROBE_ROUNDS} раунда x пауза {PROBE_DELAY}с "
          f"= окно наблюдения ~{total_minutes:.0f} мин, "
          f"потоков: {MAX_WORKERS} (общий пул)\n")

    # Помечаем каждую ссылку её группой
    labelled = [
        (label, link)
        for label, links in groups.items()
        for link in links
    ]

    per_group = {label: [] for label in groups}

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(probe_server, link): label
                   for label, link in labelled}
        for future in concurrent.futures.as_completed(futures):
            label = futures[future]
            ob, score, country = future.result()
            if ob:
                per_group[label].append((ob, score, country))

    for label in per_group:
        per_group[label].sort(key=lambda x: x[1], reverse=True)

    return per_group


def filter_by_score(results: list, label: str = "") -> list:
    """
    Отбор серверов по score относительно лучшего в группе.
    results = [(outbound, score, country), ...]

    Алгоритм:
    1. Порог = best_score * SCORE_FLOOR_RATIO  (относительный, не по среднему).
       Это удерживает серверы, уступающие лучшему не более чем в 1/RATIO раз.
    2. Если после шага 1 осталось меньше MIN_KEEP_PER_GROUP — берём топ-N
       принудительно, чтобы группа не оказалась пустой.

    В отличие от порога >= среднего:
    - Не срезает половину пула механически.
    - Реагирует на реальное распределение скоростей.
    - Гарантирует минимальное число серверов в группе.
    """
    if not results:
        return []

    prefix = f"[{label}] " if label else ""
    best_score = results[0][1]  # results уже отсортированы по убыванию
    floor = best_score * SCORE_FLOOR_RATIO

    filtered = [(ob, s, c) for ob, s, c in results if s >= floor]

    # Гарантируем минимум серверов
    if len(filtered) < MIN_KEEP_PER_GROUP and len(results) >= MIN_KEEP_PER_GROUP:
        filtered = results[:MIN_KEEP_PER_GROUP]
        print(f"{prefix}Порог смягчён: взяты топ-{MIN_KEEP_PER_GROUP} "
              f"(floor {floor:.2f} дал только {len(filtered)} серверов)")
    elif len(filtered) < MIN_KEEP_PER_GROUP:
        filtered = results  # серверов вообще мало — берём всех
        print(f"{prefix}Серверов мало ({len(results)}), берём всех")

    print(f"{prefix}Порог: best={best_score:.2f}  "
          f"floor={floor:.2f} (×{SCORE_FLOOR_RATIO})  "
          f"отобрано {len(filtered)}/{len(results)}"
          + (f"  (отброшено {len(results) - len(filtered)})" if len(results) > len(filtered) else ""))
    print()
    return filtered


def needs_fallback(results: list) -> bool:
    if len(results) < MIN_SERVERS:
        print(f"\n⚠ Прошло только {len(results)} серверов (минимум: {MIN_SERVERS}). Фоллбэк...")
        return True
    if results and results[0][1] < MIN_BEST_SPEED:
        print(f"\n⚠ Лучший score {results[0][1]:.2f} < {MIN_BEST_SPEED}. Фоллбэк...")
        return True
    return False


# ===========================================================================
# ЗАПИСЬ КОНФИГА ДЛЯ ОДНОГО ПРОФИЛЯ
# ===========================================================================

def _dedup_tags(proxies: list) -> list:
    """Создаёт копии outbound'ов с уникальными тегами (добавляет -2, -3, …)."""
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
    """
    groups = {
        "EUROPE": [outbound, ...],   # серверы без Russia-тега
        "RUSSIA": [outbound, ...],   # серверы с Russia-тегом
        "ALL":    [outbound, ...],   # EUROPE + RUSSIA (порядок сохранён)
    }

    Какие балансеры попадут в конфиг — задаётся полем profile["enabled_groups"].
    Например ["EUROPE", "ALL"] — RUSSIA-группа не добавляется.
    Допустимые значения: "EUROPE", "RUSSIA", "ALL".
    """
    # ── дедублирование тегов по общему пулу ──────────────────────────────
    # ALL = EUROPE + RUSSIA — восстанавливаем срезы после дедупа
    all_raw     = [dict(p) for p in groups["ALL"]]
    all_deduped = _dedup_tags(all_raw)
    n_europe         = len(groups["EUROPE"])
    europe_deduped   = all_deduped[:n_europe]
    russia_deduped   = all_deduped[n_europe:]

    europe_tags = [p["tag"] for p in europe_deduped]
    russia_tags = [p["tag"] for p in russia_deduped]

    # ── применяем enabled_groups ──────────────────────────────────────────
    enabled = set(profile.get("enabled_groups", ["EUROPE", "RUSSIA", "ALL"]))

    if "EUROPE" not in enabled:
        europe_deduped, europe_tags = [], []
    if "RUSSIA" not in enabled:
        russia_deduped, russia_tags = [], []

    # ALL строится из оставшихся групп; если "ALL" отключён — тоже пуст
    all_tags = (europe_tags + russia_tags) if "ALL" in enabled else []

    # Итоговый пул физических outbound'ов (без дублей между группами)
    proxies = europe_deduped + russia_deduped

    # ── верхний selector «proxy»: только непустые и включённые группы ────
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

    # ── строим список outbounds ───────────────────────────────────────────
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
          f"EUROPE={len(europe_tags)}  RUSSIA={len(russia_tags)}  ALL={len(all_tags)}  "
          f"proxy-правил={len(proxy_routing_tags)}  block-правил={len(block_routing_tags)}")


# ===========================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ===========================================================================

def _is_russia(link: str, country: str | None = None) -> bool:
    """
    Определяет, является ли сервер российским.
    
    1. Проверка по regex в теге (быстрая)
    2. Проверка по коду страны из API (если передан)
    """
    tag = unquote(urlparse(link).fragment)
    
    # Проверка по regex
    if re.search(REGEXP_RUSSIA, tag):
        return True
    
    # Проверка по коду страны
    if country == 'RU':
        return True
    
    return False


def _print_top(results: list, label: str, n: int = 10):
    print(f"\nТоп-{n} [{label}] по score:")
    for i, (ob, sc, country) in enumerate(results[:n], 1):
        country_mark = f" [{country}]" if country else ""
        print(f"  {i:>2}. {ob['tag'][:55]:<55} score={sc:.2f}{country_mark}")
    if len(results) > n:
        print(f"  ... и ещё {len(results) - n} серверов")


def main(profile_names: list):
    # 1. Загрузка подписок
    all_links = fetch_links_from_subscriptions()
    if not all_links:
        print("Критическая ошибка: не удалось загрузить ни одной ссылки!")
        return

    # 2. Фильтр по параметрам протокола
    all_links = filter_by_params(all_links)

    # 3. CIDR-фильтрация
    all_links = filter_by_cidr(all_links)
    if not all_links:
        print("⚠ После CIDR-фильтрации серверов не осталось!")
        return

    # 4. Разделяем на EUROPE и RUSSIA до тестирования (только по regex)
    europe_links = [l for l in all_links if not _is_russia(l)]
    russia_links = [l for l in all_links if     _is_russia(l)]
    print(f"Разделение (по regex): EUROPE={len(europe_links)}, RUSSIA={len(russia_links)}\n")

    # 5. Тестируем обе группы в одном общем пуле (параллельно, не последовательно)
    probe_input = {}
    if europe_links:
        probe_input["EUROPE"] = europe_links
    if russia_links:
        probe_input["RUSSIA"] = russia_links

    probe_output = run_probes_grouped(probe_input)
    
    # НОВОЕ: дополнительная классификация по стране выхода
    # Серверы без Russia-тега, но с RU выходом переносим в RUSSIA
    europe_results = probe_output.get("EUROPE", [])
    russia_results = probe_output.get("RUSSIA", [])
    
    # Перераспределяем EUROPE-серверы с RU выходом
    reclassified_to_russia = []
    final_europe = []
    for ob, score, country in europe_results:
        if country == 'RU':
            reclassified_to_russia.append((ob, score, country))
        else:
            final_europe.append((ob, score, country))
    
    if reclassified_to_russia:
        print(f"\n⚠ Переклассифицировано в RUSSIA: {len(reclassified_to_russia)} серверов с RU выходом")
        russia_results.extend(reclassified_to_russia)
        russia_results.sort(key=lambda x: x[1], reverse=True)
    
    europe_results = final_europe

    # 6. Адаптивный отбор внутри каждой группы отдельно
    europe_top = filter_by_score(europe_results, "EUROPE")
    russia_top = filter_by_score(russia_results, "RUSSIA")

    # 7. Итоговая статистика
    print(f"Результаты тестирования:")
    print(f"  EUROPE : прошло зонды {len(europe_results)}, отобрано {len(europe_top)}")
    print(f"  RUSSIA : прошло зонды {len(russia_results)}, отобрано {len(russia_top)}")
    print(f"  ALL    : {len(europe_top) + len(russia_top)} серверов суммарно")

    if needs_fallback(europe_top):
        print("⚠ EUROPE маловато серверов — рекомендуем использовать группу ALL.")

    if europe_top:
        _print_top(europe_top, "EUROPE")
    if russia_top:
        _print_top(russia_top, "RUSSIA")

    if not europe_top and not russia_top:
        print("Критическая ошибка: ни один сервер не прошел проверку!")
        return

    # 8. Формируем группы: ALL = EUROPE + RUSSIA (порядок важен для write_config)
    groups = {
        "EUROPE": [ob for ob, _, _ in europe_top],
        "RUSSIA": [ob for ob, _, _ in russia_top],
        "ALL":    [ob for ob, _, _ in europe_top] + [ob for ob, _, _ in russia_top],
    }

    # 9. Запись конфигов
    print(f"\n{'='*60}")
    print(f"Запись конфигов для профилей: {', '.join(profile_names)}")
    print(f"{'='*60}")
    for name in profile_names:
        print(f"\n[{name}]")
        write_config(PROFILES[name], groups)

    print("\nГотово.")


if __name__ == "__main__":
    requested = sys.argv[1:] if len(sys.argv) > 1 else list(PROFILES.keys())
    unknown = [n for n in requested if n not in PROFILES]
    if unknown:
        print(f"Неизвестные профили: {unknown}")
        print(f"Доступные: {list(PROFILES.keys())}")
        sys.exit(1)
    main(requested)
