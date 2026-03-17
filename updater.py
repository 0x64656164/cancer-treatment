import requests
import re
import json
import os
import time
import ipaddress
import socket
import concurrent.futures
from urllib.parse import urlparse, unquote
from base import SingBoxProxy

# --- НАСТРОЙКИ ---
SUB_LINKS = [
    'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt',
    'https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt'
    # 'https://example.com/sub2.txt',
    # 'https://example.com/sub3.txt',
]
CIDR_WHITELIST_FILE = 'cidrwhitelist.txt'

REGEXP_FILTER = r'^(?!.*?\b(Russia|RU|🇷🇺)\b).*$'

REGEXP_FILTER_FALLBACK = r'.*'   # то же, но без исключения Russia, пока так, потом уберу совсем
GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656464/cancer-treatment/refs/heads/main/ruleset/srs/'

TOP_COUNT = 50          # Берём только топ-50 по скорости
MIN_SERVERS = 5         # Минимум серверов, прошедших проверку
MIN_BEST_SPEED = 1.5    # Минимальная скорость лучшего сервера (Mbps)
MAX_WORKERS = 8
SPEED_TEST_URL = 'https://cachefly.cachefly.net/1mb.test'
TIMEOUT = 5             # Максимум 5 секунд на ожидание и загрузку 1МБ

# Псевдо-скорость для hysteria2 серверов (не тестируются, но включаются в пул)
HY2_PSEUDO_SPEED = 50.0

REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]
REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]


# ---------------------------------------------------------------------------
# CIDR-фильтр: загружается один раз при старте
# ---------------------------------------------------------------------------

def load_cidr_whitelist(path: str) -> list:
    """Читает файл с CIDR-подсетями (по одной на строку), возвращает список сетей."""
    if not os.path.exists(path):
        print(f"⚠ Файл {path} не найден — CIDR-фильтр отключён, все серверы пройдут дальше.")
        return []

    networks = []
    errors = 0
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


# Глобальный список сетей — инициализируется один раз при старте
CIDR_NETWORKS = load_cidr_whitelist(CIDR_WHITELIST_FILE)

# Кэш DNS-резолюции, чтобы не резолвить один хост дважды
_dns_cache: dict = {}


def _resolve(host: str):
    """Резолвит хост в IP, кэширует результат. Возвращает None при ошибке."""
    if host not in _dns_cache:
        try:
            _dns_cache[host] = socket.gethostbyname(host)
        except Exception:
            _dns_cache[host] = None
    return _dns_cache[host]


def is_in_cidr_whitelist(host: str) -> bool:
    """
    Проверяет, попадает ли IP-адрес хоста в один из разрешённых CIDR.
    Если список сетей пуст (файл не найден) — пропускает всё.
    """
    if not CIDR_NETWORKS:
        return True

    ip_str = _resolve(host)
    if ip_str is None:
        return False  # не резолвится — отсеиваем

    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in CIDR_NETWORKS)
    except ValueError:
        return False


def extract_host_from_link(link: str) -> str:
    """Извлекает хост (адрес сервера) из ссылки."""
    return urlparse(link).hostname or ""


def filter_by_cidr(links: list) -> list:
    """
    Фильтрует список ссылок, оставляя только те,
    чей сервер попадает в CIDR-whitelist.
    DNS-резолюция идёт параллельно для скорости.
    """
    if not CIDR_NETWORKS:
        return links

    print(f"CIDR-фильтрация: проверяем {len(links)} серверов...")

    # Параллельная резолюция — заполняем кэш заранее
    hosts = list({extract_host_from_link(l) for l in links if extract_host_from_link(l)})
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS * 2) as ex:
        ex.map(_resolve, hosts)

    passed = [l for l in links if is_in_cidr_whitelist(extract_host_from_link(l))]
    print(f"CIDR-фильтр: прошло {len(passed)} из {len(links)} серверов\n")
    return passed


# ---------------------------------------------------------------------------
# Загрузка подписок
# ---------------------------------------------------------------------------

def fetch_links_from_subscriptions() -> list:
    """Загружает все ссылки со всех подписок, дедуплицирует."""
    all_links = []
    seen = set()

    for url in SUB_LINKS:
        print(f"Загрузка подписки: {url}")
        try:
            raw = requests.get(url, timeout=15).text
            # Исправлено: добавлен hysteria2 в паттерн
            found = re.findall(r'^(?:vless|vmess|trojan|hy2|hysteria2):\/\/.+$', raw, re.MULTILINE)
            new_count = 0
            for link in found:
                if link not in seen:
                    seen.add(link)
                    all_links.append(link)
                    new_count += 1
            print(f"  → Найдено: {len(found)}, новых (уникальных): {new_count}")
        except Exception as e:
            print(f"  ✗ Ошибка загрузки {url}: {e}")

    print(f"\nИтого уникальных серверов со всех подписок: {len(all_links)}\n")
    return all_links


# ---------------------------------------------------------------------------
# Speed-тест
# ---------------------------------------------------------------------------

def parse_link(proxy, link):
    """Выбирает правильный парсер в зависимости от протокола ссылки."""
    if link.startswith("vmess://"):
        return proxy._parse_vmess_link(link)
    elif link.startswith("vless://"):
        return proxy._parse_vless_link(link)
    elif link.startswith("trojan://"):
        return proxy._parse_trojan_link(link)
    elif link.startswith(("hy2://", "hysteria2://")):
        return proxy._parse_hysteria2_link(link)
    else:
        raise ValueError(f"Неизвестный протокол: {link[:20]}")


def measure_throughput(link):
    tag = unquote(urlparse(link).fragment) or "Unnamed"

    # hysteria2 — не тестируем скорость, только парсим конфиг
    if link.startswith(("hy2://", "hysteria2://")):
        try:
            proxy = SingBoxProxy(link, config_only=True)
            outbound = proxy._parse_hysteria2_link(link)
            outbound["tag"] = tag
            outbound["domain_strategy"] = "prefer_ipv4"
            print(f"[SKIP SPEED] {tag}: hysteria2 ({HY2_PSEUDO_SPEED} Mbps pseudo)")
            return outbound, HY2_PSEUDO_SPEED
        except Exception as e:
            print(f"[FAIL] {tag}: hysteria2 parse error: {e}")
            return None, 0

    try:
        with SingBoxProxy(link) as proxy:
            start_time = time.perf_counter()
            response = proxy.get(SPEED_TEST_URL, timeout=TIMEOUT, stream=True)

            if response.status_code == 200:
                total_content = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        total_content += len(chunk)

                duration = time.perf_counter() - start_time

                if duration > 0 and total_content > 0:
                    mbps = (total_content * 8) / (duration * 1_000_000)

                    outbound = parse_link(proxy, link)
                    outbound["tag"] = tag
                    outbound["domain_strategy"] = "prefer_ipv4"

                    if "transport" in outbound and outbound["transport"].get("type") == "xhttp":
                        outbound["transport"]["type"] = "httpupgrade"
                        if isinstance(outbound["transport"].get("host"), list):
                            outbound["transport"]["host"] = (
                                outbound["transport"]["host"][0]
                                if outbound["transport"]["host"] else ""
                            )

                    print(f"[GOOD] {tag}: {mbps:.2f} Mbps")
                    return outbound, mbps
    except Exception:
        pass

    return None, 0


def run_speed_test(links, label):
    """Прогоняет список ссылок через speed test, возвращает отсортированные результаты."""
    print(f"Начинаем стресс-тест для {len(links)} серверов ({label})...")
    print(f"Параметры: топ-{TOP_COUNT} по скорости\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(measure_throughput, l): l for l in links}
        for future in concurrent.futures.as_completed(future_to_link):
            outbound, speed = future.result()
            if outbound:
                results.append((outbound, speed))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def needs_fallback(results):
    """Проверяет, нужен ли фоллбэк по результатам теста."""
    if len(results) < MIN_SERVERS:
        print(f"\n⚠ Прошло проверку только {len(results)} серверов (минимум: {MIN_SERVERS}). "
              f"Запускаем фоллбэк без фильтра Russia...")
        return True
    best_speed = results[0][1]
    if best_speed < MIN_BEST_SPEED:
        print(f"\n⚠ Лучший сервер показал {best_speed:.2f} Mbps (минимум: {MIN_BEST_SPEED} Mbps). "
              f"Запускаем фоллбэк без фильтра Russia...")
        return True
    return False


# ---------------------------------------------------------------------------
# Основная функция
# ---------------------------------------------------------------------------

def generate_final_config():
    # 1. Загрузка всех ссылок со всех подписок
    links = fetch_links_from_subscriptions()
    if not links:
        print("Критическая ошибка: Не удалось загрузить ни одной ссылки!")
        return

    # 2. CIDR-фильтрация по адресу сервера
    links = filter_by_cidr(links)
    if not links:
        print("Критическая ошибка: После CIDR-фильтрации не осталось серверов!")
        return

    # 3. Первый проход: основной фильтр по тегу (без Russia)
    filtered = [l for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
    results = run_speed_test(filtered, "основной фильтр, без Russia")

    # 4. Фоллбэк: повтор с разрешением Russia
    if needs_fallback(results):
        filtered_fallback = [l for l in links if re.match(REGEXP_FILTER_FALLBACK, unquote(urlparse(l).fragment))]
        already_tested = set(filtered)
        new_links = [l for l in filtered_fallback if l not in already_tested]

        if new_links:
            fallback_results = run_speed_test(new_links, "фоллбэк, включая Russia")
            results = sorted(results + fallback_results, key=lambda x: x[1], reverse=True)
        else:
            print("Фоллбэк: новых ссылок для теста не найдено.")

    if not results:
        print("Критическая ошибка: Ни один сервер не прошел проверку!")
        return

    top_results = results[:TOP_COUNT]
    final_proxies = [r[0] for r in top_results]
    proxy_tags = [p["tag"] for p in final_proxies]

    print(f"\nТест окончен. Всего прошли проверку: {len(results)}, "
          f"отобрано в топ-{TOP_COUNT}: {len(final_proxies)} серверов.")
    print("\nТоп-10 по скорости:")
    for i, (ob, spd) in enumerate(top_results[:10], 1):
        print(f"  {i:>2}. {ob['tag'][:55]:<55} {spd:6.2f} Mbps")

    # Уникализация тегов
    seen_tags = {}
    for pb in final_proxies:
        t = pb["tag"]
        if t in seen_tags:
            seen_tags[t] += 1
            pb["tag"] = f"{t}-{seen_tags[t]}"
        else:
            seen_tags[t] = 0

    # Сборка структуры Rule Sets
    formatted_rule_sets = []
    proxy_routing_tags = []
    block_routing_tags = []
    rule_tags = set()

    def add_rule(tag, url, is_block):
        if tag in rule_tags:
            return
        formatted_rule_sets.append({
            "type": "remote", "tag": tag, "format": "binary", "url": url,
            "download_detour": "direct" if is_block else "proxy"
        })
        if is_block:
            block_routing_tags.append(tag)
        else:
            proxy_routing_tags.append(tag)
        rule_tags.add(tag)

    if os.path.exists('ruleset/srs/'):
        for folder, is_block in [('ruleset/srs/', False), ('ruleset/srs/block/', True)]:
            if not os.path.exists(folder):
                continue
            for file in os.listdir(folder):
                if file.endswith('.srs'):
                    tag = file.replace('.srs', '')
                    url = f"{GITHUB_RAW_BASE}{'block/' if is_block else ''}{file}"
                    add_rule(tag, url, is_block)

    for url in REMOTE_BLOCK_RULE_SETS:
        add_rule(url.split('/')[-1].replace('.srs', ''), url, True)
    for url in REMOTE_RULE_SETS:
        add_rule(url.split('/')[-1].replace('.srs', ''), url, False)

    # Формируем итоговый JSON
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
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True}
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + proxy_tags},
            {
                "type": "urltest", "tag": "auto", "outbounds": proxy_tags,
                "url": "http://cp.cloudflare.com/", "interval": "10m"
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ] + final_proxies,
        "route": {
            "rules": [
                {"protocol": "dns", "action": "hijack-dns"},
                {"rule_set": block_routing_tags, "outbound": "block"},
                {"rule_set": proxy_routing_tags, "outbound": "proxy"}
            ],
            "rule_set": formatted_rule_sets,
            "final": "direct",
            "auto_detect_interface": True
        }
    }

    with open('config.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print("\nconfig.json успешно сохранён.")


if __name__ == "__main__":
    generate_final_config()
