import requests
import re
import json
import os
import time
import concurrent.futures
from urllib.parse import urlparse, unquote
from base import SingBoxProxy

# --- НАСТРОЙКИ ---
SUB_LINK = 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt'
REGEXP_FILTER = r'^(?=.*(?:YA|VK))(?!.*Russia).*$'
REGEXP_FILTER_FALLBACK = r'^(?=.*(?:YA|VK)).*$'   # то же, но без исключения Russia
GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656464/cancer-treatment/refs/heads/main/ruleset/srs/'

TOP_COUNT = 50          # Берём только топ-50 по скорости
MIN_SERVERS = 5         # Минимум серверов, прошедших проверку
MIN_BEST_SPEED = 1.5    # Минимальная скорость лучшего сервера (Mbps)
MAX_WORKERS = 8
SPEED_TEST_URL = 'https://cachefly.cachefly.net/1mb.test'
TIMEOUT = 5             # Максимум 5 секунд на ожидание и загрузку 1МБ

REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]
REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]


def measure_throughput(link):
    tag = unquote(urlparse(link).fragment) or "Unnamed"
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

                    outbound = proxy._parse_vless_link(link)
                    outbound["tag"] = tag
                    outbound["domain_strategy"] = "prefer_ipv4"

                    # Совместимость с xhttp
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


def generate_final_config():
    print("Загрузка базы ссылок...")
    try:
        raw_links = requests.get(SUB_LINK).text
        links = re.findall(r'^vless:\/\/.+$', raw_links, re.MULTILINE)
    except Exception as e:
        print(f"Ошибка загрузки подписки: {e}")
        return

    # --- Первый проход: основной фильтр (без Russia) ---
    filtered = [l for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
    results = run_speed_test(filtered, "основной фильтр, без Russia")

    # --- Фоллбэк: повтор с разрешением Russia ---
    if needs_fallback(results):
        filtered_fallback = [l for l in links if re.match(REGEXP_FILTER_FALLBACK, unquote(urlparse(l).fragment))]
        # Исключаем ссылки, которые уже тестировались, чтобы не дублировать
        already_tested = set(filtered)
        new_links = [l for l in filtered_fallback if l not in already_tested]

        if new_links:
            fallback_results = run_speed_test(new_links, "фоллбэк, включая Russia")
            # Объединяем и пересортируем
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
