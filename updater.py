import requests
import re
import json
import os
import time
import subprocess
import concurrent.futures
from urllib.parse import urlparse, unquote
from base import SingBoxProxy

# --- НАСТРОЙКИ ---
SUB_LINK = 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt'
REGEXP_FILTER = r'^(?=.*(?:YA|VK))(?!.*Russia).*$'
GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/srs/'

TOP_COUNT = 50          # Берём только топ-50 по скорости
MAX_WORKERS = 16
SPEED_TEST_URL = 'https://cachefly.cachefly.net/1mb.test'
TIMEOUT = 5             # Максимум 5 секунд на ожидание и загрузку 1МБ
MAX_PACKET_LOSS = 10.0  # Порог потери пакетов в %: серверы выше отбрасываются
PING_COUNT = 10         # Кол-во пингов для замера потерь

REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]
REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]


def measure_packet_loss(host: str) -> float:
    """
    Замеряет потерю пакетов до хоста через системный ping.
    Возвращает процент потерь (0.0–100.0), или 100.0 при ошибке.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", str(PING_COUNT), "-W", "2", host],
            capture_output=True, text=True, timeout=PING_COUNT * 3
        )
        # Ищем строку вида "X% packet loss"
        match = re.search(r'(\d+(?:\.\d+)?)% packet loss', result.stdout)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return 100.0


def measure_throughput(link):
    tag = unquote(urlparse(link).fragment) or "Unnamed"
    try:
        with SingBoxProxy(link) as proxy:
            # --- Фильтр 1: потеря пакетов ---
            # Получаем хост сервера из распарсенной ссылки
            outbound_tmp = proxy._parse_vless_link(link)
            server_host = outbound_tmp.get("server", "")

            if server_host:
                loss = measure_packet_loss(server_host)
                if loss > MAX_PACKET_LOSS:
                    print(f"[LOSS] {tag}: {loss:.1f}% packet loss - Rejected")
                    return None, 0, 0.0
            else:
                loss = 0.0

            # --- Фильтр 2: скорость ---
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

                    print(f"[GOOD] {tag}: {mbps:.2f} Mbps, loss={loss:.1f}%")
                    return outbound, mbps, loss

    except Exception:
        pass

    return None, 0, 0.0


def generate_final_config():
    print("Загрузка базы ссылок...")
    try:
        raw_links = requests.get(SUB_LINK).text
        links = re.findall(r'^vless:\/\/.+$', raw_links, re.MULTILINE)
    except Exception as e:
        print(f"Ошибка загрузки подписки: {e}")
        return

    filtered = [l for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
    print(f"Начинаем стресс-тест для {len(filtered)} серверов...")
    print(f"Параметры: потеря пакетов ≤ {MAX_PACKET_LOSS}%, топ-{TOP_COUNT} по скорости\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(measure_throughput, l): l for l in filtered}
        for future in concurrent.futures.as_completed(future_to_link):
            outbound, speed, loss = future.result()
            if outbound:
                results.append((outbound, speed, loss))

    if not results:
        print("Критическая ошибка: Ни один сервер не прошел проверку!")
        return

    # Сортируем по скорости (лучшие первые) и берём топ TOP_COUNT
    results.sort(key=lambda x: x[1], reverse=True)
    top_results = results[:TOP_COUNT]

    final_proxies = [r[0] for r in top_results]
    proxy_tags = [p["tag"] for p in final_proxies]

    print(f"\nТест окончен. Прошли фильтр потерь: {len(results)}, "
          f"отобрано в топ-{TOP_COUNT}: {len(final_proxies)} серверов.")
    print("\nТоп-10 по скорости:")
    for i, (ob, spd, ls) in enumerate(top_results[:10], 1):
        print(f"  {i:>2}. {ob['tag'][:50]:<50} {spd:6.2f} Mbps  loss={ls:.1f}%")

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
            {"type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30", "auto_route": True}
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + proxy_tags},
            {
                "type": "urltest", "tag": "auto", "outbounds": proxy_tags,
                "url": "http://cp.cloudflare.com/", "interval": "10m"
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ] + final_proxies,
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
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
