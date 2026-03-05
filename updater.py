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
REGEXP_FILTER = r'^(?!.*Russia).*$'
GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/srs/'

TOP_COUNT = 100  # Оставляем 100 лучших
MAX_WORKERS = 8  # Не ставьте слишком много, чтобы не забить свой же канал при тестах
# Ссылка на файл для теста (1МБ достаточно для быстрой оценки)
SPEED_TEST_URL = 'https://cachefly.cachefly.net/1mb.test'
TIMEOUT = 15 # Максимальное время на тест одного прокси

REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]
REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]

def measure_throughput(link):
    """
    Замеряет реальную скорость загрузки данных через прокси.
    Возвращает (outbound_dict, mbps)
    """
    tag = unquote(urlparse(link).fragment) or "Unnamed"
    try:
        # Используем контекстный менеджер из base.py
        with SingBoxProxy(link) as proxy:
            start_time = time.perf_counter()
            # Скачиваем файл
            response = proxy.get(SPEED_TEST_URL, timeout=TIMEOUT, stream=True)
            
            if response.status_code == 200:
                total_content = 0
                # Считаем объем полученных данных
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        total_content += len(chunk)
                
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                if duration > 0:
                    # Расчет Mbps: (байты * 8 бит) / секунды / 1,000,000
                    mbps = (total_content * 8) / (duration * 1_000_000)
                    
                    # Подготавливаем конфиг
                    outbound = proxy._parse_vless_link(link)
                    outbound["tag"] = tag
                    
                    # Fix xhttp -> httpupgrade
                    if "transport" in outbound and outbound["transport"].get("type") == "xhttp":
                        outbound["transport"]["type"] = "httpupgrade"
                        if isinstance(outbound["transport"].get("host"), list):
                            outbound["transport"]["host"] = outbound["transport"]["host"][0] if outbound["transport"]["host"] else ""
                    
                    print(f"[OK] {tag}: {mbps:.2f} Mbps")
                    return outbound, mbps
    except Exception:
        pass
    return None, 0

def generate_final_config():
    print("Загрузка ссылок...")
    try:
        raw_links = requests.get(SUB_LINK).text
        links = re.findall(r'^vless:\/\/.+$', raw_links, re.MULTILINE)
    except Exception as e:
        print(f"Ошибка загрузки: {e}")
        return

    # Фильтрация
    filtered = [l for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
    print(f"Начинаем замер пропускной способности для {len(filtered)} серверов...")

    results = []
    # Запускаем тесты параллельно
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(measure_throughput, l): l for l in filtered}
        for future in concurrent.futures.as_completed(future_to_link):
            outbound, speed = future.result()
            if outbound and speed > 0:
                results.append((outbound, speed))

    # Сортировка по убыванию скорости
    results.sort(key=lambda x: x[1], reverse=True)
    top_proxies = [r[0] for r in results[:TOP_COUNT]]
    
    print(f"Тест завершен. Лучший результат: {results[0][1]:.2f} Mbps" if results else "Нет живых серверов")

    # Уникализация тегов
    seen_tags = {}
    for pb in top_proxies:
        t = pb["tag"]
        if t in seen_tags:
            seen_tags[t] += 1
            pb["tag"] = f"{t}-{seen_tags[t]}"
        else:
            seen_tags[t] = 0

    proxy_tags = [p["tag"] for p in top_proxies]

    # --- СБОРКА КОНФИГА (SRS и прочее) ---
    formatted_rule_sets = []
    proxy_routing_tags = []
    block_routing_tags = []
    rule_tags = set()

    def add_rule(tag, url, is_block):
        if tag in rule_tags: return
        formatted_rule_sets.append({
            "type": "remote", "tag": tag, "format": "binary", "url": url,
            "download_detour": "direct" if is_block else "proxy"
        })
        if is_block: block_routing_tags.append(tag)
        else: proxy_routing_tags.append(tag)
        rule_tags.add(tag)

    # Добавляем SRS из репозитория
    for folder, is_block in [('ruleset/srs/', False), ('ruleset/srs/block', True)]:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                if file.endswith('.srs'):
                    tag = file.replace('.srs', '')
                    url = f"{GITHUB_RAW_BASE}{'block/' if is_block else ''}{file}"
                    add_rule(tag, url, is_block)

    for url in REMOTE_BLOCK_RULE_SETS: add_rule(url.split('/')[-1].replace('.srs', ''), url, True)
    for url in REMOTE_RULE_SETS: add_rule(url.split('/')[-1].replace('.srs', ''), url, False)

    # Финальный JSON
    config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "tls://1.1.1.1", "detour": "proxy"},
                {"tag": "local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "remote"
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30", "auto_route": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + proxy_tags},
            {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ] + top_proxies,
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

if __name__ == "__main__":
    generate_final_config()