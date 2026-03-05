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

TOP_COUNT = 100          # Оставляем только 100 лучших
TEST_THREADS = 10        # Количество одновременных тестов
# Ссылка для теста. 'generate_204' проверяет доступность и задержку.
# Для реальной скорости лучше файл побольше: 'https://cachefly.cachefly.net/1mb.test'
SPEED_TEST_URL = 'http://cp.cloudflare.com/generate_204'
TIMEOUT = 10             # Тайм-аут на один сервер

REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]
REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]

def benchmark_proxy(link):
    """Тестирует прокси и возвращает (outbound_dict, score)"""
    try:
        tag = unquote(urlparse(link).fragment) or "Unnamed"
        
        # Используем SingBoxProxy из вашего base.py
        with SingBoxProxy(link) as proxy:
            start_time = time.time()
            # Делаем запрос через поднятый прокси
            response = proxy.get(SPEED_TEST_URL, timeout=TIMEOUT)
            duration = time.time() - start_time
            
            if response.status_code < 400:
                # Чем меньше duration, тем выше score
                score = 1000 / duration 
                
                # Генерируем структуру для конфига
                outbound = proxy._parse_vless_link(link)
                outbound["tag"] = tag
                
                # Фикс xhttp -> httpupgrade
                if "transport" in outbound and outbound["transport"].get("type") == "xhttp":
                    outbound["transport"]["type"] = "httpupgrade"
                
                return outbound, score
    except:
        pass
    return None, 0

def generate_final_config():
    print(f"Загрузка подписки...")
    try:
        resp = requests.get(SUB_LINK, timeout=15)
        links = re.findall(r'^vless:\/\/.+$', resp.text, re.MULTILINE)
    except Exception as e:
        print(f"Ошибка загрузки: {e}")
        return

    # Фильтруем по названию
    candidates = [l for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
    print(f"Найдено {len(candidates)} кандидатов. Начинаем тест скорости в {TEST_THREADS} потоков...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=TEST_THREADS) as executor:
        future_to_link = {executor.submit(benchmark_proxy, l): l for l in candidates}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_link)):
            outbound, score = future.result()
            if outbound:
                results.append((outbound, score))
            if i % 10 == 0:
                print(f"Проверено {i}/{len(candidates)}...")

    # Сортируем: лучшие сверху
    results.sort(key=lambda x: x[1], reverse=True)
    top_results = results[:TOP_COUNT]
    
    # Очищаем список и исправляем дубли тегов
    final_proxies = []
    seen_tags = {}
    for outbound, _ in top_results:
        t = outbound["tag"]
        if t in seen_tags:
            seen_tags[t] += 1
            outbound["tag"] = f"{t}-{seen_tags[t]}"
        else:
            seen_tags[t] = 0
        final_proxies.append(outbound)

    proxy_tags = [p["tag"] for p in final_proxies]
    print(f"Отобрано {len(final_proxies)} лучших серверов.")

    # --- Сборка Rule Sets ---
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

    # Локальные SRS
    for folder, is_block in [('ruleset/srs/', False), ('ruleset/srs/block', True)]:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                if file.endswith('.srs'):
                    tag = file.replace('.srs', '')
                    url = f"{GITHUB_RAW_BASE}{'block/' if is_block else ''}{file}"
                    add_rule(tag, url, is_block)

    for url in REMOTE_BLOCK_RULE_SETS: add_rule(url.split('/')[-1].replace('.srs', ''), url, True)
    for url in REMOTE_RULE_SETS: add_rule(url.split('/')[-1].replace('.srs', ''), url, False)

    # Финальный конфиг
    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": "tls://1.1.1.1", "detour": "proxy"},
                {"tag": "dns-direct", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns-fakeip", "address": "fakeip"}
            ],
            "rules": [
                {"outbound": "any", "server": "dns-direct"},
                {"query_type": ["A", "AAAA"], "server": "dns-fakeip"}
            ],
            "final": "dns-remote",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30",
            "auto_route": True, "strict_route": True, "sniff": True, "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + proxy_tags + ["direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
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

if __name__ == "__main__":
    generate_final_config()