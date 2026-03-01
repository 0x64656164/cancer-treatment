import requests
import re
import json
import os
from urllib.parse import urlparse, unquote
from base import SingBoxProxy

# --- НАСТРОЙКИ ---
SUB_LINK = 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt'
REGEXP_FILTER = r'^(?!.*Russia).*$'
GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/srs/'

REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]
REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]

def generate_final_config():
    try:
        response = requests.get(SUB_LINK, timeout=15)
        response.raise_for_status()
        links = re.findall(r'^vless:\/\/.+$', response.text, re.MULTILINE)
    except Exception as e:
        print(f"Ошибка загрузки: {e}")
        links = []

    all_proxy_outbounds = []
    seen_tags = {}

    # Создаем фиктивный объект для доступа к парсеру
    parser = SingBoxProxy("vless://temp@temp:443#temp")

    for link in links:
        try:
            # Извлекаем оригинальное имя из ссылки (после #)
            url_parts = urlparse(link)
            original_tag = unquote(url_parts.fragment)
            
            # Проверка фильтра (пропускаем "Russia")
            if not original_tag or not re.match(REGEXP_FILTER, original_tag):
                continue

            # Парсим ссылку через логику base.py
            outbound = parser._parse_vless_link(link)
            
            # --- КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ ---
            # 1. Принудительно ставим оригинальный тег вместо дефолтного "proxy"
            outbound["tag"] = original_tag
            
            # 2. Исправляем xhttp -> httpupgrade
            if "transport" in outbound and outbound["transport"].get("type") == "xhttp":
                outbound["transport"]["type"] = "httpupgrade"
                # В sing-box v1.10+ host в httpupgrade должен быть строкой, а не списком
                if isinstance(outbound["transport"].get("host"), list):
                    outbound["transport"]["host"] = outbound["transport"]["host"][0] if outbound["transport"]["host"] else ""

            # 3. Добавляем в список с суффиксами, если тег уже существует
            if outbound["tag"] in seen_tags:
                seen_tags[outbound["tag"]] += 1
                outbound["tag"] = f"{outbound['tag']}-{seen_tags[outbound['tag']]}"
            else:
                seen_tags[outbound["tag"]] = 0

            all_proxy_outbounds.append(outbound)
                
        except Exception as e:
            print(f"Ошибка парсинга ссылки: {e}")

    # Список тегов для селектора
    proxy_tags = [p["tag"] for p in all_proxy_outbounds]

    # --- СБОРКА ПРАВИЛ (RULE SETS) ---
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

    # Локальные
    for folder, is_block in [('ruleset/srs/', False), ('ruleset/srs/block', True)]:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                if file.endswith('.srs'):
                    tag = file.replace('.srs', '')
                    url = f"{GITHUB_RAW_BASE}{'block/' if is_block else ''}{file}"
                    add_rule(tag, url, is_block)

    # Внешние
    for url in REMOTE_BLOCK_RULE_SETS: add_rule(url.split('/')[-1].replace('.srs', ''), url, True)
    for url in REMOTE_RULE_SETS: add_rule(url.split('/')[-1].replace('.srs', ''), url, False)

    # --- ИТОГОВЫЕ ВЫХОДЫ ---
    main_outbounds = [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + proxy_tags + ["direct"]},
        {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
        {"type": "direct", "tag": "direct"},
        {"type": "dns", "tag": "dns-out"},
        {"type": "block", "tag": "block"}
    ]
    
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
        "outbounds": main_outbounds + all_proxy_outbounds,
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
    print("Конфиг успешно пересобран.")
