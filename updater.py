import requests
import re
import json
import os
from urllib.parse import urlparse, unquote, parse_qs

# --- НАСТРОЙКИ ---
# Ссылка на вашу подписку с VLESS конфигами
SUB_LINK = 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt'
# Фильтр: исключаем теги, содержащие "Russia"
REGEXP_FILTER = r'^(?!.*Russia).*$'

# Базовый URL для ваших локальных SRS файлов в GitHub
GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/srs/'

# Внешние наборы правил (удаленные)
REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]

REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs"
]

def parse_vless(link):
    """Парсит VLESS ссылку и адаптирует её под стандарт Sing-box 1.10+"""
    parsed = urlparse(link)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    tag = unquote(parsed.fragment) or f"VLESS-{parsed.hostname}"
    
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": int(parsed.port) if parsed.port else 443,
        "uuid": params.get('uuid', parsed.username),
        "packet_encoding": "xudp"
    }

    # Настройка TLS / Reality
    security = params.get('security', '').lower()
    if security in ['tls', 'reality']:
        outbound["tls"] = {
            "enabled": True,
            "server_name": params.get('sni', parsed.hostname),
            "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')}
        }
        if security == 'reality':
            outbound["tls"]["reality"] = {
                "enabled": True,
                "public_key": params.get('pbk', ''),
                "short_id": params.get('sid', '')
            }

    # ЛОГИКА ТРАНСПОРТА (Исправление xhttp -> httpupgrade)
    t_type = params.get('type', 'tcp').lower()
    path = params.get('path', '/')
    host = params.get('host', params.get('sni', ''))

    if t_type in ['xhttp', 'httpupgrade']:
        # Sing-box использует httpupgrade для замены xhttp из Xray
        outbound["transport"] = {
            "type": "httpupgrade",
            "path": path,
            "host": host
        }
    elif t_type == 'ws':
        outbound["transport"] = {
            "type": "ws",
            "path": path,
            "headers": {"Host": host} if host else {}
        }
    elif t_type == 'grpc':
        outbound["transport"] = {
            "type": "grpc",
            "service_name": params.get('serviceName', '')
        }
    # Для TCP (по умолчанию) блок transport не создаем
    
    return outbound

# --- 1. СБОР RULE_SETS (БЕЗ ДУБЛИКАТОВ) ---
formatted_rule_sets = []
proxy_routing_tags = []
block_routing_tags = []
seen_tags = set()

def add_rule_set(tag, url, is_block=False):
    """Добавляет набор правил, если такой тег еще не встречался"""
    if not tag or tag in seen_tags:
        return
    
    rule_entry = {
        "type": "remote",
        "tag": tag,
        "format": "binary",
        "url": url,
        "download_detour": "direct" if is_block else "proxy"
    }
    formatted_rule_sets.append(rule_entry)
    if is_block:
        block_routing_tags.append(tag)
    else:
        proxy_routing_tags.append(tag)
    seen_tags.add(tag)

# А. Локальные файлы из папок (Приоритет)
folders = [('ruleset/srs/', False), ('ruleset/srs/block', True)]
for folder_path, is_block in folders:
    if os.path.exists(folder_path):
        for file_name in os.listdir(folder_path):
            if file_name.endswith('.srs'):
                tag = file_name.replace('.srs', '')
                # Формируем URL для GitHub Raw
                sub_path = 'block/' if is_block else ''
                url = f"{GITHUB_RAW_BASE}{sub_path}{file_name}"
                add_rule_set(tag, url, is_block)

# Б. Внешние ссылки
for url in REMOTE_BLOCK_RULE_SETS:
    tag = url.split('/')[-1].replace('.srs', '')
    add_rule_set(tag, url, True)

for url in REMOTE_RULE_SETS:
    tag = url.split('/')[-1].replace('.srs', '')
    add_rule_set(tag, url, False)

# --- 2. ПОЛУЧЕНИЕ ПРОКСИ-СЕРВЕРОВ ---
try:
    response = requests.get(SUB_LINK, timeout=15)
    response.raise_for_status()
    raw_links = re.findall(r'^vless:\/\/.+$', response.text, re.MULTILINE)
except Exception as e:
    print(f"Ошибка при загрузке подписки: {e}")
    raw_links = []

proxy_outbounds = []
for link in raw_links:
    # Декодируем фрагмент для проверки фильтра
    fragment = unquote(urlparse(link).fragment)
    if re.match(REGEXP_FILTER, fragment):
        try:
            proxy_outbounds.append(parse_vless(link))
        except:
            continue

proxy_tags = [p["tag"] for p in proxy_outbounds]

# --- 3. СБОРКА ИТОГОВОГО КОНФИГА ---
config = {
    "log": {"level": "info", "timestamp": True},
    "dns": {
        "servers": [
            {"tag": "dns_proxy", "address": "tls://1.1.1.1", "detour": "proxy"},
            {"tag": "dns_direct", "address": "223.5.5.5", "detour": "direct"},
            {"tag": "dns_fakeip", "address": "fakeip"}
        ],
        "rules": [
            {"outbound": "any", "server": "dns_direct"},
            {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
        ],
        "final": "dns_proxy",
        "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
    },
    "inbounds": [{
        "type": "tun",
        "tag": "tun-in",
        "inet4_address": "172.19.0.1/30",
        "auto_route": True,
        "strict_route": True,
        "sniff": True,
        "sniff_override_destination": True
    }],
    "outbounds": [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + proxy_tags + ["direct"]},
        {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://cp.cloudflare.com/", "interval": "10m"},
        {"type": "direct", "tag": "direct"},
        {"type": "dns", "tag": "dns-out"},
        {"type": "block", "tag": "block"}
    ] + proxy_outbounds,
    "route": {
        "rules": [
            {"protocol": "dns", "outbound": "dns-out"},
            # Сначала блокировка
            {"rule_set": block_routing_tags, "outbound": "block"},
            # Затем проксирование
            {"rule_set": proxy_routing_tags, "outbound": "proxy"}
        ],
        "rule_set": formatted_rule_sets,
        "final": "direct",
        "auto_detect_interface": True
    }
}

# Сохранение
with open('config.json', 'w', encoding='utf-8') as f:
    json.dump(config, f, indent=2, ensure_ascii=False)

print(f"Готово! Создан config.json. Наборов правил: {len(seen_tags)}, Прокси: {len(proxy_tags)}.")
