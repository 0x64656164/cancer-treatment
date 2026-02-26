import requests
import re
import json
import os
from urllib.parse import urlparse, unquote, parse_qs

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

def parse_vless(link):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    tag = unquote(parsed.fragment) or f"VLESS-{parsed.hostname}"
    
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": int(parsed.port) if parsed.port else 443,
        "uuid": params.get('uuid', [parsed.username])[0],
        "packet_encoding": "xudp"
    }

    # TLS / Reality
    security = params.get('security', [''])[0]
    if security in ['tls', 'reality']:
        outbound["tls"] = {
            "enabled": True,
            "server_name": params.get('sni', [parsed.hostname])[0],
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
        if security == 'reality':
            outbound["tls"]["reality"] = {
                "enabled": True,
                "public_key": params.get('pbk', [''])[0],
                "short_id": params.get('sid', [''])[0]
            }

    # Transport (xhttp, ws, grpc, http)
    if 'type' in params:
        t_type = params['type'][0]
        if t_type != 'tcp':  # Для TCP блок transport не нужен
            outbound["transport"] = {"type": t_type}
            
            # Общие параметры для большинства типов
            path = params.get('path', ['/'])[0]
            host = params.get('host', [params.get('sni', [''])[0]])[0]
            
            if t_type == 'ws':
                outbound["transport"]["path"] = path
                if host: outbound["transport"]["headers"] = {"Host": host}
            elif t_type == 'grpc':
                outbound["transport"]["service_name"] = params.get('serviceName', [''])[0]
            elif t_type in ['xhttp', 'http']:
                outbound["transport"]["path"] = path
                if host: outbound["transport"]["host"] = host
                # Доп. параметры для xhttp (версия 1.10+)
                if 'mode' in params:
                    outbound["transport"]["mode"] = params['mode'][0]

    return outbound

# --- 1. СБОР RULE_SETS (БЕЗ ДУБЛИКАТОВ) ---
formatted_rule_sets = []
proxy_routing_tags = []
block_routing_tags = []
seen_tags = set()

def add_rule_set(tag, url, is_block=False):
    if tag in seen_tags: return
    formatted_rule_sets.append({
        "type": "remote",
        "tag": tag,
        "format": "binary",
        "url": url,
        "download_detour": "direct" if is_block else "proxy"
    })
    if is_block: block_routing_tags.append(tag)
    else: proxy_routing_tags.append(tag)
    seen_tags.add(tag)

# Проход по папкам
for folder, is_block in [('ruleset/srs/', False), ('ruleset/srs/block', True)]:
    if os.path.exists(folder):
        for file in os.listdir(folder):
            if file.endswith('.srs'):
                tag = file.replace('.srs', '')
                url = f"{GITHUB_RAW_BASE}{'block/' if is_block else ''}{file}"
                add_rule_set(tag, url, is_block)

# Проход по внешним ссылкам
for url in REMOTE_BLOCK_RULE_SETS:
    add_rule_set(url.split('/')[-1].replace('.srs', ''), url, True)
for url in REMOTE_RULE_SETS:
    add_rule_set(url.split('/')[-1].replace('.srs', ''), url, False)

# --- 2. ПОЛУЧЕНИЕ ПРОКСИ ---
try:
    raw_data = requests.get(SUB_LINK, timeout=15).text
    links = re.findall(r'^vless:\/\/.+$', raw_data, re.MULTILINE)
except: links = []

proxy_outbounds = [parse_vless(l) for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
proxy_tags = [p["tag"] for p in proxy_outbounds]

# --- 3. ФИНАЛЬНЫЙ КОНФИГ ---
final_config = {
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
    ] + proxy_outbounds,
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
    json.dump(final_config, f, indent=2, ensure_ascii=False)

print(f"Обновлено! Версия 1.10.3 поддерживается. Уникальных правил: {len(seen_tags)}")
