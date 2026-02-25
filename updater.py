import requests
import re
import json
import os
from urllib.parse import urlparse, unquote, parse_qs

# --- НАСТРОЙКИ ---
SUB_LINK = 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt'
REGEXP_FILTER = r'^(?!.*Russia).*$'

GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/0x64656164/cancer-treatment/refs/heads/main/ruleset/srs/'

# Список дополнительных внешних SRS файлов
REMOTE_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked-all.srs"
]

REMOTE_BLOCK_RULE_SETS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geosite-category-ads-all.srs"
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
        "uuid": parsed.username, 
        "packet_encoding": "xudp"
    }
    
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
    
    # Исправление ошибки "Unknown transport type: tcp"
    if 'type' in params:
        t_type = params['type'][0]
        if t_type != 'tcp': # Sing-box не принимает "type": "tcp", это значение по умолчанию
            outbound["transport"] = {"type": t_type}
            if t_type == 'grpc': 
                outbound["transport"]["service_name"] = params.get('serviceName', [''])[0]
            elif t_type == 'ws': 
                outbound["transport"]["path"] = params.get('path', ['/'])[0]
                
    return outbound

# --- 1. СБОР REMOTE RULE_SETS ---
formatted_rule_sets = []
proxy_routing_tags = []
block_routing_tags = []

# А. Локальные файлы из основной папки -> в PROXY
local_dir = 'ruleset/srs/'
if os.path.exists(local_dir):
    for file in os.listdir(local_dir):
        if file.endswith('.srs'):
            tag = file.replace('.srs', '')
            full_url = GITHUB_RAW_BASE + file
            formatted_rule_sets.append({
                "type": "remote", "tag": tag, "format": "binary",
                "url": full_url, "download_detour": "proxy"
            })
            proxy_routing_tags.append(tag)

# Б. Локальные файлы из папки block -> в BLOCK
local_block_dir = 'ruleset/srs/block'
if os.path.exists(local_block_dir):
    for file in os.listdir(local_block_dir):
        if file.endswith('.srs'):
            tag = file.replace('.srs', '')
            full_url = GITHUB_RAW_BASE + 'block/' + file
            formatted_rule_sets.append({
                "type": "remote", "tag": tag, "format": "binary",
                "url": full_url, "download_detour": "direct"
            })
            block_routing_tags.append(tag)

# В. Внешние ссылки для BLOCK
for url in REMOTE_BLOCK_RULE_SETS:
    tag = url.split('/')[-1].replace('.srs', '')
    if tag not in block_routing_tags:
        formatted_rule_sets.append({
            "type": "remote", "tag": tag, "format": "binary",
            "url": url, "download_detour": "direct"
        })
        block_routing_tags.append(tag)

# Г. Внешние ссылки для PROXY
for url in REMOTE_RULE_SETS:
    tag = url.split('/')[-1].replace('.srs', '')
    if tag not in proxy_routing_tags and tag not in block_routing_tags:
        formatted_rule_sets.append({
            "type": "remote", "tag": tag, "format": "binary",
            "url": url, "download_detour": "proxy"
        })
        proxy_routing_tags.append(tag)

# --- 2. ПОЛУЧЕНИЕ ПРОКСИ ---
try:
    raw_data = requests.get(SUB_LINK, timeout=15).text
    links = re.findall(r'^vless:\/\/.+$', raw_data, re.MULTILINE)
except: 
    links = []

proxy_outbounds = [parse_vless(l) for l in links if re.match(REGEXP_FILTER, unquote(urlparse(l).fragment))]
proxy_tags = [p["tag"] for p in proxy_outbounds]

# --- 3. СБОРКА КОНФИГА ---
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

print(f"Готово! Ошибка TCP исправлена. Блокировка: {len(block_routing_tags)}, Прокси: {len(proxy_routing_tags)}.")
