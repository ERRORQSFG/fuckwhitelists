import socket
import ipaddress
import time
import requests as reqs
from urllib.parse import unquote, urlparse, parse_qs, urlunparse
import json
import subprocess
import os
import random
import base64
import bisect
import urllib3
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# Настройки для GitHub (замени на свои)
GH_USER = "ТВОЙ_ЛОГИН"
GH_REPO = "ИМЯ_РЕПО"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XRAY_PATH = "./xray"
TEST_URL = "http://clients3.google.com/generate_204"
TIMEOUT_CHECK = 5
THREADS = 50 
TCP_TIMEOUT = 0.8

def ensure_xray():
    if not os.path.exists(XRAY_PATH):
        print("📥 Скачиваю Xray для Linux...")
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        r = reqs.get(url, timeout=15)
        with open("xray.zip", "wb") as f: f.write(r.content)
        with zipfile.ZipFile("xray.zip", "r") as zip_ref: zip_ref.extract("xray", path=".")
        os.chmod(XRAY_PATH, 0o755)
        os.remove("xray.zip")

def get_geo(ip):
    try:
        r = reqs.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
        code = r.get("country_code", "UN").upper()
        flag = "".join(chr(127397 + ord(c)) for c in code)
        return code, flag
    except: return "UN", "🏳️"

def parse_uri_to_xray_outbound(uri):
    try:
        uri = uri.replace("&amp;", "&")
        parsed = urlparse(uri)
        query = {k: unquote(v[0]) for k, v in parse_qs(parsed.query).items()}
        protocol = parsed.scheme
        if protocol not in ["vless", "trojan"]: return None

        out = {"protocol": protocol, "settings": {}, 
               "streamSettings": {"network": query.get("type", "tcp"), "security": query.get("security", "none")}}
        
        if protocol == "vless":
            out["settings"] = {"vnext": [{"address": parsed.hostname, "port": int(parsed.port or 443),
                               "users": [{"id": parsed.username, "encryption": "none", "flow": query.get("flow", "")}]}]}
        elif protocol == "trojan":
            out["settings"] = {"servers": [{"address": parsed.hostname, "port": int(parsed.port or 443), "password": parsed.username}]}

        if out["streamSettings"]["security"] == "reality":
            out["streamSettings"]["realitySettings"] = {"show": False, "fingerprint": query.get("fp", "chrome"),
                "serverName": query.get("sni", ""), "publicKey": query.get("pbk", ""), "shortId": query.get("sid", ""), "spiderX": ""}
        
        return out
    except: return None

def check_worker(raw_config, source_name, sni_label):
    config_name = f"temp_{random.getrandbits(32)}.json"
    process = None
    try:
        p = urlparse(raw_config)
        try: entry_ip = socket.gethostbyname(p.hostname)
        except: entry_ip = p.hostname
            
        with socket.create_connection((entry_ip, p.port or 443), timeout=TCP_TIMEOUT):
            outbound = parse_uri_to_xray_outbound(raw_config)
            if not outbound: return None

            l_port = random.randint(20000, 60000)
            with open(config_name, "w") as f:
                json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": l_port, "protocol": "socks"}], "outbounds": [outbound]}, f)

            process = subprocess.Popen([XRAY_PATH, "-c", config_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

            proxies = {'http': f'socks5h://127.0.0.1:{l_port}', 'https': f'socks5h://127.0.0.1:{l_port}'}
            r = reqs.get(TEST_URL, proxies=proxies, timeout=TIMEOUT_CHECK)
            
            if r.status_code in [200, 204]:
                e_code, e_flag = get_geo(entry_ip)
                exit_ip = reqs.get("https://api.ipify.org", proxies=proxies, timeout=3).text
                ex_code, ex_flag = get_geo(exit_ip)
                
                geo_str = f"{e_flag} {e_code}-{ex_flag} {ex_code}" if e_code != ex_code else f"{ex_flag} {ex_code}"
                new_name = f"FWL • {geo_str} • {sni_label} • {source_name}"
                return urlunparse(list(p)[:5] + [new_name])
    except: pass
    finally:
        if process: process.terminate()
        if os.path.exists(config_name): os.remove(config_name)
    return None

if __name__ == "__main__":
    ensure_xray()
    
    allowed_snis = {}
    if os.path.exists("whitelist/sni.txt"):
        with open("whitelist/sni.txt", "r", encoding='utf-8') as f:
            for line in f:
                if ":" in line:
                    k, v = line.strip().split(":", 1)
                    allowed_snis[k.strip().lower()] = v.strip()

    print("📥 Сбор данных...")
    all_raw = []
    if os.path.exists("subs.txt"):
        with open("subs.txt", "r", encoding='utf-8') as f:
            sources = [line.strip().split('|') for line in f if '|' in line]
        
        for link, name in sources:
            try:
                # Добавил таймаут и игнор SSL, чтобы не тупило на кривых источниках
                r = reqs.get(link.strip(), timeout=15, verify=False)
                if r.status_code == 200:
                    # Улучшенная регулярка: ловит всё от vless/trojan до конца строки или кавычки
                    found = re.findall(r'(?:vless|trojan)://[^\s#"\'<>\^]+(?:#[^\s"\'<>]*)?', r.text)
                    all_raw.extend([(node, name) for node in found])
            except Exception as e:
                print(f"❌ Ошибка загрузки {name}: {e}")
                continue

    print(f"🔎 Найдено {len(all_raw)} сырых ссылок. Фильтрация...")
    tasks = []
    seen = set()
    
    for raw, s_name in all_raw:
        try:
            # Чистим ссылку от мусора
            raw_clean = raw.strip().split('\\')[0].split('"')[0].split("'")[0]
            if "&amp;" in raw_clean:
                raw_clean = raw_clean.replace("&amp;", "&")
            
            p = urlparse(raw_clean)
            if not p.hostname or not p.username:
                continue

            q = parse_qs(p.query)
            # Достаем SNI или хост
            sni = unquote(q.get('sni', [p.hostname])[0] or "").lower()
            
            # ФИЛЬТР: Если SNI в списке — даем метку. Если нет — ставим 'Unknown', но НЕ УДАЛЯЕМ
            label = allowed_snis.get(sni) or next((v for k, v in allowed_snis.items() if sni.endswith(k)), None)
            if not label:
                label = "Other" # Теперь он пропустит даже те, которых нет в sni.txt

            if raw_clean not in seen:
                seen.add(raw_clean)
                tasks.append((raw_clean, s_name, label))
        except Exception:
            continue

    # ОТЛАДКА: сколько реально ушло в тест
    print(f"🚀 В тестер уходит: {len(tasks)} нод")
    
    if len(tasks) == 0:
        print("‼️ ВНИМАНИЕ: Список задач пуст. Проверь форматы в subs.txt или доступ к ссылкам.")
    
    results = []
    # Если задач мало, можно уменьшить потоки, но 50 — ок
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = [ex.submit(check_worker, *t) for t in tasks]
        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)
                print(f"✅ Годно: {res.split('#')[-1]}")

    # Сохранение TXT
    with open("result.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(results))

    # Генерация HTML (исправленные скобки)
    sub_url = f"https://raw.githubusercontent.com/{GH_USER}/{GH_REPO}/main/result.txt"
    html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS Subs</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background: #0f172a; color: white; min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 24px; }}
    </style>
</head>
<body>
    <div class="glass p-8 m-4 max-w-lg w-full shadow-2xl">
        <h1 class="text-2xl font-bold mb-2">FuckWhiteLists</h1>
        <h1 class="text-2xl font-bold mb-2">Просьба использовать подписку ТОЛЬКО при ограничениях интернета (при белых списках)!</h1>
        <p class="text-blue-400 text-sm mb-6">Серверов в подписке: {len(results)}</p>
        <div class="bg-black/30 p-4 rounded-xl border border-white/5 mb-6">
            <p class="text-gray-400 text-xs uppercase mb-2">URL подписки</p>
            <div class="truncate font-mono text-blue-300 text-xs mb-4" id="sub-url">{sub_url}</div>
            <button onclick="copyToClipboard()" class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-bold transition-all active:scale-95">Скопировать ссылку</button>
        </div>
        <div id="toast" class="fixed bottom-10 left-1/2 -translate-x-1/2 px-6 py-3 rounded-2xl opacity-0 transition-opacity duration-300 pointer-events-none text-white shadow-2xl"></div>
    </div>
    <script>
        function showToast(msg, isError = false) {{
            const toast = document.getElementById('toast');
            toast.innerText = msg;
            toast.style.background = isError ? '#ef4444' : '#22c55e';
            toast.classList.add('opacity-100');
            setTimeout(() => {{ toast.classList.remove('opacity-100'); }}, 3000);
        }}
        async function copyToClipboard() {{
            const url = "{sub_url}";
            try {{
                await navigator.clipboard.writeText(url);
                showToast("✅ Скопировано!");
            }} catch (err) {{
                const isTG = /Telegram/i.test(navigator.userAgent);
                if (isTG) {{
                    showToast("❌ Браузер Telegram блокирует копирование. Открой в Chrome/Safari", true);
                }} else {{
                    showToast("❌ Ошибка копирования", true);
                }}
            }}
        }}
    </script>
</body>
</html>
"""
    with open("index.html", "w", encoding='utf-8') as f:
        f.write(html_content)
    print("🎉 Все готово!")
