# Copyright (C) 2025 / S1131
# This program is free software under the GNU GPLv3 license.
# DISCLAIMER:
# This script is provided for educational and ethical auditing purposes.
# The author is NOT LIABLE for any damage, data loss, or
# legal action resulting from the misuse of this tool.
# Use at your own risk and responsibility.

import requests
import argparse
import os
import signal
import json
import time
import threading
import random
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from collections import deque, namedtuple
from requests.adapters import HTTPAdapter
from itertools import islice

PluginResult = namedtuple('PluginResult', ['status', 'index', 'name', 'status_code', 'target', 'time'])

class WordPressScanner:
    def __init__(self, url, dict_path, threads=10, delay=0, random_stealth=False, random_headers=False):
        
        self.url = url.rstrip('/')
        self.dict_path = dict_path
        self.threads = threads
        self.state_file = "scanner_checkpoint.json"
        
        self.active_tasks = {} 
        self.retry_queue = deque()
        self.found_plugins = [] 
        self.scan_index = 0
        self.stats = {"blocks": 0, "net_errors": 0}
        
        self.random_stealth = random_stealth
        self.random_headers = random_headers
        self.delay = delay
        self.waf_waiting_time = 10
        self.waf_max_retry = 10
        self.waf_status_codes = [403, 429, 503]
        self.host_waiting_time = 5
        self.host_max_retry = 3

        self.waf_blocked = threading.Event()
        self.host_down = threading.Event()
        self.recovery_lock = threading.Lock()
        
        self.session = self._setup_session()
        self.executor = None
        self.pbar = None
        self._cleaned = False

        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
        ]

        signal.signal(signal.SIGINT, self.signal_handler)

    def ntime(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _setup_session(self):
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=self.threads, pool_maxsize=self.threads)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        })
        return session

    def __enter__(self):
        self.executor = ThreadPoolExecutor(max_workers=self.threads)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def signal_handler(self, signum, frame):
        print("\r\033[K", end="", flush=True)
        self.cleanup()
        os._exit(0)

    def cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
        
        if self.pbar is not None:
            self.pbar.close()
            self.pbar = None
            
        self.save_checkpoint()
        
        if self.executor:
            self.executor.shutdown(wait=False)

    def get_wordlist_generator(self):
        with open(self.dict_path, 'r', errors='ignore') as f:
            for line in islice(f, self.scan_index, None):
                word = line.strip()
                if word: yield word

    def show_plugins_found(self):
        output = self.pbar.write if self.pbar else print
        for p in self.found_plugins:
            output(f"[+] {p['time']} | Plugin:{p['name']}, Url:{p['url']} - code: {p['code']}")

    def save_checkpoint(self):
        temp_retry = list(self.retry_queue)
        for task_info in self.active_tasks.values():
            item = [task_info['index'], task_info['name']]
            if item not in temp_retry:
                temp_retry.append(item)

        temp_retry.sort(key=lambda x: x[0])
        if temp_retry: 
            self.scan_index = temp_retry[0][0]

        data = {
            'index': self.scan_index,
            'retry_queue': temp_retry,
            'target': self.url,
            'found': self.found_plugins, 
            'stats': self.stats
        }
        with open(self.state_file, 'w') as f:
            json.dump(data, f, indent=4)

    def load_checkpoint(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                try:
                    data = json.load(f)
                    if self.url == data.get('target'):
                        self.scan_index = data.get('index', 0)
                        self.retry_queue = deque(data.get('retry_queue', []))
                        self.found_plugins = data.get('found', [])
                        self.stats = data.get('stats', self.stats)
                        print(f"[*] [{self.ntime()}] Cargando estado previo...")
                        self.show_plugins_found()
                        return True
                except: 
                    return False
        return False

    def scan_request(self, url):
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True)
            return r.status_code
        except:
            return "NET_ERROR"

    def plugin_request(self, name, index, bypass=False):
        
        now = self.ntime()
        current_headers = {}

        if (self.waf_blocked.is_set() or self.host_down.is_set()) and not bypass:
            return PluginResult("PAUSE", index, name, 0, "", now)
        
        if self.delay > 0 and self.random_stealth:
            time.sleep(random.uniform(0.5, self.delay))
        elif self.random_stealth:
            time.sleep(random.uniform(0.2, 1.5))
        elif self.delay > 0:
            time.sleep(self.delay)
            
        if self.random_headers:
            current_headers = {'User-Agent': random.choice(self.user_agents)}

        target = f"{self.url}/wp-content/plugins/{name}/readme.txt"

        try:
            r = self.session.get(
                target, timeout=10, 
                allow_redirects=True, 
                verify=False, 
                headers=current_headers
            )
            
            if r.status_code in self.waf_status_codes:
                return PluginResult("WAF_BLOCK", index, name, r.status_code, target, now)
            if r.status_code == 200:
                return PluginResult("FOUND", index, name, r.status_code, target, now)
            else:
                return PluginResult("MISS", index, name, r.status_code, target, now)
        except:
            return PluginResult("NET_ERROR", index, name, 0, target, now)

    def handle_waf_recovery(self, plugin):
        with self.recovery_lock:
            self.pbar.write(f"[!] [{plugin.time}] WAF Detectado: {plugin.name}")
            for _ in range(self.waf_max_retry):
                with tqdm(
                    total=self.waf_waiting_time, 
                    desc=f"[{self.ntime()}] Espera WAF", 
                    bar_format='{desc}: {n_fmt}/{total}s', 
                    leave=False
                ) as hb:
                    for _ in range(self.waf_waiting_time):
                        time.sleep(1)
                        hb.update(1)

                res = self.plugin_request(plugin.name, plugin.index, bypass=True)
                if res.status != "WAF_BLOCK":
                    self.waf_blocked.clear()
                    self.pbar.write(f"[*] [{self.ntime()}] WAF Superado.")
                    return
            self.signal_handler(None, None)

    def handle_host_recovery(self):
        with self.recovery_lock:
            self.pbar.write(f"[!] [{self.ntime()}] Conexión perdida. Reintentando...")
            for i in range(self.host_max_retry):
                with tqdm(
                    total=self.host_waiting_time, 
                    desc=f"[{self.ntime()}] Reintento {i+1}/{self.host_max_retry}", 
                    bar_format='{desc}: {n_fmt}/{total}s', 
                    leave=False
                ) as hb:
                    for _ in range(self.host_waiting_time):
                        time.sleep(1)
                        hb.update(1)
                
                if self.scan_request(self.url) != "NET_ERROR":
                    self.host_down.clear()
                    self.pbar.write(f"[*] [{self.ntime()}] Host restaurado.")
                    return
            
            self.pbar.write(f"[FATAL] [{self.ntime()}] El servidor no responde.")
            self.signal_handler(None, None)

    def run(self, resume=False):
        if resume: 
            self.load_checkpoint()
        
        try:
            total_lines = sum(1 for _ in open(self.dict_path, 'r', errors='ignore'))
        except FileNotFoundError:
            print(f"[!] No existe: {self.dict_path}"); return

        if self.scan_index >= total_lines:
            print(f"[!] [{self.ntime()}] Escaneo completado."); return

        word_gen = self.get_wordlist_generator()
        
        self.pbar = tqdm(
            total=total_lines, 
            initial=self.scan_index, 
            desc="Scanner", 
            unit="plg", 
            dynamic_ncols=True,
            leave=False
        )

        last_block_result = None

        while not self._cleaned:
            if self.waf_blocked.is_set() and last_block_result:
                self.handle_waf_recovery(last_block_result)
            if self.host_down.is_set():
                self.handle_host_recovery()

            while not (self.waf_blocked.is_set() or self.host_down.is_set()) and len(self.active_tasks) < self.threads:
                if self.retry_queue:
                    item = self.retry_queue.popleft()
                    index, name = item[0], item[1]
                else:
                    try:
                        name = next(word_gen); index = self.scan_index; self.scan_index += 1
                    except StopIteration: break
                
                future = self.executor.submit(self.plugin_request, name, index)
                self.active_tasks[future] = {'index': index, 'name': name}

            if not self.active_tasks: break
            
            done, _ = wait(self.active_tasks.keys(), return_when=FIRST_COMPLETED, timeout=1)
            
            for f in done:
                res = f.result()
                self.active_tasks.pop(f)

                if res.status in ["WAF_BLOCK", "NET_ERROR", "PAUSE"]:
                    self.retry_queue.appendleft((res.index, res.name))
                    if res.status == "WAF_BLOCK":
                        last_block_result = res
                        self.waf_blocked.set()
                    if res.status == "NET_ERROR": self.host_down.set()
                elif res.status == "FOUND":
                    if not any(p['url'] == res.target for p in self.found_plugins):
                        self.pbar.write(f"[+] [{res.time}] Plugins:[{res.name}], Url:{res.target} - {res.status_code}")
                        self.found_plugins.append({"time": res.time, "name": res.name, "url": res.target, "code": res.status_code})
                    self.pbar.update(1)
                elif res.status == "MISS":
                    self.pbar.update(1)

            if self.pbar:
                self.pbar.set_postfix({"Cola": len(self.retry_queue), "Hallazgos": len(self.found_plugins)})
        
        self.cleanup()
        print(f"\n[*] Escaneo finalizado. Hallazgos: {len(self.found_plugins)}")
        self.show_plugins_found()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-d", "--dict", required=True)
    parser.add_argument("-t", "--threads", type=int, default=15)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("-s", "--stealth", type=float, nargs='?', default=0.0, const=0.5, help="Segudos de espera entre peticiones ej: 0.5")
    parser.add_argument("--random-stealth", action="store_true", help="Establece tiempos de espera aleatorios entre peticiones")
    parser.add_argument("--random-headers", action="store_true", help="Establece cabeceras aleatorias")
    args = parser.parse_args()
    
    requests.packages.urllib3.disable_warnings()
    try:
        with WordPressScanner(
            args.url, 
            args.dict, 
            args.threads, 
            delay=args.stealth, 
            random_stealth=args.random_stealth,
            random_headers=args.random_headers
        ) as scanner:
            scanner.run(resume=args.resume)
    except SystemExit: pass
    except Exception as e:
        print(f"\n[!] Error: {e}")
