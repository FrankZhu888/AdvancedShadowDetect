#!/usr/bin/env python3
# Script Name: Advanced Shadow Detect
# Description: An advanced tool to detect hidden processes on Linux
# by analyzing CPU scheduler and comparing kernel syscalls against the /proc filesystem.
# Written by Frank Zhu <zhuzhenquan@bytedance.com>      2025.12.09

import os
import sys
import errno
import time

CONFIG_SCHED_DEBUG = "/proc/sched_debug"
CONFIG_PID_MAX = "/proc/sys/kernel/pid_max"
DEFAULT_PID_MAX = 32768

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def check_root():
    if os.geteuid() != 0:
        print(Colors.FAIL + "[-] Error: This script must be run as root." + Colors.ENDC)
        sys.exit(1)

def get_pid_max():
    try:
        with open(CONFIG_PID_MAX, "r") as f:
            return int(f.read().strip())
    except Exception:
        return DEFAULT_PID_MAX

def get_visible_pids():
    pids = set()
    if not os.path.exists("/proc"):
        return pids
    try:
        for fname in os.listdir("/proc"):
            if fname.isdigit():
                pids.add(int(fname))
    except Exception as e:
        print(Colors.WARNING + f"[-] Failed to read /proc: {e}" + Colors.ENDC)
    return pids

def check_scheduler(visible_pids):
    results = []
    print(f"[*] Analyzing kernel scheduler ({CONFIG_SCHED_DEBUG})...")

    if not os.path.exists(CONFIG_SCHED_DEBUG):
        print(Colors.WARNING + "    [-] Skipped: SCHED_DEBUG not enabled on system" + Colors.ENDC)
        return results

    sched_pids = set()
    try:
        with open(CONFIG_SCHED_DEBUG, 'r') as f:
            for line in f:
                if "PID" in line and "tree-key" in line:
                    continue

                parts = line.split()
                if len(parts) > 2 and parts[1].isdigit():
                    sched_pids.add(int(parts[1]))
    except Exception as e:
        print(Colors.WARNING + f"    [-] Parsing failed: {e}" + Colors.ENDC)
        return results

    for pid in sched_pids:
        if pid == 0: continue

        if pid not in visible_pids:
            if not os.path.exists(f"/proc/{pid}"):
                results.append({
                    'pid': pid,
                    'source': 'Scheduler Analysis',
                    'severity': 'HIGH',
                    'desc': 'Process running in scheduler but invisible in /proc (DKOM attack)'
                })

    print(f"    -> Scheduler analysis complete, found {len(results)} anomalies")
    return results

def check_bruteforce(visible_pids, max_pid):
    results = []
    print(f"[*] Executing PID brute-force enumeration (Max PID: {max_pid})...")

    for pid in range(1, max_pid + 1):
        if pid in visible_pids:
            continue

        try:
            os.kill(pid, 0)
            is_alive = True
        except OSError as err:
            if err.errno == errno.ESRCH:
                is_alive = False
            elif err.errno == errno.EPERM:
                is_alive = True
            else:
                is_alive = False

        if is_alive:
            if not os.path.exists(f"/proc/{pid}"):
                results.append({
                    'pid': pid,
                    'source': 'PID Brute-force',
                    'severity': 'MEDIUM',
                    'desc': 'Syscall kill(0) confirms existence, but /proc/{pid} is missing'
                })

    print(f"    -> Brute-force analysis complete, found {len(results)} anomalies")
    return results

def main():
    check_root()
    os.system('clear' if os.name == 'posix' else 'cls')

    print(Colors.HEADER + "="*70)
    print("                    Linux Advanced Shadow Detect")
    print("                   CPU Scheduler + PID Brute-force")
    print("="*70 + Colors.ENDC)

    max_pid = get_pid_max()
    visible_pids = get_visible_pids()

    print(f"[*] System PID Max  : {Colors.BOLD}{max_pid}{Colors.ENDC}")
    print(f"[*] Visible PIDs    : {Colors.BOLD}{len(visible_pids)}{Colors.ENDC}")
    print("-" * 70)

    findings_map = {}

    sched_results = check_scheduler(visible_pids)
    for item in sched_results:
        pid = item['pid']
        if pid not in findings_map: findings_map[pid] = []
        findings_map[pid].append(item)

    bf_results = check_bruteforce(visible_pids, max_pid)
    for item in bf_results:
        pid = item['pid']
        if pid not in findings_map: findings_map[pid] = []
        findings_map[pid].append(item)

    print("\n" + "="*70)
    print(Colors.HEADER + "                              SCAN RESULT" + Colors.ENDC)
    print("="*70)

    if not findings_map:
        print(f"\n{Colors.GREEN}[+] No hidden processes found.{Colors.ENDC}\n")
    else:
        print(f"\n{Colors.FAIL}[!] WARNING: Found {len(findings_map)} hidden process anomalies!{Colors.ENDC}\n")

        print(f"{Colors.BOLD}{'PID':<8} | {'LEVEL':<8} | {'SOURCE':<26} | {'DESCRIPTION'}{Colors.ENDC}")
        print("-" * 116)

        for pid, detections in findings_map.items():
            sources = ", ".join(set([d['source'].replace(" Analysis", "").replace(" Enumeration", "") for d in detections]))

            is_high = any(d['severity'] == 'HIGH' for d in detections)
            severity_str = "HIGH" if is_high else "MEDIUM"
            color_code = Colors.FAIL if is_high else Colors.WARNING

            desc_str = detections[0]['desc']

            print(f"{color_code}{pid:<8} | {severity_str:<8} | {sources:<20} | {desc_str}{Colors.ENDC}")

    print("="*116)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
