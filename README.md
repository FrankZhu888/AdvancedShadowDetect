# AdvancedShadowDetect
A advanced tool to detect hidden processes on Linux by checking CPU scheduler and comparing kernel syscalls against the /proc filesystem.

## Overview
Shadow Detect is a simple security tool designed for production environments where installing binary tools like unhide or rkhunter is difficult or restricted. It implements the "brute-force" detection technique to identify processes that exist in the kernel but are hidden from the system.

## Features
Zero Dependencies: Uses only the Python 3 standard library. No pip install required.

Production Safe: Does not modify system files; it only performs read operations and benign system calls.

Lightweight: Single script file, easy to audit and deploy.

Cross-Referencing: Detects discrepancies between the Kernel scheduler and the /proc filesystem.


## How it works
Linux Rootkits often hide processes by hooking system calls (like getdents) to filter specific PIDs from directory listings. This makes the malicious process invisible to standard tools like ls, ps, and top.
Shadow Detect bypasses these hooks using the following logic:

1. Brute Force PIDs: It iterates through every possible PID (from 1 to pid_max).
2. Kernel Probe: It sends a null signal kill(pid, 0) to checking if the PID is active in the kernel scheduler.
3. Diffing: If the kernel confirms the PID exists, but the corresponding directory /proc/[PID] is missing, the process is flagged as hidden.

## Usage
Prerequisites
1. Python 3.x
2. Root privileges (required to probe processes belonging to other users).

Running the tool
1. Download the script
2. Run with sudo access 

Example Output

<img width="882" height="645" alt="截屏2025-12-10 10 17 55" src="https://github.com/user-attachments/assets/489a45ec-d325-4696-92cf-456b1025eea3" />


## Support Contact

For issues or questions, contact:

Frank Zhu [flankeroot@gmail.com](mailto:flankeroot@gmail.com)  

