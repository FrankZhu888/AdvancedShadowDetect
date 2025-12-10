# AdvancedShadowDetect
An advanced tool to detect hidden processes on Linux by analyzing the CPU scheduler and performing syscall brute-forcing.

## Overview
AdvancedShadowDetect is a lightweight, dependency-free security tool designed for Linux production environments where installing binary tools (like unhide or rkhunter) is restricted or impractical.

Unlike traditional tools that rely solely on system calls, this tool implements a Dual-Engine Detection Strategy: it combines Kernel Scheduler Analysis with PID Brute-forcing to identify sophisticated hidden processes (Rootkits). It is specifically designed to catch advanced threats that employ techniques like DKOM (Direct Kernel Object Manipulation) to unlink themselves from the standard process list while remaining active in the CPU queue.

## Features
- **Zero Dependencies**: Written in pure Python 3 using only the standard library. No pip install required.

- **Deep Detection**: Capable of detecting DKOM attacks by inspecting the kernel scheduler, in addition to standard syscall hooking.

- **Production Safe**: Does not modify system files; operates strictly via read-only operations and benign system signal checks.

- **Lightweight & Portable**: Single script file, easy to audit, deploy, and run in isolated environments.


## How it works
Linux Rootkits typically hide processes using two main methods:

1. Syscall Hooking: Intercepting system calls (like getdents) to filter specific PIDs from directory listings.
2. DKOM (Direct Kernel Object Manipulation): Removing the malicious process from the kernel's process linked list (tasks list), making it invisible to tools like ps or top.

AdvancedShadowDetect bypasses these mechanisms using the following two strategies:

1. Scheduler Analysis (The "Anti-DKOM" Method)

Even if a process removes itself from the process list (DKOM), it must remain in the CPU Scheduler's runqueue to be executed.

Mechanism: The script parses /proc/sched_debug (a view into the scheduler's state provided by CONFIG_SCHED_DEBUG).

Logic: It extracts PIDs directly from the scheduler's runqueue and cross-references them with the /proc filesystem.
Detection: If a PID is running in the scheduler but is missing from /proc, it is flagged as a high-severity hidden process.

2. PID Brute-force (The "Anti-Hook" Method)

To catch rootkits that simply hide directories but leave the process structure intact:

Mechanism: The script iterates through the entire PID space (from 1 to pid_max).

Logic: It sends a null signal kill(pid, 0) to every potential PID. This system call checks if a process exists in the kernel without affecting it.

Detection: If the kernel returns "Success" (Process exists) or "Permission Denied" (Process exists but owned by another user), but the corresponding /proc/[PID] directory is invisible, it is flagged as a hidden process.

## Usage
Prerequisites
1. Python 3.x
2. Root privileges (Required to inspect the scheduler and probe processes belonging to other users)

Running the tool
1. Download the script
2. Run with sudo access 

Example Output

<img width="882" height="645" alt="截屏2025-12-10 10 17 55" src="https://github.com/user-attachments/assets/489a45ec-d325-4696-92cf-456b1025eea3" />

## Disclaimer

This tool is for detection and forensics purposes only. It does not attempt to kill or remove the rootkit, as doing so on a compromised kernel can lead to system instability. If a hidden process is found, it is recommended to isolate the machine and perform offline memory forensics.

## Support Contact

For issues or questions, contact:

Frank Zhu [flankeroot@gmail.com](mailto:flankeroot@gmail.com)  

