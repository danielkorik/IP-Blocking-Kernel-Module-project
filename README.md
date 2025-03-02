# IP-Blocking-Kernel-Module-project
This project is a Linux kernel module that intercepts network packets, logs their source IP addresses, and blocks IPs based on SYN/RST packet counts and total packet volume.It is designed to enhance network security by detecting and mitigating potential threats.

## Features
- **Packet Logging**: Logs the source IP address, SYN count, RST count, and total packet count for each intercepted packet.
- **IP Blocking**: Blocks IP addresses that exceed a specified threshold for SYN/RST packets or total packet volume.
- **Dynamic Blocking**: Blocks IPs for a configurable duration (default: 1 minute).

## Prerequisites
- **Linux Environment**: A Linux system with kernel headers installed.
- **Compiler Tools**: GCC, make, and other essential build tools.
- **Root Access**: Required to load and unload kernel modules.

## How to Run

1. Clone the Repository:
   bash
   git clone https://github.com/your-username/ip-blocking-module.git
   cd ip-blocking-module]

2. Compile the Module: 
   make

3. Load the Module:
   sudo insmod blovk-ip-module.ko

4. Generate Network Traffic:
   ping website.com

5. Check Kernel Logs:
   dmesg | tail

6. Unload the Module:
   sudo rmmod block-ip-module

7. Clean Up:
   make clean

## Configuration
You can modify the following constants in the block-ip-module.c file to customize the module's behavior:

MAX_PACKETS: Maximum packet count threshold (default: 50).

OBSERVATION_PERIOD: Time window for counting packets (default: 30 seconds).

BLOCK_DURATION: Duration to block an IP (default: 1 minute).

MAX_SYN_RST_COUNT: Threshold for SYN or RST counts to block (default: 5).

## Screenshot

![image](https://github.com/user-attachments/assets/2b4c58ce-e244-4321-935b-6f03a2efc34a)

## License
This project is licensed under the GPL License. See the LICENSE file for details.

