# Process Aware Traffic Capturer (C#)

This project is a high-performance network traffic analysis tool developed in C#. Unlike standard packet sniffers, it **correlates every network packet with the specific Application (Process Name & PID) that generated it** and embeds this information directly into the **PcapNG** file as metadata (packet comments).

##  Features

*   **Process Identification:** Identifies the application name (e.g., `chrome.exe`, `discord.exe`) and PID responsible for each packet.
*   **PcapNG Metadata:** Saves captured traffic in PcapNG format and writes process information into the "Packet Comment" field, visible in Wireshark.
*   **Hybrid Architecture (High Accuracy):**
    *   **ETW (Event Tracing for Windows):** Uses Kernel-level events in Administrator mode to track millisecond-level connections with 100% accuracy.
    *   **Win32 API Fallback:** Automatically switches to "Polling Mode" if Administrator privileges are not available.
*   **Protocol Support:** Full support for TCP and UDP over **IPv4** and **IPv6**.
*   **CLI Interface:** Fully configurable via command-line arguments (Interface selection, Duration, Output path, etc.).
*   **High Performance:** Uses a multithreaded (Producer-Consumer) architecture to minimize packet drops under heavy load.

##  Prerequisites

To build and run this tool, you need:

1.  **.NET 6.0** SDK or later.
2.  **Npcap Driver:** Comes with Wireshark or can be downloaded [here](https://npcap.com/).
    *   *Ensure "Install Npcap in WinPcap API-compatible Mode" is checked during installation.*
3.  **Administrator Privileges:** Recommended for ETW (Real-time tracking) features.


## Usage
The application runs via command-line arguments.

Basic Commands
### Show help menu
ProCess.exe -h

### List available network interfaces
ProCess.exe -i

### Listen on a specific interface (e.g., index 1) for 60 seconds
ProCess.exe -i 1 -t 60

### Save to a specific path and show live details (Verbose)
ProCess.exe -i 1 -t 300 -o "C:\Logs\capture.pcapng" -v
Arguments
Argument	Short	Description	Default
--interface	-i	Index of the network interface to listen on. Lists interfaces if omitted.	-
--time	-t	Capture duration in seconds.	30
--output	-o	Path for the output PcapNG file.	capture.pcapng
--promiscuous	-p	Enables Promiscuous mode (Captures all traffic on the wire).	Disabled
--verbose	-v	Prints captured packet details to the console in real-time.	Disabled
--help	-h	Shows the help screen.	-
## Viewing in Wireshark
To see the Process Name and PID in Wireshark:
Open the generated .pcapng file in Wireshark.
Right-click on the column headers in the packet list -> Column Preferences.
Add a new column (+).
Set Type to "Custom".
Set Fields to pkt_comment (or frame.comment).
You will now see descriptions like chrome.exe (PID: 1240) next to each packet.
<img width="1915" height="1034" alt="image" src="https://github.com/user-attachments/assets/c76da1ca-341d-41d8-9dca-f496cdf525a0" />

