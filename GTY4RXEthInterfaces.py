import subprocess
import threading
import time
import re
from collections import defaultdict
from datetime import datetime

#Working code to receive UDP packets on each of four channels and save them into files
# Define each channel: interface + optional IP filter + output file
channels = [
    {"interface": "enp1s0f0np0", "ip": "169.254.83.159", "file": "/home/radarskinpc/Documents/Data/Compression/Test7/udp_capture0.txt"},
    {"interface": "enp1s0f1np1", "ip": "169.254.161.244", "file": "/home/radarskinpc/Documents/Data/Compression/Test7/udp_capture1.txt"},
    {"interface": "enp1s0f2np2", "ip": "169.254.115.124", "file": "/home/radarskinpc/Documents/Data/Compression/Test7/udp_capture2.txt"},
    {"interface": "enp1s0f3np3", "ip": "169.254.199.168", "file": "/home/radarskinpc/Documents/Data/Compression/Test7/udp_capture3.txt"},
]



def capture_udp_from_interface(interface, ip_filter, output_file, duration=10):
    """
    Captures UDP packets, writes to file, and prints packet stats.
    """
    cmd = [
        "sudo", "tcpdump",
        "-l",                  # Line buffered for real-time reading
        "-i", interface,
        "-n",
        "-s", "0",
        "-XX",
        "udp"
    ]

    if ip_filter:
        cmd += ["and", "host", ip_filter]

    print(f"[INFO] Starting capture on {interface} (IP filter: {ip_filter}) → {output_file}")

    packet_count = 0
    total_bytes = 0
    pps = defaultdict(int)  # {timestamp (HH:MM:SS): count}

    try:
        with open(output_file, "w") as f:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            start_time = time.time()
            while True:
                line = proc.stdout.readline()
                if not line:
                    break

                f.write(line)
                line = line.strip()

                # Match start of packet with timestamp
                ts_match = re.match(r'^(\d{2}:\d{2}:\d{2})\.\d+', line)
                if ts_match:
                    packet_count += 1
                    ts_key = ts_match.group(1)
                    pps[ts_key] += 1

                # Match hex lines like: 0x0000:  45 00 ...
                if re.match(r'^0x[0-9a-f]+:', line):
                    hex_data = line.split(':', 1)[1].strip().split()
                    hex_bytes = [b for b in hex_data if re.match(r'^[0-9a-fA-F]{2}$', b)]
                    total_bytes += len(hex_bytes)

                if time.time() - start_time > duration:
                    break

            proc.terminate()

        print(f"\n[STATS] Interface: {interface}")
        print(f"        Total packets captured: {packet_count}")
        print(f"        Total bytes captured:   {total_bytes}")
        if packet_count > 0:
            print(f"        Avg packet size:        {total_bytes // packet_count} bytes")

        print(f"\n[PACKETS PER SECOND]:")
        for ts in sorted(pps):
            print(f"        {ts} → {pps[ts]} packets")
        print("-" * 50)

    except Exception as e:
        print(f"[ERROR] Failed to capture on {interface}: {e}")


def main():
    threads = []
    for ch in channels:
        t = threading.Thread(
            target=capture_udp_from_interface,
            args=(ch["interface"], ch["ip"], ch["file"], 10)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
