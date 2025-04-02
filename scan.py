from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
from scapy.layers.inet import IP, ICMP, TCP
from scapy.arch.windows import get_windows_if_list
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
import argparse
import time
import os
import ctypes
import sys
import threading
import subprocess
import ipaddress

# Check for admin privileges
if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
    print("ERROR: This script requires Administrator privileges!")
    time.sleep(2)
    sys.exit(1)

console = Console()
networks = {}
clients = {}
stop_event = threading.Event()

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Wi-Fi Network Scanner for Windows")
    parser.add_argument("-i", "--interface", help="Network interface name")
    parser.add_argument("-c", "--channel", type=int, help="Specific channel to scan")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                      help="Scanning duration in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

def get_wifi_interface(user_interface=None):
    interfaces = get_windows_if_list()
    wlan_ifaces = [iface for iface in interfaces
                  if 'wireless' in iface['name'].lower() or 'wi-fi' in iface['name'].lower()]

    if user_interface:
        for iface in wlan_ifaces:
            if iface['name'].lower() == user_interface.lower():
                return iface['name']
        console.print(f"[red]Error: Interface {user_interface} not found![/red]")
        return None

    if not wlan_ifaces:
        console.print("[red]No wireless interfaces found![/red]")
        console.print("[yellow]Available interfaces:[/yellow]")
        for iface in interfaces:
            console.print(f"- [cyan]{iface['name']}[/cyan] (Driver: {iface['driver']})")
        return None

    return wlan_ifaces[0]['name']

def channel_operations(interface, args):
    channels = [args.channel] if args.channel else [1, 6, 11]
    console.print(f"\n[bold]Starting channel operations on {interface}[/bold]", style="yellow")

    try:
        for channel in channels:
            result = os.system(f'netsh wlan set channel channel={channel} interface="{interface}"')
            if args.debug:
                if result == 0:
                    console.print(f"  ✓ Locked to channel {channel}", style="green")
                else:
                    console.print(f"  × Failed to set channel {channel}", style="red")
            time.sleep(1)
            if stop_event.is_set():
                break
    except Exception as e:
        console.print(f"[red]Channel error: {e}[/red]")

def process_packet(pkt, args):
    try:
        if pkt.haslayer(Dot11):
            # Beacon frames (network discovery)
            if pkt.type == 0 and pkt.subtype == 8:
                bssid = pkt.addr2
                ssid = pkt[Dot11Elt][0].info.decode(errors='ignore') or "<hidden>"

                try:
                    channel = int(ord(pkt[Dot11Elt][2].info))
                except (IndexError, TypeError):
                    channel = "N/A"

                dbm_signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else None

                encryption = "Open"
                for elt in pkt[Dot11Elt]:
                    if elt.ID == 48:  # RSN Information Element
                        encryption = "WPA2"
                        break
                    elif elt.ID == 221 and b'WPA' in elt.info:
                        encryption = "WPA"
                        break

                networks[bssid] = {
                    'ssid': ssid,
                    'channel': channel,
                    'signal': dbm_signal,
                    'encryption': encryption,
                    'last_seen': time.time()
                }

                if args.debug:
                    console.print(f"Found: [bold]{ssid}[/bold] ({bssid}) | Ch{channel} | {dbm_signal}dBm | {encryption}")

            # Data frames (client discovery)
            elif pkt.type == 2:
                if pkt.addr1 and pkt.addr1 != 'ff:ff:ff:ff:ff:ff':
                    if pkt.addr1 not in clients:
                        clients[pkt.addr1] = {
                            'bssid': pkt.addr2,
                            'last_seen': time.time()
                        }

    except Exception as e:
        if args.debug:
            console.print(f"[red]Packet error: {e}[/red]")

def print_network_results():
    table = Table(title="Wi-Fi Networks", show_lines=True)
    table.add_column("#", style="bold")
    table.add_column("BSSID", style="cyan")
    table.add_column("SSID", style="magenta")
    table.add_column("Channel", style="green")
    table.add_column("Signal (dBm)", style="yellow")
    table.add_column("Encryption", style="blue")

    for i, (bssid, data) in enumerate(sorted(networks.items(),
                            key=lambda x: x[1]['signal'] or -100,
                            reverse=True), 1):
        table.add_row(
            str(i),
            bssid,
            data['ssid'],
            str(data['channel']),
            str(data['signal']) if data['signal'] else "N/A",
            data['encryption']
        )

    console.print(table)

def scan_network_devices(target_network):
    console.print(f"\n[bold]Scanning devices on network: {target_network}[/bold]")

    # Get local IP and subnet
    local_ip = subprocess.check_output("ipconfig | findstr IPv4", shell=True).decode().split(":")[1].strip()
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)

    # Ping sweep
    live_hosts = []
    for host in network.hosts():
        if stop_event.is_set():
            break
        host = str(host)
        try:
            res = subprocess.call(['ping', '-n', '1', '-w', '500', host],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res == 0:
                live_hosts.append(host)
                console.print(f"  [green]✓ {host} is alive[/green]")
        except:
            pass

    return live_hosts

def scan_ports(target_ip):
    console.print(f"\n[bold]Scanning ports on {target_ip}[/bold]")
    open_ports = []

    # Common ports to scan
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]

    for port in ports:
        if stop_event.is_set():
            break
        try:
            pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
            res = sr1(pkt, timeout=1, verbose=0)
            if res and res.haslayer(TCP) and res[TCP].flags == 0x12:
                open_ports.append(port)
                console.print(f"  [green]✓ Port {port} is open[/green]")
        except:
            pass

    return open_ports

def brute_force_wifi(target_bssid, password_file="passwords.txt"):
    if not os.path.exists(password_file):
        console.print(f"[red]Error: Password file {password_file} not found![/red]")
        return False

    console.print(f"\n[bold]Attempting brute force on {target_bssid}[/bold]")

    with open(password_file, 'r') as f:
        passwords = f.read().splitlines()

    for password in passwords:
        if stop_event.is_set():
            break
        console.print(f"  Trying: {password}")
        # This is a simulation - actual brute forcing requires more complex setup
        # In real world, you'd use tools like aircrack-ng

    return False

def interactive_menu():
    console.print("\n[bold]Select an option:[/bold]")
    console.print("1. Scan all connected devices on selected network")
    console.print("2. Scan all open ports on selected device")
    console.print("3. Brute force WiFi password (requires password file)")
    console.print("4. Exit")

    choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4"])
    return choice

def main():
    args = parse_args()

    # Windows-specific Scapy configuration
    conf.use_pcap = False
    conf.use_winpcapy = True

    # Interface detection
    interface = get_wifi_interface(args.interface)
    if not interface:
        return

    console.print(f"\n[bold green]Starting scan on {interface}[/bold green]")

    # Channel setup
    if args.channel:
        channel_operations(interface, args)
    else:
        hopper = threading.Thread(target=channel_operations, args=(interface, args))
        hopper.daemon = True
        hopper.start()

    # Packet capture
    try:
        sniff(iface=interface,
             prn=lambda pkt: process_packet(pkt, args),
             timeout=args.timeout,
             store=0,
             L3socket=conf.L3socket)
    except Exception as e:
        console.print(f"[red]Capture error: {e}[/red]")
    finally:
        stop_event.set()

    # Results
    console.print(f"\n[bold]Scan completed! Found {len(networks)} networks:[/bold]")
    print_network_results()

    # Network selection
    if not networks:
        return

    selected = Prompt.ask("Select a network (number)", choices=[str(i) for i in range(1, len(networks)+1)])
    selected_bssid = list(networks.keys())[int(selected)-1]
    selected_network = networks[selected_bssid]

    while True:
        choice = interactive_menu()

        if choice == "1":
            live_hosts = scan_network_devices(selected_network['ssid'])
            if live_hosts:
                console.print("\n[bold]Live hosts:[/bold]")
                for host in live_hosts:
                    console.print(f"  - {host}")

        elif choice == "2":
            target_ip = Prompt.ask("Enter target IP to scan")
            open_ports = scan_ports(target_ip)
            if open_ports:
                console.print("\n[bold]Open ports:[/bold]")
                for port in open_ports:
                    console.print(f"  - {port}")

        elif choice == "3":
            if selected_network['encryption'] == "Open":
                console.print("[yellow]Network is open - no password needed![/yellow]")
            else:
                brute_force_wifi(selected_bssid)

        elif choice == "4":
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Scan aborted by user![/red]")
        stop_event.set()
        sys.exit(0)
