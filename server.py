import psutil
import pyshark
import time
from collections import defaultdict
import sys

# Optional: Color-coded output for better readability
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# Configuration
PROCESS_NAME = "cod.exe"
MONITOR_INTERVAL = 1  # seconds for each monitoring interval
DATA_RATE_THRESHOLD = 1000  # bytes per second to consider as significant traffic

def print_info(message):
    if COLORAMA_AVAILABLE:
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")
    else:
        print(f"[INFO] {message}")

def print_success(message):
    if COLORAMA_AVAILABLE:
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    else:
        print(f"[SUCCESS] {message}")

def print_warning(message):
    if COLORAMA_AVAILABLE:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
    else:
        print(f"[WARNING] {message}")

def print_error(message):
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    else:
        print(f"[ERROR] {message}")

def get_top_cpu_processes(n=10):
    """Retrieve top n processes by CPU usage."""
    processes = []
    # Initialize CPU percent for all processes
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Wait a second to get accurate CPU usage
    time.sleep(1)
    # Collect CPU usage
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            cpu = proc.cpu_percent(interval=None)
            if cpu is None:
                cpu = 0.0
            processes.append((proc.info['name'], cpu))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Get number of CPU cores
    num_cores = psutil.cpu_count()
    # Normalize CPU usage based on number of cores
    processes = [(name, cpu / num_cores) for name, cpu in processes]
    # Sort by CPU usage descending
    processes = sorted(processes, key=lambda x: x[1], reverse=True)
    # Remove duplicates while keeping the highest CPU usage
    seen = set()
    unique_processes = []
    for name, cpu in processes:
        if name.lower() not in seen:
            unique_processes.append((name, cpu))
            seen.add(name.lower())
        if len(unique_processes) >= n:
            break
    return unique_processes

def list_top_processes():
    """List top CPU consuming processes."""
    top_cpu = get_top_cpu_processes(10)
    
    combined_list = []
    print_success("\n=== Top 10 CPU Consuming Processes ===")
    if top_cpu:
        print(f"{'No.':<5}{'Process Name':<35}{'CPU Usage (%)':>15}")
        print("-" * 55)
        for idx, (name, cpu) in enumerate(top_cpu, 1):
            print(f"{idx:<5}{name:<35}{cpu:>15.1f}")
            combined_list.append(name)
    else:
        print_warning("No CPU data available.")
    
    return combined_list

def list_network_interfaces():
    """List available network interfaces sorted by total traffic (bytes sent + received)."""
    interfaces = psutil.net_io_counters(pernic=True)
    interface_traffic = {}
    for iface, counters in interfaces.items():
        total = counters.bytes_sent + counters.bytes_recv
        interface_traffic[iface] = total
    # Sort interfaces by total traffic descending
    sorted_ifaces = sorted(interface_traffic.items(), key=lambda x: x[1], reverse=True)
    
    print_success("\n=== Available Network Interfaces ===")
    print(f"{'No.':<5}{'Interface Name':<35}{'Bytes Sent':>15}{'Bytes Received':>20}{'Total Traffic':>20}")
    print("-" * 100)
    
    iface_list = []
    for idx, (iface, total) in enumerate(sorted_ifaces, 1):
        sent = interfaces[iface].bytes_sent
        recv = interfaces[iface].bytes_recv
        iface_list.append(iface)
        print(f"{idx:<5}{iface:<35}{sent:>15,}{recv:>20,}{total:>20,}")
    
    return iface_list

def get_user_selection(prompt, max_number):
    """Generic function to get user selection based on a prompt and maximum number."""
    while True:
        try:
            selection = int(input(f"\n{prompt} (1-{max_number}): ").strip())
            if 1 <= selection <= max_number:
                return selection
            else:
                print_warning(f"Please enter a number between 1 and {max_number}.")
        except ValueError:
            print_warning("Invalid input. Please enter a numeric value.")

def get_process_pids(process_name):
    """Get all PIDs for the given process name."""
    pids = []
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                pids.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids

def get_udp_ports(pid):
    """Get all local UDP ports for the given PID."""
    ports = set()
    try:
        proc = psutil.Process(pid)
        for conn in proc.net_connections(kind='udp'):
            if conn.laddr:
                ports.add(conn.laddr.port)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return ports

def monitor_udp_traffic(pid_ports, interface_name, duration):
    """Monitor UDP traffic and calculate data rates per remote connection."""
    capture_filter = "udp"
    try:
        capture = pyshark.LiveCapture(interface=interface_name, bpf_filter=capture_filter)
    except pyshark.capture.capture.TSharkCrashException:
        print_error("Failed to start packet capture. Ensure TShark is installed and accessible.")
        sys.exit(1)
    except pyshark.capture.capture.UnknownInterfaceException:
        print_error(f"Interface '{interface_name}' does not exist. Please verify the interface name.")
        sys.exit(1)

    traffic_data = defaultdict(int)
    start_time = time.time()

    print_info(f"Capturing UDP traffic on interface '{interface_name}' for {duration} second(s)...")

    try:
        for packet in capture.sniff_continuously():
            try:
                if 'UDP' in packet:
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)

                    # Check if either src_port or dst_port is in pid_ports
                    if src_port in pid_ports:
                        remote_ip = packet.ip.dst
                        remote_port = dst_port
                        traffic_data[(remote_ip, remote_port)] += len(packet)
                    elif dst_port in pid_ports:
                        remote_ip = packet.ip.src
                        remote_port = src_port
                        traffic_data[(remote_ip, remote_port)] += len(packet)
            except AttributeError:
                continue  # Ignore non-IP packets or missing attributes

            if time.time() - start_time > duration:
                break
    except KeyboardInterrupt:
        # Immediate termination upon Ctrl+C
        print("\n[WARNING] Script terminated by user.")
        sys.exit(0)
    finally:
        capture.close()

    return traffic_data

def main():
    print_info("Starting Game Server Monitoring Tool...")

    # List top CPU consuming processes
    processes = list_top_processes()

    # Allow user to select a process
    process_selection = get_user_selection("Enter the number of the process you want to monitor", len(processes))
    selected_process = processes[process_selection - 1]
    print_info(f"Selected process: {selected_process}")

    # Get PIDs of the selected process
    pids = get_process_pids(selected_process)
    if not pids:
        print_error(f"No running process found with name '{selected_process}'. Ensure the application is running.")
        sys.exit(1)

    # Aggregate all UDP ports from all PIDs
    all_ports = set()
    for pid in pids:
        ports = get_udp_ports(pid)
        all_ports.update(ports)

    if not all_ports:
        print_warning(f"No UDP ports found for '{selected_process}'. Ensure the application is actively communicating.")
        sys.exit(1)

    # List network interfaces
    interfaces = list_network_interfaces()

    # Allow user to select a network interface
    iface_selection = get_user_selection("Enter the number of the network interface you want to use", len(interfaces))
    selected_interface = interfaces[iface_selection - 1]
    print_info(f"Selected network interface: {selected_interface}")

    while True:
        # Monitor UDP traffic for the specified interval
        traffic_data = monitor_udp_traffic(all_ports, selected_interface, MONITOR_INTERVAL)

        if not traffic_data:
            print_info("No significant UDP traffic detected in this interval. Continuing to monitor...")
            continue

        # Identify the connection with the highest data transfer
        active_server = max(traffic_data, key=traffic_data.get)
        data_rate = traffic_data[active_server] / MONITOR_INTERVAL  # bytes per second

        if data_rate >= DATA_RATE_THRESHOLD:
            print_success("\n=== Active Game Server Identified ===")
            print(f"{'IP Address':<15}: {active_server[0]}")
            print(f"{'Port':<15}: {active_server[1]}")
            print(f"{'Data Rate':<15}: {data_rate:.2f} B/s")
            print("=====================================\n")
            break  # Exit the loop after identifying the server
        else:
            print_info("Detected UDP traffic below the threshold. Continuing to monitor...")

    print_info("Monitoring concluded.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ensures immediate termination upon Ctrl+C
        print("\n[WARNING] Script terminated by user.")
        sys.exit(0)
