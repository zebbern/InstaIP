import time, sys, signal, psutil, pyperclip
from scapy.all import sniff, UDP, IP
from collections import defaultdict
from colorama import init, Fore, Style

init(autoreset=True)

INTERVAL = 1
THRESHOLD = 250
LOG = 'udp_monitor_log.txt'
TARGET_PROCS = {'cod.exe'}

def cprint(msg, color='green'):
    colors = {'green': Fore.GREEN, 'cyan': Fore.CYAN, 'yellow': Fore.YELLOW, 'red': Fore.RED}
    print(f"{colors.get(color, Fore.WHITE)}{msg}{Style.RESET_ALL}")

def log_line(txt):
    with open(LOG, 'a', encoding='utf-8') as f: 
        f.write(txt + "\n")

def run_start():
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line("\n=====================================")
    log_line(f"=== RUN START: {t} ===")
    log_line("=====================================")

def run_end():
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line("=====================================")
    log_line(f"=== RUN END: {t} ===")
    log_line("=====================================")

def sigint_handler(sig, frame):
    run_end()
    cprint("\nMonitoring canceled by user.\n", 'red')
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

def get_ports(proc_names):
    ports = set()
    pnames = {n.lower() for n in proc_names}
    for p in psutil.process_iter(['name']):
        try:
            if p.info['name'] and p.info['name'].lower() in pnames:
                for c in p.net_connections(kind='udp'):
                    if c.laddr and c.laddr.port:
                        ports.add(c.laddr.port)
        except:
            pass
    return ports

def get_interface():
    ifaces = psutil.net_io_counters(pernic=True)
    if not ifaces: 
        cprint("No network interfaces found.", 'red')
        sys.exit(1)
    return max(ifaces, key=lambda i: ifaces[i].bytes_sent + ifaces[i].bytes_recv)

def sniff_udp(tports, iface, dur):
    data = defaultdict(int)
    def cb(pkt):
        if UDP in pkt and IP in pkt:
            l = len(pkt)
            s_ip, d_ip = pkt[IP].src, pkt[IP].dst
            s_pt, d_pt = pkt[UDP].sport, pkt[UDP].dport
            if s_pt in tports: data[(d_ip, d_pt)] += l
            elif d_pt in tports: data[(s_ip, s_pt)] += l
    flt = " or ".join(f"udp port {p}" for p in tports) if tports else "udp port 0"
    sniff(filter=flt, prn=cb, timeout=dur, iface=iface, store=False)
    return data

def report(d, seen, sec, thr):
    for (ip, port), bcount in d.items():
        rate = bcount / sec
        if rate >= thr and (ip, port) not in seen:
            t = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Copy to clipboard, e.g.,: udp 12.34.56.78 120 dport=1234
            clip_text = f"udp {ip} 120 dport={port}"
            pyperclip.copy(clip_text)

            if port == 44998:
                cprint("=====================================", 'red')
                cprint("Rotating IP found", 'red')
                cprint(f"IP Address   : {ip}", 'yellow')
                cprint(f"Port         : {port}", 'yellow')
                cprint(f"Data Rate    : {rate:.2f} B/s", 'green')
                cprint("=====================================", 'red')
                log_line(f"{t} | Rotating IP found | IP={ip}, Port={port}, Rate={rate:.2f} B/s")
            else:
                cprint("=====================================", 'green')
                cprint("=== Live Game Session Found ===", 'cyan')
                cprint(f"IP Address   : {ip}", 'yellow')
                cprint(f"Port         : {port}", 'yellow')
                cprint(f"Data Rate    : {rate:.2f} B/s", 'green')
                cprint("=====================================", 'green')
                log_line(f"{t} | Live Game Session Found | IP={ip}, Port={port}, Rate={rate:.2f} B/s")

            seen.add((ip, port))

def main():
    cprint("Starting UDP Traffic Monitor...", 'green')
    run_start()
    iface = get_interface()
    seen = set()
    while True:
        tports = get_ports(TARGET_PROCS)
        if not tports:
            cprint("No target UDP ports found for specified processes.", 'yellow')
            time.sleep(INTERVAL)
            continue
        data = sniff_udp(tports, iface, INTERVAL)
        report(data, seen, INTERVAL, THRESHOLD)

if __name__ == "__main__":
    main()
