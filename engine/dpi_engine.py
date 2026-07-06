import sys
import time
import os
import json
import argparse
import threading
import urllib.request
import urllib.error
from scapy.all import IP, TCP, UDP, Ether

# Define simulated server IPs for mock data
IP_MOCK_MAP = {
    "142.250.190.46": "google.com",
    "172.217.16.14": "youtube.com",
    "157.240.22.35": "facebook.com",
    "140.82.112.4": "github.com",
    "52.84.18.15": "amazon.com",
    "23.45.67.89": "netflix.com"
}

# Global flow dictionary
active_flows = {}

# Global stats counters
total_packets_counter = 0
total_blocked_counter = 0
app_counts = {}
running = True

# Paths to rules and stats configuration
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stats.json")

def load_rules():
    default_rules = {
        "blocked_ips": [],
        "blocked_domains": [],
        "blocked_apps": []
    }
    if not os.path.exists(RULES_FILE):
        try:
            os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
            with open(RULES_FILE, "w") as f:
                json.dump(default_rules, f, indent=2)
        except Exception:
            return default_rules
            
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return default_rules

def write_stats_file(stats):
    """
    Writes stats atomically using a temp file and rename.
    """
    tmp_file = STATS_FILE + ".tmp"
    try:
        with open(tmp_file, "w") as f:
            json.dump(stats, f, indent=2)
        os.replace(tmp_file, STATS_FILE)
    except Exception as e:
        print(f"[!] Error writing stats file: {e}")

def check_blocked(src_ip, dst_ip, sni, app, rules):
    blocked_ips = rules.get("blocked_ips", [])
    blocked_domains = rules.get("blocked_domains", [])
    blocked_apps = rules.get("blocked_apps", [])
    
    if src_ip in blocked_ips or dst_ip in blocked_ips:
        blocked_ip = src_ip if src_ip in blocked_ips else dst_ip
        return True, f"IP blocked ({blocked_ip})"
        
    if sni:
        sni_lower = sni.lower()
        for domain in blocked_domains:
            domain_lower = domain.lower()
            if domain_lower in sni_lower:
                return True, f"Domain blocked ({domain})"
                
    if app:
        app_lower = app.lower()
        for blocked_app in blocked_apps:
            if blocked_app.lower() == app_lower:
                return True, f"App blocked ({blocked_app})"
                
    return False, None

def get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    if src_ip < dst_ip:
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    elif src_ip > dst_ip:
        return (dst_ip, src_ip, dst_port, src_port, protocol)
    else:
        if (src_port or 0) <= (dst_port or 0):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)

def create_tls_client_hello(domain):
    domain_bytes = domain.encode('utf-8')
    domain_len = len(domain_bytes)
    
    sni_ext = (
        b'\x00\x00' + 
        (domain_len + 5).to_bytes(2, byteorder='big') +
        (domain_len + 3).to_bytes(2, byteorder='big') +
        b'\x00' +
        domain_len.to_bytes(2, byteorder='big') +
        domain_bytes
    )
    
    extensions = (len(sni_ext)).to_bytes(2, byteorder='big') + sni_ext
    ch_body = (
        b'\x03\x03' + 
        b'\x00' * 32 + 
        b'\x00' + 
        b'\x00\x02\x00\x2f' + 
        b'\x01\x00' + 
        extensions
    )
    
    hs_header = b'\x01' + len(ch_body).to_bytes(3, byteorder='big')
    hs_data = hs_header + ch_body
    record_header = b'\x16\x03\x01' + len(hs_data).to_bytes(2, byteorder='big')
    return record_header + hs_data

def generate_mock_packet(index):
    src_ip = "192.168.1.50"
    step_mapping = {
        0: {"dst_ip": "142.250.190.46", "proto": "TCP", "port": 443, "sni": "google.com"},
        1: {"dst_ip": "172.217.16.14", "proto": "TCP", "port": 80, "payload": b"GET / HTTP/1.1\r\nHost: youtube.com\r\n\r\n"},
        2: {"dst_ip": "157.240.22.35", "proto": "TCP", "port": 443, "sni": "facebook.com"},
        3: {"dst_ip": "8.8.8.8", "proto": "UDP", "port": 53},
        4: {"dst_ip": "23.45.67.89", "proto": "TCP", "port": 443, "sni": "netflix.com"},
        5: {"dst_ip": "140.82.112.4", "proto": "TCP", "port": 22},
        6: {"dst_ip": "52.84.18.15", "proto": "TCP", "port": 443, "sni": "amazon.com"},
        7: {"dst_ip": "1.1.1.1", "proto": "UDP", "port": 53},
        8: {"dst_ip": "157.240.22.35", "proto": "TCP", "port": 443, "sni": "facebook.com"},
        9: {"dst_ip": "142.250.190.46", "proto": "TCP", "port": 80, "payload": b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"}
    }
    
    conf = step_mapping.get(index % 10)
    dst_ip = conf["dst_ip"]
    proto = conf["proto"]
    port = conf["port"]
    
    sport = 55000 + (index % 10 if index % 10 != 8 else 2)
    
    if proto == "TCP":
        if "sni" in conf:
            tls_payload = create_tls_client_hello(conf["sni"])
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=port)/tls_payload
        elif "payload" in conf:
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=port)/conf["payload"]
        else:
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=port)
    else:
        pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=port)
        
    return pkt

def extract_sni(payload):
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    if len(payload) < 9 or payload[5] != 0x01:
        return None
    idx = 43
    if len(payload) < idx + 1:
        return None
    session_id_len = payload[idx]
    idx += 1 + session_id_len
    if len(payload) < idx + 2:
        return None
    cipher_suites_len = int.from_bytes(payload[idx:idx+2], byteorder='big')
    idx += 2 + cipher_suites_len
    if len(payload) < idx + 1:
        return None
    compression_methods_len = payload[idx]
    idx += 1 + compression_methods_len
    if len(payload) < idx + 2:
        return None
    extensions_len = int.from_bytes(payload[idx:idx+2], byteorder='big')
    idx += 2
    extensions_end = idx + extensions_len
    if extensions_end > len(payload):
        extensions_end = len(payload)
    while idx + 4 <= extensions_end:
        ext_type = int.from_bytes(payload[idx:idx+2], byteorder='big')
        ext_len = int.from_bytes(payload[idx+2:idx+4], byteorder='big')
        idx += 4
        if ext_type == 0: # SNI
            if idx + ext_len <= extensions_end:
                sni_idx = idx
                if sni_idx + 2 <= idx + ext_len:
                    sni_list_len = int.from_bytes(payload[sni_idx:sni_idx+2], byteorder='big')
                    sni_idx += 2
                    while sni_idx + 3 <= idx + ext_len:
                        name_type = payload[sni_idx]
                        name_len = int.from_bytes(payload[sni_idx+1:sni_idx+3], byteorder='big')
                        sni_idx += 3
                        if name_type == 0: # Host Name
                            if sni_idx + name_len <= idx + ext_len:
                                return payload[sni_idx:sni_idx+name_len].decode('utf-8', errors='ignore')
                        sni_idx += name_len
            break
        idx += ext_len
    return None

def classify_app(sni, protocol, dport):
    if sni:
        sni_lower = sni.lower()
        if "youtube.com" in sni_lower or "googlevideo.com" in sni_lower:
            return "YouTube"
        elif "facebook.com" in sni_lower or "fbcdn.net" in sni_lower or "messenger.com" in sni_lower:
            return "Facebook"
        elif "google.com" in sni_lower or "gmail.com" in sni_lower or "googleapis.com" in sni_lower:
            return "Google"
        elif "github.com" in sni_lower or "githubusercontent.com" in sni_lower:
            return "GitHub"
        elif "netflix.com" in sni_lower or "nflxso.net" in sni_lower or "nflxvideo.net" in sni_lower:
            return "Netflix"
        elif "amazon.com" in sni_lower or "amazonaws.com" in sni_lower:
            return "Amazon"
        else:
            return f"Web ({sni})"
            
    if protocol == "TCP":
        if dport == 80 or dport == 8080:
            return "HTTP Web"
        elif dport == 22:
            return "SSH"
        elif dport == 443:
            return "Generic HTTPS"
        else:
            return f"TCP ({dport})"
    elif protocol == "UDP":
        if dport == 53:
            return "DNS"
        else:
            return f"UDP ({dport})"
            
    return protocol or "Unknown"

def track_packet(pkt, rules=None):
    """
    Main flow tracking entry point. Updates global stats counters and active flows.
    """
    global total_packets_counter, total_blocked_counter, app_counts
    
    if rules is None:
        rules = load_rules()
        
    tuple_5 = parse_5_tuple(pkt)
    if not tuple_5:
        return None
        
    src_ip, dst_ip, src_port, dst_port, protocol = tuple_5
    flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
    
    # Try to parse SNI if TCP port 443
    sni = None
    if protocol == "TCP" and (dst_port == 443 or src_port == 443):
        payload = bytes(pkt[TCP].payload)
        if payload:
            sni = extract_sni(payload)
            
    app = classify_app(sni, protocol, dst_port if dst_port == 443 or src_port != 443 else src_port)
    
    pkt_len = len(pkt)
    
    # Perform blocking evaluation
    is_blocked, block_reason = check_blocked(src_ip, dst_ip, sni, app, rules)
    
    # Increment global stats
    total_packets_counter += 1
    if is_blocked:
        total_blocked_counter += 1
        
    # Increment app counts
    app_counts[app] = app_counts.get(app, 0) + 1
    
    if flow_key in active_flows:
        # Update existing flow
        flow = active_flows[flow_key]
        flow["packet_count"] += 1
        flow["byte_count"] += pkt_len
        flow["last_seen"] = time.time()
        
        # If we got a new classification/SNI, update it
        if sni and not flow["sni"]:
            flow["sni"] = sni
            flow["app"] = app
            
        # Re-evaluate blocking
        if is_blocked and not flow["blocked"]:
            flow["blocked"] = True
            flow["block_reason"] = block_reason
            print(f"[BLOCK ALERT] Flow {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({app}) BLOCKED: {block_reason}")
    else:
        # Initialize new flow
        active_flows[flow_key] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "app": app,
            "sni": sni,
            "packet_count": 1,
            "byte_count": pkt_len,
            "blocked": is_blocked,
            "block_reason": block_reason,
            "first_seen": time.time(),
            "last_seen": time.time()
        }
        if is_blocked:
            print(f"[BLOCK ALERT] Flow {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({app}) BLOCKED: {block_reason}")
        
    return flow_key

def parse_5_tuple(pkt):
    if IP not in pkt:
        return None
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto_num = pkt[IP].proto
    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        protocol = "TCP"
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        protocol = "UDP"
    else:
        src_port = None
        dst_port = None
        if proto_num == 1:
            protocol = "ICMP"
        else:
            protocol = f"IP-proto-{proto_num}"
    return (src_ip, dst_ip, src_port, dst_port, protocol)

def stats_exporter_thread():
    """
    Background loop that aggregates and writes stats to stats.json every 1s.
    """
    global running, total_packets_counter, total_blocked_counter, app_counts, active_flows
    
    last_packets = 0
    last_blocked = 0
    
    print("[*] Stats Exporter thread started.")
    
    while running:
        time.sleep(1.0)
        
        # Calculate rates
        total_pkts = total_packets_counter
        total_blkd = total_blocked_counter
        
        pkts_sec = total_pkts - last_packets
        blkd_sec = total_blkd - last_blocked
        
        last_packets = total_pkts
        last_blocked = total_blkd
        
        # Format top apps
        top_apps = sorted(
            [{"app": app, "packets": count} for app, count in app_counts.items()],
            key=lambda x: x["packets"],
            reverse=True
        )[:5]
        
        # Format recent flows
        recent_flows = []
        sorted_flows = sorted(active_flows.values(), key=lambda x: x["last_seen"], reverse=True)[:15]
        for f in sorted_flows:
            recent_flows.append({
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "src_port": f["src_port"],
                "dst_port": f["dst_port"],
                "protocol": f["protocol"],
                "app": f["app"],
                "sni": f["sni"] or "",
                "packet_count": f["packet_count"],
                "byte_count": f["byte_count"],
                "blocked": f["blocked"],
                "block_reason": f.get("block_reason") or ""
            })
            
        stats_payload = {
            "timestamp": time.time(),
            "packets_per_sec": pkts_sec,
            "blocked_per_sec": blkd_sec,
            "total_packets": total_pkts,
            "total_blocked": total_blkd,
            "top_apps": top_apps,
            "active_flows_count": len(active_flows),
            "recent_flows": recent_flows
        }
        
        write_stats_file(stats_payload)
        print(f"[STATS] Writing to stats.json: {json.dumps(stats_payload)}")

        # Synchronize with backend API (local or remote)
        backend_url = os.environ.get("DPI_BACKEND_URL") or os.environ.get("VITE_BACKEND_URL") or "http://localhost:5000"
        
        # 1. Push stats to backend
        try:
            stats_json_data = json.dumps(stats_payload).encode('utf-8')
            req = urllib.request.Request(
                f"{backend_url.rstrip('/')}/api/stats",
                data=stats_json_data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=1.0) as response:
                pass
        except Exception:
            pass

        # 2. Pull rules from backend dynamically
        try:
            req = urllib.request.Request(
                f"{backend_url.rstrip('/')}/api/rules",
                method='GET'
            )
            with urllib.request.urlopen(req, timeout=1.0) as response:
                rules_data = json.loads(response.read().decode('utf-8'))
                if rules_data and isinstance(rules_data, dict):
                    # Write pulled rules to local rules.json file atomically
                    tmp_rules = RULES_FILE + ".tmp"
                    with open(tmp_rules, "w") as f:
                        json.dump(rules_data, f, indent=2)
                    os.replace(tmp_rules, RULES_FILE)
        except Exception:
            pass

def step1_sniffer(use_mock=False):
    print(f"[*] Starting Step 1 Sniffer (use_mock={use_mock})...")
    packets_to_sniff = 10
    if not use_mock:
        try:
            from scapy.all import sniff
            def packet_callback(pkt):
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    if TCP in pkt:
                        print(f"Live TCP Packet: {src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport}")
                    elif UDP in pkt:
                        print(f"Live UDP Packet: {src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport}")
            sniff(count=packets_to_sniff, prn=packet_callback, timeout=10)
            return
        except RuntimeError:
            use_mock = True
    if use_mock:
        for i in range(packets_to_sniff):
            pkt = generate_mock_packet(i)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else "-")
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else "-")
            print(f"Mock Packet [{i+1}/10]: {src_ip}:{sport} -> {dst_ip}:{dport}")
            time.sleep(0.1)

def step2_parse_5_tuple(use_mock=False):
    print(f"[*] Starting Step 2 5-Tuple Parser (use_mock={use_mock})...")
    packets_to_sniff = 10
    def process_packet(pkt, idx, is_live=True):
        tuple_5 = parse_5_tuple(pkt)
        if tuple_5:
            src_ip, dst_ip, src_port, dst_port, protocol = tuple_5
            print(f"[{'Live' if is_live else 'Mock'} Packet {idx}/10] Proto: {protocol:4s} | {src_ip}:{src_port or '-'} -> {dst_ip}:{dst_port or '-'}")
    if not use_mock:
        try:
            from scapy.all import sniff
            state = {"count": 0}
            sniff(count=packets_to_sniff, prn=lambda p: [state.update({"count": state["count"]+1}), process_packet(p, state["count"])], timeout=10)
            return
        except RuntimeError:
            use_mock = True
    if use_mock:
        for i in range(packets_to_sniff):
            pkt = generate_mock_packet(i)
            process_packet(pkt, i+1, is_live=False)
            time.sleep(0.1)

def step3_sni_extractor(use_mock=False):
    print(f"[*] Starting Step 3 SNI Extractor (use_mock={use_mock})...")
    test_domain = "youtube.com"
    raw_tls = create_tls_client_hello(test_domain)
    extracted = extract_sni(raw_tls)
    print(f"[*] Unit Test: Generating TLS Client Hello for '{test_domain}'")
    print(f"[*] Unit Test: Parsed SNI: '{extracted}'")
    if extracted == test_domain:
        print("[+] Unit Test PASSED!")
        
    packets_to_sniff = 10
    def process_packet(pkt, idx, is_live=True):
        tuple_5 = parse_5_tuple(pkt)
        if tuple_5:
            src_ip, dst_ip, src_port, dst_port, protocol = tuple_5
            sni = None
            if protocol == "TCP" and dst_port == 443:
                payload = bytes(pkt[TCP].payload)
                if payload:
                    sni = extract_sni(payload)
            sni_info = f" | SNI: {sni}" if sni else ""
            print(f"[{'Live' if is_live else 'Mock'} Packet {idx}/10] Proto: {protocol:4s} | {src_ip}:{src_port or '-'} -> {dst_ip}:{dst_port or '-'}{sni_info}")

    if not use_mock:
        try:
            from scapy.all import sniff
            state = {"count": 0}
            sniff(count=packets_to_sniff, prn=lambda p: [state.update({"count": state["count"]+1}), process_packet(p, state["count"])], timeout=10)
            return
        except RuntimeError:
            use_mock = True
    if use_mock:
        for i in range(packets_to_sniff):
            pkt = generate_mock_packet(i)
            process_packet(pkt, i+1, is_live=False)
            time.sleep(0.1)

def step4_app_classifier(use_mock=False):
    print(f"[*] Starting Step 4 App Classifier (use_mock={use_mock})...")
    packets_to_sniff = 10
    def process_packet(pkt, idx, is_live=True):
        tuple_5 = parse_5_tuple(pkt)
        if tuple_5:
            src_ip, dst_ip, src_port, dst_port, protocol = tuple_5
            sni = None
            if protocol == "TCP" and dst_port == 443:
                payload = bytes(pkt[TCP].payload)
                if payload:
                    sni = extract_sni(payload)
            app = classify_app(sni, protocol, dst_port)
            print(f"[{'Live' if is_live else 'Mock'} Packet {idx}/10] {src_ip}:{src_port or '-'} -> {dst_ip}:{dst_port or '-'} | Proto: {protocol:4s} | App: {app}")
    if not use_mock:
        try:
            from scapy.all import sniff
            state = {"count": 0}
            sniff(count=packets_to_sniff, prn=lambda p: [state.update({"count": state["count"]+1}), process_packet(p, state["count"])], timeout=10)
            return
        except RuntimeError:
            use_mock = True
    if use_mock:
        for i in range(packets_to_sniff):
            pkt = generate_mock_packet(i)
            process_packet(pkt, i+1, is_live=False)
            time.sleep(0.1)

def step5_flow_tracker(use_mock=False):
    print(f"[*] Starting Step 5 Flow Tracker (use_mock={use_mock})...")
    packets_to_sniff = 10
    if not use_mock:
        try:
            from scapy.all import sniff
            sniff(count=packets_to_sniff, prn=track_packet, timeout=10)
        except RuntimeError:
            use_mock = True
    if use_mock:
        for i in range(packets_to_sniff):
            pkt = generate_mock_packet(i)
            track_packet(pkt)
            time.sleep(0.1)
            
    print("\n[+] Flow Tracking Results:")
    for key, flow in active_flows.items():
        src = f"{flow['src_ip']}:{flow['src_port'] or '-'}"
        dst = f"{flow['dst_ip']}:{flow['dst_port'] or '-'}"
        print(f"{src:25s} -> {dst:25s} | App: {flow['app']:12s} | Pkts: {flow['packet_count']}")

def step6_rules_engine(use_mock=False):
    print(f"[*] Starting Step 6 Rules Engine (use_mock={use_mock})...")
    rules = load_rules()
    packets_to_sniff = 10
    if not use_mock:
        try:
            from scapy.all import sniff
            sniff(count=packets_to_sniff, prn=lambda p: track_packet(p, rules), timeout=10)
        except RuntimeError:
            use_mock = True
    if use_mock:
        for i in range(packets_to_sniff):
            pkt = generate_mock_packet(i)
            track_packet(pkt, rules)
            time.sleep(0.1)
            
    print("\n[+] Flow Tracking & Blocking Results:")
    for key, flow in active_flows.items():
        src = f"{flow['src_ip']}:{flow['src_port'] or '-'}"
        dst = f"{flow['dst_ip']}:{flow['dst_port'] or '-'}"
        status = "BLOCKED" if flow["blocked"] else "ALLOWED"
        print(f"{src:25s} -> {dst:25s} | App: {flow['app']:12s} | Status: {status:8s} | Reason: {flow.get('block_reason') or '-'}")

def step7_realtime_stats(use_mock=False):
    global running
    print(f"[*] Starting Step 7 Real-time Stats Exporter (use_mock={use_mock})...")
    rules = load_rules()
    exporter = threading.Thread(target=stats_exporter_thread, daemon=True)
    exporter.start()
    
    duration = 10
    start_time = time.time()
    
    if not use_mock:
        try:
            from scapy.all import sniff
            print(f"[*] Capturing live packets for {duration}s...")
            sniff(prn=lambda p: track_packet(p, rules), timeout=duration)
        except RuntimeError as e:
            print(f"[!] Live capture failed: {e}")
            use_mock = True
            
    if use_mock:
        print(f"[*] Running Mock packet stream for {duration}s (generating ~5 packets/sec)...")
        pkt_index = 0
        while time.time() - start_time < duration:
            pkt = generate_mock_packet(pkt_index)
            track_packet(pkt, rules)
            pkt_index += 1
            time.sleep(0.2)
            
    print("[*] Capture duration finished. Stopping stats exporter...")
    running = False
    exporter.join(timeout=2.0)
    print(f"[+] Step 7 complete. Final stats written to '{STATS_FILE}'.")

def step8_end_to_end(use_mock=False):
    """
    Step 8: Run engine indefinitely. Periodically re-reads rules.json, 
    writes stats.json, and prints status. Handles Ctrl+C.
    """
    global running
    print(f"[*] Starting Step 8 End-to-End DPI Engine (use_mock={use_mock})...")
    print("[*] Press Ctrl+C to stop.")
    
    exporter = threading.Thread(target=stats_exporter_thread, daemon=True)
    exporter.start()
    
    try:
        if not use_mock:
            try:
                from scapy.all import sniff
                print("[*] Capturing live packets indefinitely...")
                # Sniff continuously, reloading rules dynamically inside track_packet
                sniff(prn=lambda p: track_packet(p, load_rules()))
            except RuntimeError as e:
                print(f"[!] Live capture failed: {e}")
                use_mock = True
                
        if use_mock:
            print("[*] Running Mock packet stream indefinitely (generating ~5 packets/sec)...")
            pkt_index = 0
            while True:
                rules = load_rules()
                pkt = generate_mock_packet(pkt_index)
                track_packet(pkt, rules)
                pkt_index += 1
                time.sleep(0.2)
                
    except KeyboardInterrupt:
        print("\n[*] Stopping DPI engine...")
    finally:
        running = False
        exporter.join(timeout=2.0)
        print("[+] DPI engine stopped.")

def main():
    parser = argparse.ArgumentParser(description="DPI Engine - Python Component")
    parser.add_argument("--step", type=int, default=1, choices=[1, 2, 3, 4, 5, 6, 7, 8],
                        help="Build order step to run/test")
    parser.add_argument("--mock", action="store_true", help="Force mock packet generator")
    
    args = parser.parse_args()
    
    if args.step == 1:
        step1_sniffer(use_mock=args.mock)
    elif args.step == 2:
        step2_parse_5_tuple(use_mock=args.mock)
    elif args.step == 3:
        step3_sni_extractor(use_mock=args.mock)
    elif args.step == 4:
        step4_app_classifier(use_mock=args.mock)
    elif args.step == 5:
        step5_flow_tracker(use_mock=args.mock)
    elif args.step == 6:
        step6_rules_engine(use_mock=args.mock)
    elif args.step == 7:
        step7_realtime_stats(use_mock=args.mock)
    elif args.step == 8:
        step8_end_to_end(use_mock=args.mock)
    else:
        print(f"[-] Step {args.step} is not implemented yet.")
        sys.exit(1)

if __name__ == "__main__":
    main()
