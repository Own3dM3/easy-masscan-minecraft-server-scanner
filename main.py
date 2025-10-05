#!/usr/bin/env python3
import argparse, re, socket, struct, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Set, Dict, Any
import dns.resolver
from colorama import Fore, Style, init
init(autoreset=True)

IPV4_RE = re.compile(r"(?:\b|^)((?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3})(?:\b|$)")
PORT_NUM_RE = re.compile(r"\b([0-9]{1,5})\b")
MASSCAN_DISCOVERED_RE = re.compile(r"Discovered open port\s*([0-9]{1,5})\/\w+\s*on\s*(" + IPV4_RE.pattern + r")", re.IGNORECASE)

def varint(v:int)->bytes:
    out=bytearray()
    while True:
        b=v&0x7F; v >>=7
        out.append(b | (0x80 if v else 0))
        if not v: break
    return bytes(out)

def read_varint(s):
    v=0
    for i in range(5):
        try:
            b=s.recv(1)
            if not b: raise ConnectionError("closed")
            by=b[0]; v |= (by & 0x7F) << (7*i)
            if not (by & 0x80): break
        except socket.timeout:
            raise ConnectionError("timeout")
    return v

def send_packet(s,pid,data):
    body=varint(pid)+data; s.sendall(varint(len(body))+body)

def resolve_srv(host, default=25565):
    try:
        ans=dns.resolver.resolve(f"_minecraft._tcp.{host}", "SRV")
        r=ans[0]; return str(r.target).rstrip("."), int(r.port)
    except Exception:
        return host, default

def extract_motd(d):
    if isinstance(d,str): return d.strip()
    if isinstance(d,list): return "".join(extract_motd(x) for x in d)
    if isinstance(d,dict):
        parts=[]
        if "text" in d and isinstance(d["text"],str): parts.append(d["text"])
        if "extra" in d and isinstance(d["extra"],list): parts.append("".join(extract_motd(x) for x in d["extra"]))
        c="".join(parts).strip()
        return c or json.dumps(d, ensure_ascii=False)
    return str(d).strip()

def check_whitelist(host, port, timeout=5.0):
    try:
        hr, pr = resolve_srv(host, port)
        with socket.create_connection((hr, pr), timeout=timeout) as s:
            s.settimeout(timeout)
            data = varint(767) + varint(len(hr)) + hr.encode() + struct.pack(">H", pr) + varint(2)
            send_packet(s, 0x00, data)
            username = "PingTest"
            login_data = varint(len(username)) + username.encode()
            send_packet(s, 0x00, login_data)
            try:
                packet_len = read_varint(s) 
                pid = read_varint(s)  
                print(Fore.CYAN + f"Debug: Packet ID {pid}, length {packet_len} for {host}:{port}" + Style.RESET_ALL)
                if pid == 0x02:  
                    return True, "Not whitelisted (login successful)"
                elif pid == 0x00: 
                    jl = read_varint(s)
                    payload = b""
                    while len(payload) < jl:
                        chunk = s.recv(jl - len(payload))
                        if not chunk: raise ConnectionError("closed while reading JSON")
                        payload += chunk
                    try:
                        disconnect_info = json.loads(payload.decode("utf-8", errors="ignore"))
                        message = extract_motd(disconnect_info.get("reason", "Disconnected"))
                        print(Fore.CYAN + f"Debug: Disconnect message: {message}" + Style.RESET_ALL)
                        if "whitelist" in message.lower():
                            return False, f"Whitelisted: {message}"
                        return True, f"Not whitelisted (disconnected: {message})"
                    except json.JSONDecodeError:
                        return False, "Invalid JSON response"
                else:
                    return False, f"Unexpected packet ID: {pid}"
            except ConnectionError as e:
                print(Fore.CYAN + f"Debug: Connection error in response reading: {str(e)}" + Style.RESET_ALL)
                return False, f"Connection error: {str(e)}"
    except Exception as e:
        print(Fore.CYAN + f"Debug: Failed to connect to {host}:{port}: {str(e)}" + Style.RESET_ALL)
        return False, f"Failed to check whitelist: {str(e)}"

def ping_server(host, port=25565, timeout=5.0) -> Dict[str,Any]:
    hr, pr = resolve_srv(host, port)
    with socket.create_connection((hr, pr), timeout=timeout) as s:
        s.settimeout(timeout)
        data = varint(767) + varint(len(hr)) + hr.encode() + struct.pack(">H", pr) + varint(1)
        send_packet(s,0x00,data); send_packet(s,0x00,b"")
        _ = read_varint(s); pid = read_varint(s)
        if pid != 0x00: raise ValueError(f"pkt {pid}")
        jl = read_varint(s); payload=b""
        while len(payload) < jl:
            chunk = s.recv(jl - len(payload))
            if not chunk: raise ConnectionError("closed while json")
            payload += chunk
        info = json.loads(payload.decode("utf-8", errors="ignore"))
        version = info.get("version",{}).get("name","Unknown")
        players = info.get("players",{}); online = players.get("online","?"); maxp = players.get("max","?")
        motd = extract_motd(info.get("description",""))
        is_open, wl_message = check_whitelist(host, port, timeout)
        return {
            "host": host,
            "resolved": hr,
            "port": pr,
            "version": version,
            "online": online,
            "max": maxp,
            "motd": motd,
            "whitelist": is_open,
            "whitelist_message": wl_message
        }

def parse_masscan_results_loose(file_path:str, want_port:int) -> Set[str]:
    ips=set()
    p=Path(file_path)
    if not p.exists():
        raise FileNotFoundError(file_path)
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line: continue
            m = MASSCAN_DISCOVERED_RE.search(line)
            if m:
                port = int(m.group(1)); ip = m.group(2)
                if port == want_port: ips.add(ip); continue
            if line.lower().startswith("open ") or " open " in (" " + line.lower() + " "):
                parts = line.split()
                try:
                    if parts[0].lower()=="open" and len(parts)>=4:
                        ip = next((p for p in parts if IPV4_RE.match(p)), None)
                        port_candidates = [int(x) for x in parts if x.isdigit()]
                        if ip and port_candidates:
                            if want_port in port_candidates:
                                ips.add(ip); continue
                except Exception:
                    pass
            ip_match = IPV4_RE.search(line)
            if ip_match:
                ip = ip_match.group(1)
                port_found = None
                mcol = re.search(r":([0-9]{1,5})", line)
                if mcol:
                    port_found = int(mcol.group(1))
                else:
                    mf = re.search(r"([0-9]{1,5})\/[a-zA-Z]+", line)
                    if mf:
                        port_found = int(mf.group(1))
                    else:
                        nums = [int(x) for x in PORT_NUM_RE.findall(line)]
                        if nums:
                            if want_port in nums:
                                port_found = want_port
                            else:
                                port_found = nums[-1]
                if port_found == want_port:
                    ips.add(ip)
    return ips

def print_info(info):
    motd = info.get("motd","")
    whitelist_status = "Open" if info.get("whitelist") else "Whitelisted"
    whitelist_color = Fore.GREEN if info.get("whitelist") else Fore.RED
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.GREEN + "🌐 Сервер: " + Fore.YELLOW + f"{info.get('host')} (resolved {info.get('resolved')}):{info.get('port')}")
    print(Fore.BLUE + "🎮 Версия: " + Fore.WHITE + str(info.get("version")))
    print(Fore.MAGENTA + "👥 Онлайн: " + Fore.WHITE + f"{info.get('online')}/{info.get('max')}")
    print(Fore.CYAN + "💬 MOTD: " + Style.BRIGHT + (motd or "-"))
    print(Fore.YELLOW + "🔒 Whitelist: " + whitelist_color + whitelist_status)
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + Style.RESET_ALL)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in","-i",dest="infile",required=True)
    ap.add_argument("--port","-p",type=int,default=25565)
    ap.add_argument("--workers","-w",type=int,default=10)
    ap.add_argument("--timeout","-t",type=float,default=5.0)
    args = ap.parse_args()
    try:
        ips = parse_masscan_results_loose(args.infile, args.port)
    except Exception as e:
        print(Fore.RED + f"Error reading {args.infile}: {e}" + Style.RESET_ALL); return
    if not ips:
        print("No hosts found"); return
    print(f"Found {len(ips)} hosts; checking with {args.workers} workers...")
    results, failed = {}, []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(lambda x: ping_server(x, args.port, args.timeout), ip): ip for ip in sorted(ips)}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                res = fut.result()
                results[ip]=res
                print_info(res)
            except Exception as e:
                failed.append((ip,str(e)))
                print(Fore.YELLOW + f"⚠ {ip} — error: {e}" + Style.RESET_ALL)
    print()
    print(Fore.GREEN + f"Done. OK: {len(results)}. Errors: {len(failed)}" + Style.RESET_ALL)
    if failed:
        print(Fore.YELLOW + "Failed hosts:" + Style.RESET_ALL)
        for ip,err in failed:
            print(" ", ip, err)

if __name__=="__main__":
    main()
