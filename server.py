import socket
import threading
import os
import re
import json

#IP = "10.20.101.5"
#PORT = 8080
IP = "127.0.0.1"
PORT = 8080
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"

def recv_until_newline(conn):
    data = bytearray()
    while True:
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Client closed before header")
        data.extend(chunk)
        if data.endswith(b"\n"):
            break
    return data.decode(FORMAT).rstrip("\n")

def recv_exact(conn, n):
    remaining = n
    chunks = []
    while remaining > 0:
        chunk = conn.recv(min(SIZE, remaining))
        if not chunk:
            raise ConnectionError("Connection closed while receiving file")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        header = recv_until_newline(conn)
    except Exception as e:
        print(f"[ERROR] Failed to read header from {addr}: {e}")
        conn.close()
        return

    if header.startswith("INGEST|"):
        try:
            _, filename, filesize_str = header.split("|", 2)
            filesize = int(filesize_str)
        except Exception as e:
            print(f"[ERROR] Invalid INGEST header from {addr}: {header} ({e})")
            conn.close()
            return

        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        safe_name = os.path.basename(filename)
        try:
            file_bytes = recv_exact(conn, filesize)
            text = file_bytes.decode(FORMAT, errors="replace")
            lines = text.splitlines()
            rows = []

            # regex to capture: timestamp, hostname, daemon, optional severity, message
            main_re = re.compile(
                r'^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+'
                r'(?P<daemon>[^:]+):\s*'
                r'(?:(?P<severity>fatal|error|warning|info|debug)\s*:\s*)?'
                r'(?P<message>.*)$',
                re.IGNORECASE,
            )

            severity_search = re.compile(r'\b(fatal|error|warning|info|debug):\b', re.IGNORECASE)

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                m = main_re.match(line)
                if m:
                    timestamp = m.group('timestamp')
                    hostname = m.group('hostname')
                    daemon = m.group('daemon').strip()
                    severity = m.group('severity') or ""
                    message = m.group('message').strip()
                else:
                    # fallback: try to split by first three whitespace groups
                    parts = line.split(None, 4)
                    if len(parts) >= 5:
                        timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
                        hostname = parts[3]
                        rest = parts[4]
                        # attempt to split daemon and message
                        if ':' in rest:
                            daemon_part, message = rest.split(':', 1)
                            daemon = daemon_part.strip()
                            message = message.strip()
                        else:
                            daemon = ''
                            message = rest
                        severity = ""
                    else:
                        # if completely unparseable, put whole line in message
                        timestamp = ""
                        hostname = ""
                        daemon = ""
                        severity = ""
                        message = line

                # if severity empty, try to find inside message
                if not severity:
                    s = severity_search.search(message)
                    if s:
                        severity = s.group(1).lower()

                rows.append((timestamp, hostname, daemon, severity.lower() if severity else '', message))

            # also append to JSON object file (syslog.json) with numeric IDs
            json_path = os.path.join(logs_dir, "syslog.json")
            json_entries = []
            for (timestamp, hostname, daemon, severity, message) in rows:
                entry = {
                    "timestamp": timestamp,
                    "hostname": hostname,
                    "daemon": daemon,
                    "severity": severity.upper() if severity else "",
                    "message": message,
                }
                json_entries.append(entry)

            try:
                out_dict = {}
                next_id = 1
                if os.path.exists(json_path):
                    with open(json_path, 'r', encoding=FORMAT) as jf:
                        try:
                            existing = json.load(jf)
                        except Exception:
                            existing = None
                    if isinstance(existing, dict):
                        out_dict = existing
                        try:
                            max_key = max(int(k) for k in out_dict.keys() if str(k).isdigit())
                            next_id = max_key + 1
                        except Exception:
                            next_id = len(out_dict) + 1
                    elif isinstance(existing, list):
                        out_dict = {str(i): e for i, e in enumerate(existing, start=1)}
                        next_id = len(out_dict) + 1
                    else:
                        out_dict = {}

                for e in json_entries:
                    out_dict[str(next_id)] = e
                    next_id += 1

                with open(json_path, 'w', encoding=FORMAT) as jf:
                    json.dump(out_dict, jf, indent=2)

                # rebuild hostname -> [ids] index from the numeric-keyed syslog
                hostname_index_path = os.path.join(logs_dir, "hostname_index.json")
                try:
                    hostname_index = {}
                    for key, val in out_dict.items():
                        try:
                            idx = int(key)
                        except Exception:
                            continue
                        hostname = val.get('hostname', '') if isinstance(val, dict) else ''
                        if hostname is None:
                            hostname = ''
                        if hostname:
                            hostname_index.setdefault(hostname, []).append(idx)

                    # sort id lists for readability
                    for h in hostname_index:
                        hostname_index[h].sort()

                    with open(hostname_index_path, 'w', encoding=FORMAT) as hf:
                        json.dump(hostname_index, hf, indent=2)
                except Exception as e:
                    print(f"[ERROR] Writing hostname index to {hostname_index_path}: {e}")
                # rebuild daemon -> [ids] index from the numeric-keyed syslog
                daemon_index_path = os.path.join(logs_dir, "daemon_index.json")
                try:
                    daemon_index = {}
                    for key, val in out_dict.items():
                        try:
                            idx = int(key)
                        except Exception:
                            continue
                        daemon = val.get('daemon', '') if isinstance(val, dict) else ''
                        if daemon is None:
                            daemon = ''
                        # remove bracketed parts like [12345]
                        daemon_clean = re.sub(r'\[.*?\]', '', daemon).strip()
                        if daemon_clean:
                            daemon_index.setdefault(daemon_clean, []).append(idx)

                    # sort id lists for readability
                    for d in daemon_index:
                        daemon_index[d].sort()

                    with open(daemon_index_path, 'w', encoding=FORMAT) as df:
                        json.dump(daemon_index, df, indent=2)
                except Exception as e:
                    print(f"[ERROR] Writing daemon index to {daemon_index_path}: {e}")
                # rebuild severity -> [ids] index from the numeric-keyed syslog
                severity_index_path = os.path.join(logs_dir, "severity_index.json")
                try:
                    severity_index = {}
                    for key, val in out_dict.items():
                        try:
                            idx = int(key)
                        except Exception:
                            continue
                        severity = val.get('severity', '') if isinstance(val, dict) else ''
                        if severity is None:
                            severity = ''
                        sev_clean = severity.strip().upper()
                        if sev_clean:
                            severity_index.setdefault(sev_clean, []).append(idx)

                    # sort id lists for readability
                    for s in severity_index:
                        severity_index[s].sort()

                    with open(severity_index_path, 'w', encoding=FORMAT) as sf:
                        json.dump(severity_index, sf, indent=2)
                except Exception as e:
                    print(f"[ERROR] Writing severity index to {severity_index_path}: {e}")
                # rebuild date -> [ids] index from the numeric-keyed syslog (date only, no time)
                date_index_path = os.path.join(logs_dir, "date_index.json")
                try:
                    date_index = {}
                    for key, val in out_dict.items():
                        try:
                            idx = int(key)
                        except Exception:
                            continue
                        timestamp = val.get('timestamp', '') if isinstance(val, dict) else ''
                        if not timestamp:
                            continue
                        parts = timestamp.split()
                        if len(parts) >= 2:
                            # keep month and day only, e.g. 'Feb 19'
                            date_only = f"{parts[0]} {parts[1]}"
                        else:
                            date_only = timestamp.strip()
                        if date_only:
                            date_index.setdefault(date_only, []).append(idx)

                    # sort id lists for readability
                    for d in date_index:
                        date_index[d].sort()

                    with open(date_index_path, 'w', encoding=FORMAT) as df:
                        json.dump(date_index, df, indent=2)
                except Exception as e:
                    print(f"[ERROR] Writing date index to {date_index_path}: {e}")
            except Exception as e:
                print(f"[ERROR] Writing JSON to {json_path}: {e}")

            print(f"[INGEST] Processed {len(rows)} lines from {safe_name} from {addr} -> {json_path}")
            conn.sendall(f"OK Processed {len(rows)} lines".encode(FORMAT))
        except Exception as e:
            print(f"[ERROR] Receiving file from {addr}: {e}")
            try:
                conn.sendall(f"ERROR {e}".encode(FORMAT))
            except Exception:
                pass
    else:
        # fallback: echo simple text
        try:
            msg = header
            print(f"[{addr}] {msg}")
            conn.sendall(f"Msg received: {msg}".encode(FORMAT))
        except Exception:
            pass

    conn.close()

def main():
    print("[STARTING] Server is starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    main()