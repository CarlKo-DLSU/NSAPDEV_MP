import socket
import threading
import os
import re
import json
import time

#IP = "10.20.101.5"
#PORT = 8080
IP = "127.0.0.1"
PORT = 8080
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
data_lock = threading.Lock()
active_connections = 0
conn_lock = threading.Lock()

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
    global active_connections
    task_type = "UNKNOWN"

    with conn_lock:
        active_connections += 1
        print(f"[NEW CONNECTION] {addr} connected.")

    try:
        try:
            header = recv_until_newline(conn)

            if header.startswith("INGEST|"):
                task_type = "INGEST"
                try:
                    _, filename, _ = header.split("|", 2)
                    print(f"[TASK] INGEST {os.path.basename(filename)}")
                except:
                    print("[TASK] INGEST <unknown>")

            elif header.startswith("QUERY|"):
                task_type = "QUERY"
                try:
                    _, qtype, param = header.split("|", 2)
                    print(f"[TASK] QUERY {qtype} {param}")
                except:
                    print("[TASK] QUERY <unknown>")

            elif header.strip().upper() == "PURGE":
                task_type = "PURGE"
                print("[TASK] PURGE")

            else:
                task_type = "UNKNOWN"
                print("[TASK] UNKNOWN")
            with conn_lock:
                print(f"[ACTIVE CONNECTIONS] {active_connections}")
        except Exception as e:
            print(f"[ERROR] Failed to read header from {addr}: {e}")
            return
        with data_lock:
            if header.startswith("INGEST|"):
                try:
                    _, filename, filesize_str = header.split("|", 2)
                    filesize = int(filesize_str)
                except Exception as e:
                    print(f"[ERROR] Invalid INGEST header from {addr}: {header} ({e})")
                    
                    return

                logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                os.makedirs(logs_dir, exist_ok=True)
                safe_name = os.path.basename(filename)
                try:
                    # mark processing start for debugging timing
                    proc_start = time.time()
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

                    # match severity tokens followed by a colon (allow spaces before/after colon)
                    severity_search = re.compile(r'\b(fatal|error|warning|info|debug)\s*:\s*', re.IGNORECASE)

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
                            # preserve original message text as parsed by regex
                            message = m.group('message').strip()
                            # if severity was captured as a prefix, do NOT include it in raw_message
                            raw_message = message
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
                                raw_message = message
                            else:
                                # if completely unparseable, put whole line in message
                                timestamp = ""
                                hostname = ""
                                daemon = ""
                                severity = ""
                                message = line

                        # if severity empty, try to find inside message (e.g. "... ERROR: ..." inside message)
                        if not severity:
                            s = severity_search.search(message)
                            if s:
                                severity = s.group(1).lower()
                                # keep original message with severity present
                                raw_message = message
                                # remove the matched severity token (e.g. "ERROR:") from the cleaned message
                                # only remove the first occurrence to avoid accidental removals
                                message = message[:s.start()] + message[s.end():]
                                message = message.strip()

                        rows.append((timestamp, hostname, daemon, severity.lower() if severity else '', message, raw_message))

                    # also append to JSON object file (syslog.json) with numeric IDs
                    json_path = os.path.join(logs_dir, "syslog.json")
                    json_entries = []
                    for (timestamp, hostname, daemon, severity, message, raw_message) in rows:
                        entry = {
                            "timestamp": timestamp,
                            "hostname": hostname,
                            "daemon": daemon,
                            "severity": severity.upper() if severity else "",
                            "message": message,
                            "raw_message": raw_message,
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

                    elapsed = time.time() - proc_start
                    print(f"[INGEST] Processed {len(rows)} lines from {safe_name} from {addr} -> {json_path} (took {elapsed:.2f}s)")
                    try:
                        conn.sendall(f"OK Processed {len(rows)} lines".encode(FORMAT))
                        # politely signal EOF to client side after sending ACK
                        try:
                            conn.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"[ERROR] Sending ACK to {addr}: {e}")
                except Exception as e:
                    print(f"[ERROR] Receiving file from {addr}: {e}")
                    try:
                        conn.sendall(f"ERROR {e}".encode(FORMAT))
                    except Exception:
                        pass
            else:
                # support QUERY commands: QUERY|SEARCH_DATE|<date_string>\n
                if header.startswith("QUERY|"):
                    try:
                        _, qtype, param = header.split("|", 2)
                    except Exception as e:
                        try:
                            conn.sendall(f"ERROR Invalid QUERY header: {e}".encode(FORMAT))
                        except Exception:
                            pass
                        
                        return

                    qtype = qtype.upper()
                    if qtype == "SEARCH_DATE":
                        date_string = param
                        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                        date_index_path = os.path.join(logs_dir, "date_index.json")
                        json_path = os.path.join(logs_dir, "syslog.json")

                        if not os.path.exists(date_index_path):
                            try:
                                conn.sendall(f"ERROR date index not found".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return
                        try:
                            with open(date_index_path, 'r', encoding=FORMAT) as df:
                                date_index = json.load(df)
                        except Exception as e:
                            try:
                                conn.sendall(f"ERROR reading date index: {e}".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        ids = date_index.get(date_string, []) if isinstance(date_index, dict) else []

                        if not ids:
                            try:
                                conn.sendall(f"NOTFOUND No entries for date '{date_string}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        # load syslog to fetch actual entries
                        if not os.path.exists(json_path):
                            try:
                                conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return
                        try:
                            with open(json_path, 'r', encoding=FORMAT) as jf:
                                out_dict = json.load(jf)
                        except Exception as e:
                            try:
                                conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        # build result lines
                        lines = []
                        for idx in ids:
                            key = str(idx)
                            entry = out_dict.get(key) if isinstance(out_dict, dict) else None
                            if not entry:
                                # skip missing entries
                                continue
                            timestamp = entry.get('timestamp', '')
                            hostname = entry.get('hostname', '')
                            daemon = entry.get('daemon', '')
                            raw = entry.get('raw_message', '')
                            message = entry.get('message', '')
                            if raw:
                                lines.append(f"{timestamp} {hostname} {daemon}: {raw}")
                            else:
                                severity = entry.get('severity', '')
                                sev = severity.lower() if severity else ''
                                if sev:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {sev}: {message}")
                                else:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {message}")

                        if not lines:
                            try:
                                conn.sendall(f"NOTFOUND No valid entries found for date '{date_string}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        # assemble response
                        resp_lines = [f"Found {len(lines)} matching entries for date '{date_string}':"]
                        for i, l in enumerate(lines, start=1):
                            resp_lines.append(f"{i}. {l}")

                        resp_text = "\n".join(resp_lines)
                        try:
                            conn.sendall(resp_text.encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    elif qtype == "SEARCH_HOST":
                        hostname_query = param
                        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                        hostname_index_path = os.path.join(logs_dir, "hostname_index.json")
                        json_path = os.path.join(logs_dir, "syslog.json")

                        if not os.path.exists(hostname_index_path):
                            try:
                                conn.sendall(f"ERROR hostname index not found".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        try:
                            with open(hostname_index_path, 'r', encoding=FORMAT) as hf:
                                hostname_index = json.load(hf)
                        except Exception as e:
                            try:
                                conn.sendall(f"ERROR reading hostname index: {e}".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        ids = hostname_index.get(hostname_query, []) if isinstance(hostname_index, dict) else []

                        if not ids:
                            try:
                                conn.sendall(f"NOTFOUND No entries for hostname '{hostname_query}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        if not os.path.exists(json_path):
                            try:
                                conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return
                        try:
                            with open(json_path, 'r', encoding=FORMAT) as jf:
                                out_dict = json.load(jf)
                        except Exception as e:
                            try:
                                conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        lines = []
                        for idx in ids:
                            key = str(idx)
                            entry = out_dict.get(key) if isinstance(out_dict, dict) else None
                            if not entry:
                                continue
                            timestamp = entry.get('timestamp', '')
                            hostname = entry.get('hostname', '')
                            daemon = entry.get('daemon', '')
                            raw = entry.get('raw_message', '')
                            message = entry.get('message', '')
                            if raw:
                                lines.append(f"{timestamp} {hostname} {daemon}: {raw}")
                            else:
                                severity = entry.get('severity', '')
                                sev = severity.lower() if severity else ''
                                if sev:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {sev}: {message}")
                                else:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {message}")

                        if not lines:
                            try:
                                conn.sendall(f"NOTFOUND No valid entries found for hostname '{hostname_query}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        resp_lines = [f"Found {len(lines)} matching entries for hostname '{hostname_query}':"]
                        for i, l in enumerate(lines, start=1):
                            resp_lines.append(f"{i}. {l}")

                        resp_text = "\n".join(resp_lines)
                        try:
                            conn.sendall(resp_text.encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    elif qtype == "SEARCH_DAEMON":
                        daemon_query = param
                        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                        daemon_index_path = os.path.join(logs_dir, "daemon_index.json")
                        json_path = os.path.join(logs_dir, "syslog.json")

                        # detect bracketed pid form (e.g. sshd[1234])
                        bracketed = True if re.search(r"\[\d+\]$", daemon_query) else False

                        ids = []
                        out_dict = None

                        if not bracketed:
                            # use daemon_index.json
                            if not os.path.exists(daemon_index_path):
                                try:
                                    conn.sendall(f"ERROR daemon index not found".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            try:
                                with open(daemon_index_path, 'r', encoding=FORMAT) as df:
                                    daemon_index = json.load(df)
                            except Exception as e:
                                try:
                                    conn.sendall(f"ERROR reading daemon index: {e}".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            ids = daemon_index.get(daemon_query, []) if isinstance(daemon_index, dict) else []

                            if not ids:
                                try:
                                    conn.sendall(f"NOTFOUND No entries for daemon '{daemon_query}'".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            # load syslog to fetch actual entries
                            if not os.path.exists(json_path):
                                try:
                                    conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            try:
                                with open(json_path, 'r', encoding=FORMAT) as jf:
                                    out_dict = json.load(jf)
                            except Exception as e:
                                try:
                                    conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return
                        else:
                            # bracketed form: scan syslog.json entries for exact daemon substring
                            if not os.path.exists(json_path):
                                try:
                                    conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            try:
                                with open(json_path, 'r', encoding=FORMAT) as jf:
                                    out_dict = json.load(jf)
                            except Exception as e:
                                try:
                                    conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            # collect ids where daemon field contains the bracketed form
                            for key, val in (out_dict.items() if isinstance(out_dict, dict) else []):
                                try:
                                    idx = int(key)
                                except Exception:
                                    continue
                                daemon_field = val.get('daemon', '') if isinstance(val, dict) else ''
                                if daemon_query in daemon_field:
                                    ids.append(idx)

                            if not ids:
                                try:
                                    conn.sendall(f"NOTFOUND No entries for daemon '{daemon_query}'".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                        # build result lines from out_dict and ids
                        lines = []
                        for idx in ids:
                            key = str(idx)
                            entry = out_dict.get(key) if isinstance(out_dict, dict) else None
                            if not entry:
                                continue
                            timestamp = entry.get('timestamp', '')
                            hostname = entry.get('hostname', '')
                            daemon = entry.get('daemon', '')
                            raw = entry.get('raw_message', '')
                            message = entry.get('message', '')
                            if raw:
                                lines.append(f"{timestamp} {hostname} {daemon}: {raw}")
                            else:
                                severity = entry.get('severity', '')
                                sev = severity.lower() if severity else ''
                                if sev:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {sev}: {message}")
                                else:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {message}")

                        if not lines:
                            try:
                                conn.sendall(f"NOTFOUND No valid entries found for daemon '{daemon_query}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        resp_lines = [f"Found {len(lines)} matching entries for daemon '{daemon_query}':"]
                        for i, l in enumerate(lines, start=1):
                            resp_lines.append(f"{i}. {l}")

                        resp_text = "\n".join(resp_lines)
                        try:
                            conn.sendall(resp_text.encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    elif qtype == "SEARCH_SEVERITY":
                        sev_query = param.strip().upper()
                        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                        severity_index_path = os.path.join(logs_dir, "severity_index.json")
                        json_path = os.path.join(logs_dir, "syslog.json")

                        ids = []
                        out_dict = None

                        # try severity index first
                        if os.path.exists(severity_index_path):
                            try:
                                with open(severity_index_path, 'r', encoding=FORMAT) as sf:
                                    severity_index = json.load(sf)
                            except Exception as e:
                                try:
                                    conn.sendall(f"ERROR reading severity index: {e}".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            if isinstance(severity_index, dict):
                                ids = severity_index.get(sev_query, [])

                        # fallback: scan syslog.json if no ids found
                        if not ids:
                            if not os.path.exists(json_path):
                                try:
                                    conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            try:
                                with open(json_path, 'r', encoding=FORMAT) as jf:
                                    out_dict = json.load(jf)
                            except Exception as e:
                                try:
                                    conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                            for key, val in (out_dict.items() if isinstance(out_dict, dict) else []):
                                try:
                                    idx = int(key)
                                except Exception:
                                    continue
                                sev = (val.get('severity', '') if isinstance(val, dict) else '').upper()
                                if sev == sev_query:
                                    ids.append(idx)

                        if not ids:
                            try:
                                conn.sendall(f"NOTFOUND No entries for severity '{sev_query}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        # ensure syslog loaded
                        if out_dict is None:
                            try:
                                with open(json_path, 'r', encoding=FORMAT) as jf:
                                    out_dict = json.load(jf)
                            except Exception as e:
                                try:
                                    conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                                except Exception:
                                    pass
                                
                                return

                        # build result lines
                        lines = []
                        for idx in ids:
                            key = str(idx)
                            entry = out_dict.get(key) if isinstance(out_dict, dict) else None
                            if not entry:
                                continue
                            timestamp = entry.get('timestamp', '')
                            hostname = entry.get('hostname', '')
                            daemon = entry.get('daemon', '')
                            raw = entry.get('raw_message', '')
                            message = entry.get('message', '')
                            if raw:
                                lines.append(f"{timestamp} {hostname} {daemon}: {raw}")
                            else:
                                severity = entry.get('severity', '')
                                sev = severity.lower() if severity else ''
                                if sev:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {sev}: {message}")
                                else:
                                    lines.append(f"{timestamp} {hostname} {daemon}: {message}")

                        if not lines:
                            try:
                                conn.sendall(f"NOTFOUND No valid entries found for severity '{sev_query}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        resp_lines = [f"Found {len(lines)} matching entries for severity '{sev_query}':"]
                        for i, l in enumerate(lines, start=1):
                            resp_lines.append(f"{i}. {l}")

                        resp_text = "\n".join(resp_lines)
                        try:
                            conn.sendall(resp_text.encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    elif qtype == "SEARCH_KEYWORD":
                        keyword = param
                        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                        json_path = os.path.join(logs_dir, "syslog.json")

                        if not os.path.exists(json_path):
                            try:
                                conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        try:
                            with open(json_path, 'r', encoding=FORMAT) as jf:
                                out_dict = json.load(jf)
                        except Exception as e:
                            try:
                                conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        lines = []
                        kw = keyword.lower()
                        for key, val in (out_dict.items() if isinstance(out_dict, dict) else []):
                            entry = val if isinstance(val, dict) else None
                            if not entry:
                                continue
                            raw = entry.get('raw_message', '')
                            if raw and kw in raw.lower():
                                timestamp = entry.get('timestamp', '')
                                hostname = entry.get('hostname', '')
                                daemon = entry.get('daemon', '')
                                lines.append(f"{timestamp} {hostname} {daemon}: {raw}")

                        if not lines:
                            try:
                                conn.sendall(f"NOTFOUND No entries containing keyword '{keyword}'".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        resp_lines = [f"Found {len(lines)} matching entries containing '{keyword}':"]
                        for i, l in enumerate(lines, start=1):
                            resp_lines.append(f"{i}. {l}")

                        resp_text = "\n".join(resp_lines)
                        try:
                            conn.sendall(resp_text.encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    elif qtype == "COUNT_KEYWORD":
                        keyword = param
                        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                        json_path = os.path.join(logs_dir, "syslog.json")

                        if not os.path.exists(json_path):
                            try:
                                conn.sendall(f"ERROR syslog.json not found".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        try:
                            with open(json_path, 'r', encoding=FORMAT) as jf:
                                out_dict = json.load(jf)
                        except Exception as e:
                            try:
                                conn.sendall(f"ERROR reading syslog.json: {e}".encode(FORMAT))
                            except Exception:
                                pass
                            
                            return

                        kw = keyword.lower()
                        count = 0
                        for key, val in (out_dict.items() if isinstance(out_dict, dict) else []):
                            entry = val if isinstance(val, dict) else None
                            if not entry:
                                continue
                            raw = entry.get('raw_message', '')
                            if raw and kw in raw.lower():
                                count += 1

                        try:
                            conn.sendall(f"They keyword '{keyword}' appears in {count} indexed log entry.".encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    else:
                        try:
                            conn.sendall(f"ERROR Unknown QUERY type: {qtype}".encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                elif header.strip().upper() == "PURGE":
                    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                    # if no logs dir, nothing to do
                    if not os.path.exists(logs_dir):
                        try:
                            conn.sendall("[Server Response] SUCCESS: 0 indexed log entries have been erased.".encode(FORMAT))
                        except Exception:
                            pass
                        
                        return
                    # count entries in syslog.json before deletion
                    json_path = os.path.join(logs_dir, "syslog.json")
                    entries = 0
                    try:
                        if os.path.exists(json_path):
                            with open(json_path, 'r', encoding=FORMAT) as jf:
                                existing = json.load(jf)
                            if isinstance(existing, dict):
                                entries = len(existing)
                            elif isinstance(existing, list):
                                entries = len(existing)
                    except Exception as e:
                        print(f"[ERROR] Counting syslog entries before purge: {e}")

                    # remove all .json files in logs dir
                    try:
                        for fname in os.listdir(logs_dir):
                            if fname.lower().endswith('.json'):
                                p = os.path.join(logs_dir, fname)
                                try:
                                    os.remove(p)
                                except Exception as e:
                                    print(f"[ERROR] Removing {p}: {e}")
                        try:
                            conn.sendall(f"[Server Response] SUCCESS: {entries} indexed log entries have been erased.".encode(FORMAT))
                        except Exception:
                            pass
                    except Exception as e:
                        try:
                            conn.sendall(f"[Server Response] ERROR: Purge failed: {e}".encode(FORMAT))
                        except Exception:
                            pass
                    
                    return
                else:
                    # fallback: echo simple text
                    try:
                        msg = header
                        print(f"[{addr}] {msg}")
                        conn.sendall(f"Msg received: {msg}".encode(FORMAT))
                    except Exception:
                        pass
    finally:
        try:
            conn.close()
        except:
            pass

        with conn_lock:
            active_connections -= 1
            print(f"[CLOSING CONNECTION] {task_type} task from {addr} finished.")
            print(f"[ACTIVE CONNECTIONS] {active_connections}")

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

if __name__ == "__main__":
    main()