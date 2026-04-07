import socket
import threading
import os
import re
import json
import time
import argparse

#IP = "10.20.101.5"
#PORT = 8080
IP = "127.0.0.1"
PORT = 8080
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
class RWLock:
    """A simple reader-writer lock with writer preference.

    Readers can run concurrently. Writers are exclusive and when a writer
    is waiting, new readers will block to avoid writer starvation.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._read_ready = threading.Condition(self._lock)
        self._readers = 0
        self._writers_waiting = 0
        self._writer = False

    def acquire_read(self):
        with self._lock:
            # if a writer is active or waiting, readers wait
            while self._writer or self._writers_waiting > 0:
                self._read_ready.wait()
            self._readers += 1

    def release_read(self):
        with self._lock:
            self._readers -= 1
            if self._readers == 0:
                self._read_ready.notify_all()

    def acquire_write(self):
        with self._lock:
            self._writers_waiting += 1
            while self._writer or self._readers > 0:
                self._read_ready.wait()
            self._writers_waiting -= 1
            self._writer = True

    def release_write(self):
        with self._lock:
            self._writer = False
            self._read_ready.notify_all()


data_lock = RWLock()
active_connections = 0
conn_lock = threading.Lock()
# sequencing to ensure FIFO start order of tasks
seq_lock = threading.Lock()
seq_cond = threading.Condition(seq_lock)
# next sequence number to assign
next_seq = 1
# next sequence number allowed to start
next_to_start = 1

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

def load_syslog_from_jsonl(json_path):
    """Load all entries from JSON Lines file (syslog.jsonl) into dict keyed by ID."""
    out_dict = {}
    with open(json_path, 'r', encoding=FORMAT) as jf:
        for line in jf:
            line = line.strip()
            if line:
                entry = json.loads(line)
                entry_id = entry.get('id')
                if entry_id:
                    out_dict[str(entry_id)] = entry
    return out_dict


def process_ingest(conn, header, addr):
    """Process an INGEST request: receive file, parse, append entries, update indices, send ACK."""
    try:
        _, filename, filesize_str = header.split("|", 2)
        filesize = int(filesize_str)
    except Exception as e:
        print(f"[ERROR] Invalid INGEST header from {addr}: {header} ({e})")
        try:
            conn.sendall(f"ERROR Invalid INGEST header: {e}".encode(FORMAT))
        except Exception:
            pass
        return

    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    safe_name = os.path.basename(filename)
    try:
        proc_start = time.time()
        file_bytes = recv_exact(conn, filesize)
        text = file_bytes.decode(FORMAT, errors="replace")
        lines = text.splitlines()
        rows = []

        main_re = re.compile(
            r'^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<daemon>[^:]+):\s*'
            r'(?:(?P<severity>fatal|error|warning|info|debug)\s*:\s*)?'
            r'(?P<message>.*)$',
            re.IGNORECASE,
        )
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
                message = m.group('message').strip()
                raw_message = message
            else:
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
                    hostname = parts[3]
                    rest = parts[4]
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
                    timestamp = ""
                    hostname = ""
                    daemon = ""
                    severity = ""
                    message = line

            if not severity:
                s = severity_search.search(message)
                if s:
                    severity = s.group(1).lower()
                    raw_message = message
                    message = message[:s.start()] + message[s.end():]
                    message = message.strip()

            rows.append((timestamp, hostname, daemon, severity.lower() if severity else '', message, raw_message))

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
            next_id = 1
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding=FORMAT) as jf:
                    line_count = sum(1 for _ in jf)
                    next_id = line_count + 1

            starting_id = next_id
            new_entries_by_id = {}
            with open(json_path, 'a', encoding=FORMAT) as jf:
                for e in json_entries:
                    e_with_id = {"id": next_id}
                    e_with_id.update(e)
                    jf.write(json.dumps(e_with_id) + '\n')
                    new_entries_by_id[next_id] = e
                    next_id += 1

            # update indices incrementally (hostname, daemon, severity, date)
            hostname_index_path = os.path.join(logs_dir, "hostname_index.json")
            try:
                hostname_index = {}
                if os.path.exists(hostname_index_path):
                    with open(hostname_index_path, 'r', encoding=FORMAT) as hf:
                        hostname_index = json.load(hf)
                        if not isinstance(hostname_index, dict):
                            hostname_index = {}
                for idx, entry in new_entries_by_id.items():
                    hostname = entry.get('hostname', '') if isinstance(entry, dict) else ''
                    if hostname is None:
                        hostname = ''
                    if hostname:
                        hostname_index.setdefault(hostname, []).append(idx)
                for h in hostname_index:
                    hostname_index[h].sort()
                with open(hostname_index_path, 'w', encoding=FORMAT) as hf:
                    json.dump(hostname_index, hf, indent=2)
            except Exception as e:
                print(f"[ERROR] Writing hostname index to {hostname_index_path}: {e}")

            daemon_index_path = os.path.join(logs_dir, "daemon_index.json")
            try:
                daemon_index = {}
                if os.path.exists(daemon_index_path):
                    with open(daemon_index_path, 'r', encoding=FORMAT) as df:
                        daemon_index = json.load(df)
                for idx, entry in new_entries_by_id.items():
                    daemon = entry.get('daemon', '') if isinstance(entry, dict) else ''
                    if daemon is None:
                        daemon = ''
                    daemon_clean = re.sub(r'\[.*?\]', '', daemon).strip()
                    if daemon_clean:
                        daemon_index.setdefault(daemon_clean, []).append(idx)
                for d in daemon_index:
                    daemon_index[d].sort()
                with open(daemon_index_path, 'w', encoding=FORMAT) as df:
                    json.dump(daemon_index, df, indent=2)
            except Exception as e:
                print(f"[ERROR] Writing daemon index to {daemon_index_path}: {e}")

            severity_index_path = os.path.join(logs_dir, "severity_index.json")
            try:
                severity_index = {}
                if os.path.exists(severity_index_path):
                    with open(severity_index_path, 'r', encoding=FORMAT) as sf:
                        severity_index = json.load(sf)
                for idx, entry in new_entries_by_id.items():
                    severity = entry.get('severity', '') if isinstance(entry, dict) else ''
                    if severity is None:
                        severity = ''
                    sev_clean = severity.strip().upper()
                    if sev_clean:
                        severity_index.setdefault(sev_clean, []).append(idx)
                for s in severity_index:
                    severity_index[s].sort()
                with open(severity_index_path, 'w', encoding=FORMAT) as sf:
                    json.dump(severity_index, sf, indent=2)
            except Exception as e:
                print(f"[ERROR] Writing severity index to {severity_index_path}: {e}")

            date_index_path = os.path.join(logs_dir, "date_index.json")
            try:
                date_index = {}
                if os.path.exists(date_index_path):
                    with open(date_index_path, 'r', encoding=FORMAT) as datef:
                        date_index = json.load(datef)
                for idx, entry in new_entries_by_id.items():
                    timestamp = entry.get('timestamp', '') if isinstance(entry, dict) else ''
                    if not timestamp:
                        continue
                    parts = timestamp.split()
                    if len(parts) >= 2:
                        date_only = f"{parts[0]} {parts[1]}"
                    else:
                        date_only = timestamp.strip()
                    if date_only:
                        date_index.setdefault(date_only, []).append(idx)
                for d in date_index:
                    date_index[d].sort()
                with open(date_index_path, 'w', encoding=FORMAT) as datef:
                    json.dump(date_index, datef, indent=2)
            except Exception as e:
                print(f"[ERROR] Writing date index to {date_index_path}: {e}")
        except Exception as e:
            print(f"[ERROR] Writing JSON to {json_path}: {e}")

        elapsed = time.time() - proc_start
        print(f"[INGEST] Processed {len(rows)} lines from {safe_name} from {addr} -> {json_path} (took {elapsed:.2f}s)")
        try:
            conn.sendall(f"OK Processed {len(rows)} lines".encode(FORMAT))
            try:
                conn.shutdown(socket.SHUT_WR)
            except Exception:
                pass
        except Exception as e:
            print(f"[ERROR] Sending ACK to {addr}: {e}")
    except Exception as e:
        print(f"[ERROR] Receiving file from {addr}: {e}")
        try:
            conn.sendall(f"{e}".encode(FORMAT))
        except Exception:
            pass


def process_purge(conn, addr):
    """Process a PURGE request: delete index files and report count."""
    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
    purge_start = time.time()
    if not os.path.exists(logs_dir):
        try:
            conn.sendall("[SERVER] SUCCESS: 0 indexed log entries have been erased.".encode(FORMAT))
        except Exception:
            pass
        return

    json_path = os.path.join(logs_dir, "syslog.json")
    entries = 0
    try:
        if os.path.exists(json_path):
            with open(json_path, 'r', encoding=FORMAT) as jf:
                entries = sum(1 for _ in jf)
    except Exception as e:
        print(f"[ERROR] Counting syslog entries before purge: {e}")

    try:
        removed_files = 0
        for fname in os.listdir(logs_dir):
            if fname.lower().endswith('.json'):
                p = os.path.join(logs_dir, fname)
                try:
                    os.remove(p)
                    removed_files += 1
                except Exception as e:
                    print(f"[ERROR] Removing {p}: {e}")
        try:
            conn.sendall(f"[SERVER] SUCCESS: {entries} indexed log entries have been erased.".encode(FORMAT))
        except Exception:
            pass
        try:
            purge_elapsed = time.time() - purge_start
        except Exception:
            purge_elapsed = 0.0
        print(f"[TASK] from {addr} erased={entries} files_removed={removed_files} took {purge_elapsed:.2f}s")
    except Exception as e:
        try:
            conn.sendall(f"[SERVER] ERROR: Purge failed: {e}".encode(FORMAT))
        except Exception:
            pass


def process_query(conn, header, addr):
    """Process a QUERY request. Handles all supported query types and sends responses."""
    try:
        _, qtype, param = header.split("|", 2)
    except Exception as e:
        try:
            conn.sendall(f"ERROR Invalid QUERY header: {e}".encode(FORMAT))
        except Exception:
            pass
        return

    qtype = qtype.upper()
    proc_start = time.time()
    # reuse existing query-handling logic from the original handle_client
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

        if not os.path.exists(json_path):
            try:
                conn.sendall(f"ERROR syslog.jsonl not found".encode(FORMAT))
            except Exception:
                pass
            return
        try:
            out_dict = load_syslog_from_jsonl(json_path)
        except Exception as e:
            try:
                conn.sendall(f"ERROR reading syslog.jsonl: {e}".encode(FORMAT))
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
                conn.sendall(f"NOTFOUND No valid entries found for date '{date_string}'".encode(FORMAT))
            except Exception:
                pass
            return

        resp_lines = [f"Found {len(lines)} matching entries for date '{date_string}':"]
        for i, l in enumerate(lines, start=1):
            resp_lines.append(f"{i}. {l}")

        resp_text = "\n".join(resp_lines)
        try:
            conn.sendall(resp_text.encode(FORMAT))
        except Exception:
            pass
        try:
            elapsed = time.time() - proc_start
        except Exception:
            elapsed = 0.0
        try:
            match_count = len(lines)
        except Exception:
            match_count = 'unknown'
        print(f"[TASK] {qtype} from {addr} param='{param}' matches={match_count} took {elapsed:.2f}s")
        return

    if qtype == "SEARCH_HOST":
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
                conn.sendall(f"ERROR syslog.jsonl not found".encode(FORMAT))
            except Exception:
                pass
            return
        try:
            out_dict = load_syslog_from_jsonl(json_path)
        except Exception as e:
            try:
                conn.sendall(f"ERROR reading syslog.jsonl: {e}".encode(FORMAT))
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
        try:
            elapsed = time.time() - proc_start
        except Exception:
            elapsed = 0.0
        try:
            match_count = len(lines)
        except Exception:
            match_count = 'unknown'
        print(f"[TASK] {qtype} from {addr} param='{param}' matches={match_count} took {elapsed:.2f}s")

        return

    try:
        conn.sendall(f"ERROR Unknown QUERY type: {qtype}".encode(FORMAT))
    except Exception:
        pass
    return

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
        # Decide lock type: queries are readers; INGEST and PURGE are writers.
        is_ingest = header.startswith("INGEST|")
        is_query = header.startswith("QUERY|")
        is_purge = header.strip().upper() == "PURGE"

        # FIFO sequencing
        global next_seq, next_to_start
        with seq_cond:
            my_seq = next_seq
            next_seq += 1
            while my_seq != next_to_start:
                seq_cond.wait()

        if is_ingest or is_purge:
            # writer: block all readers and writers, then dispatch domain handler
            data_lock.acquire_write()
            # mark as started so next in FIFO may begin
            with seq_cond:
                next_to_start += 1
                seq_cond.notify_all()
            try:
                if is_ingest:
                    process_ingest(conn, header, addr)
                else:
                    process_purge(conn, addr)
            finally:
                data_lock.release_write()
        elif is_query:
            # reader: allow concurrent queries unless a writer is waiting/active
            data_lock.acquire_read()
            # mark as started so next in FIFO may begin
            with seq_cond:
                next_to_start += 1
                seq_cond.notify_all()
            try:
                process_query(conn, header, addr)
            finally:
                # release reader lock after handling QUERY
                try:
                    data_lock.release_read()
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
    parser = argparse.ArgumentParser(description="Start the syslog server")
    parser.add_argument('--host', help='IP or hostname to bind to')
    parser.add_argument('--port', type=int, help='Port to listen on')
    args = parser.parse_args()

    IP = args.host
    PORT = args.port
    ADDR = (IP, PORT)

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