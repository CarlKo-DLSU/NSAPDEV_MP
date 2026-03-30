import os
import socket
import sys
import shlex

#IP = "103.231.240.136"
#PORT = 11305
SIZE = 1024
FORMAT = "utf-8"
INGEST_CMD = "INGEST"

def is_text_file(path: str) -> bool:
    try:
        with open(path, "r", encoding=FORMAT) as f:
            f.read(1024)
        return True
    except Exception:
        return False

def send_file(path: str, host: str, port: int):
    filename = os.path.basename(path)
    filesize = os.path.getsize(path)
    addr = (host, port)
    try:
        with socket.create_connection(addr) as s:
            header = f"INGEST|{filename}|{filesize}\n"
            s.sendall(header.encode(FORMAT))
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(SIZE)
                    if not chunk:
                        break
                    s.sendall(chunk)
            # wait for server acknowledgment
            ack = s.recv(SIZE).decode(FORMAT)
            print(f"[SERVER] {ack}")
    except Exception as e:
        print(f"Connection error: {e}")

def main():
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line.lower() in ("quit", "exit", "disconnect"):
            break
        # support quoted args (e.g. QUERY 1.2.3.4:1234 SEARCH_DATE "Feb 22")
        try:
            parts = shlex.split(line)
        except Exception:
            parts = line.split()
        if len(parts) == 0:
            continue
        cmd = parts[0].upper()
        if cmd == "QUERY":
            # expected: QUERY <IP_or_DNS>:<Port> SEARCH_DATE "<date_string>" OR
            #           QUERY <IP_or_DNS>:<Port> SEARCH_HOST <hostname>
            if len(parts) < 4:
                print('Usage: QUERY <IP_or_DNS>:<Port> SEARCH_DATE "<date_string>" or QUERY <IP_or_DNS>:<Port> SEARCH_HOST <hostname>')
                continue
            addr_part = parts[1]
            qcmd = parts[2].upper()
            if qcmd not in ("SEARCH_DATE", "SEARCH_HOST", "SEARCH_DAEMON", "SEARCH_SEVERITY", "SEARCH_KEYWORD", "COUNT_KEYWORD"):
                print('Unknown QUERY type. Supported: SEARCH_DATE, SEARCH_HOST, SEARCH_DAEMON, SEARCH_SEVERITY, SEARCH_KEYWORD, COUNT_KEYWORD')
                continue
            if qcmd == "SEARCH_DATE":
                # parameter: single token unless quoted (shlex preserves quoted strings)
                date_string = parts[3]
            else:
                # SEARCH_HOST: single token hostname
                date_string = None
                # parts[3] may be hostname or daemon depending on qcmd
                if qcmd == "SEARCH_HOST":
                    hostname = parts[3]
                elif qcmd == "SEARCH_DAEMON":
                    daemon = parts[3]
                elif qcmd == "SEARCH_SEVERITY":
                    # SEARCH_SEVERITY: single token severity (e.g. ERROR, FATAL)
                    severity = parts[3]
                elif qcmd == "SEARCH_KEYWORD":
                    # parameter: single token unless quoted
                    keyword = parts[3]
                else:
                    # COUNT_KEYWORD: parameter: single token unless quoted
                    keyword = parts[3]
            if ":" not in addr_part:
                print("Address must be in the form <IP_or_DNS>:<Port>")
                continue
            host, port_str = addr_part.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                print("Invalid port:", port_str)
                continue

            print(f"[System Message] Sending query...")
            try:
                with socket.create_connection((host, port)) as s:
                    if qcmd == "SEARCH_DATE":
                        header = f"QUERY|SEARCH_DATE|{date_string}\n"
                    elif qcmd == "SEARCH_HOST":
                        header = f"QUERY|SEARCH_HOST|{hostname}\n"
                    elif qcmd == "SEARCH_DAEMON":
                        header = f"QUERY|SEARCH_DAEMON|{daemon}\n"
                    elif qcmd == "SEARCH_SEVERITY":
                        header = f"QUERY|SEARCH_SEVERITY|{severity}\n"
                    elif qcmd == "SEARCH_KEYWORD":
                        header = f"QUERY|SEARCH_KEYWORD|{keyword}\n"
                    else:
                        header = f"QUERY|COUNT_KEYWORD|{keyword}\n"
                    s.sendall(header.encode(FORMAT))
                    # read until EOF
                    chunks = []
                    while True:
                        data = s.recv(SIZE)
                        if not data:
                            break
                        chunks.append(data)
                    if chunks:
                        resp = b"".join(chunks).decode(FORMAT, errors="replace")
                        lines = resp.splitlines()
                        for i, ln in enumerate(lines):
                            if i == 0:
                                print(f"[Server Response] {ln}")
                            else:
                                print(ln)
                    else:
                        print("[Server Response] (no response)")
            except Exception as e:
                print(f"Connection error: {e}")
            continue
        # PURGE command: PURGE <IP_or_DNS>:<Port>
        if cmd == "PURGE":
            if len(parts) != 2:
                print("Usage: PURGE <IP_or_DNS>:<Port>")
                continue
            addr_part = parts[1]
            if ":" not in addr_part:
                print("Address must be in the form <IP_or_DNS>:<Port>")
                continue
            host, port_str = addr_part.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                print("Invalid port:", port_str)
                continue
            try:
                with socket.create_connection((host, port)) as s:
                    header = "PURGE\n"
                    s.sendall(header.encode(FORMAT))
                    chunks = []
                    while True:
                        data = s.recv(SIZE)
                        if not data:
                            break
                        chunks.append(data)
                    if chunks:
                        resp = b"".join(chunks).decode(FORMAT, errors="replace")
                        lines = resp.splitlines()
                        for i, ln in enumerate(lines):
                            if i == 0:
                                print(f"[Server Response] {ln}")
                            else:
                                print(ln)
                    else:
                        print("[Server Response] (no response)")
            except Exception as e:
                print(f"Connection error: {e}")
            continue

        # otherwise fallthrough to existing INGEST handling
        if cmd != INGEST_CMD:
            print("Unknown command. Use: INGEST <file_path> <IP:Port>")
            continue
        if len(parts) < 3:
            print("Usage: INGEST <file_path> <IP_or_DNS>:<Port>")
            continue
        file_path = parts[1]
        addr_part = parts[2]
        if not os.path.isfile(file_path):
            print("File does not exist:", file_path)
            continue
        if not is_text_file(file_path):
            print("File is not a readable text file:", file_path)
            continue
        if ":" not in addr_part:
            print("Address must be in the form <IP_or_DNS>:<Port>")
            continue
        host, port_str = addr_part.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            print("Invalid port:", port_str)
            continue
        print(f"Ingesting '{file_path}' to {host}:{port}...")
        send_file(file_path, host, port)

if __name__ == "__main__":
    main()