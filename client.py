import os
import socket
import sys

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
        parts = line.split(maxsplit=2)
        if len(parts) == 0:
            continue
        cmd = parts[0].upper()
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