#!/usr/bin/env python3

import argparse
import socket
import sys
import time


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Observe UDP packets arriving on a port")
    p.add_argument("--host", default="0.0.0.0", help="Interface/address to bind (default: all)")
    p.add_argument("--port", type=int, required=True, help="UDP port to listen on")
    p.add_argument("--max-bytes", type=int, default=2048, help="Max datagram size to read")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #Allow fast restart if you stop / restart the listener.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    try:
        sock.bind((args.host, args.port))
    except OSError as e:
        print(f"bind failed: {e}", file=sys.stderr)
        return 2
    print(f"Listening for UDP on {args.host}: {args.port}")
    try:
        while True:
            data,(src_ip,src_port) = sock.recvfrom(args.max_bytes)
            ts = time.strftime("%Y-%m-%d% H: % M: %S")
            print(f"{ts} knock dst_port = {args.port} src = {src_ip}:{src_port} bytes = {len(data)}")

    except KeyboardInterrupt:
        print("\nStopping.")
        return 0

    finally:
        sock.close()

if __name__ == "__main__":
    raise SystemExit(main())