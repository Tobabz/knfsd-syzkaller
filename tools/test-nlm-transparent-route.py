#!/usr/bin/env python3
"""Isolated proof of the NLM relay return route and lockd callback path.

Run as root: python3 tools/test-nlm-transparent-route.py. This creates only
two disposable network namespaces and removes them on exit.
"""

import os
import socket
import subprocess
import sys
import time


SERVER = "198.18.66.1"
CLIENT = "198.18.66.2"
FRONT_PORT = 4045
BACK_PORT = 4050
CALLBACK_PORT = 4046


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def server():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER, BACK_PORT))
        listener.listen()
        listener.settimeout(8)
        print("server-ready", flush=True)
        conn, peer = listener.accept()
        with conn:
            conn.settimeout(8)
            assert peer[0] == CLIENT, peer
            assert conn.recv(16) == b"LOCK", "request missing"
            conn.sendall(b"GRANT")
    with socket.create_connection((CLIENT, CALLBACK_PORT), timeout=8) as conn:
        conn.settimeout(8)
        conn.sendall(b"GRANTED")
        assert conn.recv(16) == b"ACK", "callback ack missing"
    print("backend-saw-client-ip; callback-acknowledged", flush=True)


def relay():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER, FRONT_PORT))
        listener.listen()
        listener.settimeout(8)
        print("relay-ready", flush=True)
        inbound, peer = listener.accept()
        with inbound, socket.socket() as outbound:
            assert peer[0] == CLIENT, peer
            inbound.settimeout(8)
            outbound.settimeout(8)
            outbound.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
            outbound.bind((peer[0], 0))
            outbound.connect((SERVER, BACK_PORT))
            outbound.sendall(inbound.recv(16))
            inbound.sendall(outbound.recv(16))
    print("relay-return-path-complete", flush=True)


def client():
    with socket.socket() as callback:
        callback.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        callback.bind((CLIENT, CALLBACK_PORT))
        callback.listen()
        callback.settimeout(8)
        print("client-ready", flush=True)
        with socket.create_connection((SERVER, FRONT_PORT), timeout=8) as conn:
            conn.settimeout(8)
            conn.sendall(b"LOCK")
            assert conn.recv(16) == b"GRANT", "reply missing"
        incoming, peer = callback.accept()
        with incoming:
            incoming.settimeout(8)
            assert peer[0] == SERVER, peer
            assert incoming.recv(16) == b"GRANTED", "callback missing"
            incoming.sendall(b"ACK")
    print("client-received-reply-and-callback", flush=True)


def main():
    if len(sys.argv) > 1:
        {"server": server, "relay": relay, "client": client}[sys.argv[1]]()
        return
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    suffix = str(os.getpid())
    server_ns = "nlms" + suffix
    client_ns = "nlmc" + suffix
    link_s = "ns" + suffix
    link_c = "nc" + suffix
    created = []
    children = []
    try:
        for ns in (server_ns, client_ns):
            command("ip", "netns", "add", ns)
            created.append(ns)
        command("ip", "link", "add", link_s, "type", "veth", "peer", "name", link_c)
        command("ip", "link", "set", link_s, "netns", server_ns)
        command("ip", "link", "set", link_c, "netns", client_ns)
        for ns, link, address in ((server_ns, link_s, SERVER),
                                  (client_ns, link_c, CLIENT)):
            command("ip", "-n", ns, "link", "set", "lo", "up")
            command("ip", "-n", ns, "addr", "add", address + "/30", "dev", link)
            command("ip", "-n", ns, "link", "set", link, "up")
        # Only backend replies to the transparent socket are delivered locally.
        # Ordinary server-initiated callbacks still use the veth route.
        command("ip", "-n", server_ns, "route", "add", "local", CLIENT + "/32",
                "dev", "lo", "table", "100")
        command("ip", "-n", server_ns, "rule", "add", "pref", "100", "from", SERVER,
                "ipproto", "tcp", "sport", str(BACK_PORT), "lookup", "100")
        for ns, role in ((server_ns, "server"), (server_ns, "relay"),
                         (client_ns, "client")):
            child = subprocess.Popen(["ip", "netns", "exec", ns,
                                      sys.executable, __file__, role],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True)
            children.append((role, child))
            if role != "client":
                time.sleep(0.2)
        failed = False
        for role, child in children:
            try:
                output, _ = child.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                output, _ = child.communicate()
                failed = True
            print(role + ": " + output.strip(), flush=True)
            failed |= child.returncode != 0
        if failed:
            raise SystemExit(1)
    finally:
        for _, child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
        # If creation failed before the veth entered a namespace, remove it
        # from the root namespace as well.
        subprocess.run(["ip", "link", "del", link_s],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for ns in reversed(created):
            command("ip", "netns", "del", ns)


if __name__ == "__main__":
    main()
