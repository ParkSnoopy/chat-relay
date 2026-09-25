"""Smoke test for a running relay in either token admission mode.

Set TEST_RELAY_PORT and TEST_RELAY_TLS_CERT for a TLS listener.
"""
import json, select, socket, ssl, threading, time, os

ADDR = ("127.0.0.1", int(os.environ.get("TEST_RELAY_PORT", "6697")))
AUTH_REQUIRED = os.environ.get("TEST_RELAY_AUTH_REQUIRED", "true") == "true"
SERVER_TOKEN = os.environ["CHAT_RELAY_AUTH_TOKEN"] if AUTH_REQUIRED else None
TLS_CERT = os.environ.get("TEST_RELAY_TLS_CERT")

class Client:
    def __init__(self):
        self.sock = socket.create_connection(ADDR, timeout=5)
        if TLS_CERT:
            self.sock = ssl.create_default_context(cafile=TLS_CERT).wrap_socket(self.sock, server_hostname="localhost")
        self.sock.settimeout(0.25 if TLS_CERT else None)
        self.inbox = []
        self.lock = threading.Lock()
        self.io_lock = threading.Lock()
        self.alive = True
        self.t = threading.Thread(target=self._read, daemon=True)
        self.t.start()

    def _read(self):
        buffer = b""
        try:
            while True:
                if isinstance(self.sock, ssl.SSLSocket):
                    if not self.sock.pending() and not select.select([self.sock], [], [], 0.05)[0]:
                        continue
                    try:
                        with self.io_lock:
                            data = self.sock.recv(65536)
                    except socket.timeout:
                        continue
                else:
                    data = self.sock.recv(65536)
                if not data:
                    break
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    with self.lock:
                        self.inbox.append(json.loads(line))
        except (OSError, ValueError):
            pass
        self.alive = False

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def send(self, obj):
        if isinstance(obj, (bytes, str)):
            data = obj if isinstance(obj, bytes) else obj.encode()
            if not data.endswith(b"\n"):
                data += b"\n"
        else:
            data = (json.dumps(obj) + "\n").encode()
        with self.io_lock:
            self.sock.sendall(data)

    def register(self, name, token=None):
        msg = {"type": "register", "name": name}
        if AUTH_REQUIRED:
            msg["server_token"] = SERVER_TOKEN
        if token is not None:
            msg["token"] = token
        self.send(msg)

    def wait_for(self, pred, timeout=2.0, since=0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for m in self.inbox[since:]:
                    if pred(m):
                        return m
            time.sleep(0.05)
        return None

def check(label, cond):
    print(("PASS" if cond else "FAIL"), label)
    assert cond, label

# 1. alice registers first (deterministic order), then bob
alice = Client(); bob = Client()
alice.register("alice")
wa = alice.wait_for(lambda m: m.get("type") == "welcome" and m.get("user") == "alice")
check("welcome with token (alice)", wa and wa.get("token"))
alice_token = wa["token"]
bob.register("bob")
wb = bob.wait_for(lambda m: m.get("type") == "welcome" and m.get("user") == "bob")
check("welcome with token (bob)", wb and wb.get("token"))
bob_token = wb["token"]
check("existing user sees joined", alice.wait_for(lambda m: m.get("type") == "joined" and m.get("user") == "bob"))

# 1b. users endpoint lists everyone, and is refused before register
alice.send({"type": "users"})
u = alice.wait_for(lambda m: m.get("type") == "users")
check("users endpoint", u is not None and set(u.get("users", [])) == {"alice", "bob"})
anon = Client()
anon.send({"type": "users"})
check("users before register rejected", anon.wait_for(lambda m: m.get("error") == "register first"))

# 2. duplicate name rejected
eve = Client()
eve.register("alice")
check("dup name rejected", eve.wait_for(lambda m: m.get("type") == "error" and m.get("error") == "name taken"))

unauthorized = Client()
unauthorized.send({"type": "register", "name": "mallory", "server_token": "wrong"})
check("token handling matches admission mode", unauthorized.wait_for(lambda m: m.get("error") == ("unauthorized" if AUTH_REQUIRED else "invalid registration")))
if AUTH_REQUIRED:
    missing = Client()
    missing.send({"type": "register", "name": "mallory"})
    check("missing admission token rejected", missing.wait_for(lambda m: m.get("error") == "unauthorized"))
invalid = Client()
invalid.register("fake\nlog")
check("unsafe name rejected", invalid.wait_for(lambda m: m.get("error") == "invalid name"))

# 3. msg before register rejected
anon = Client()
anon.send({"type": "msg", "payload": "x"})
check("msg before register rejected", anon.wait_for(lambda m: m.get("error") == "register first"))

# 4. fan-out: payload structure belongs to the sender, not the relay
payload = {"opaque": [1, {"nested": True}]}
alice.send({"type": "msg", "payload": payload, "broadcast": True})
check("sender gets own msg", alice.wait_for(lambda m: m.get("from") == "alice" and m.get("payload") == payload))
check("bob gets msg", bob.wait_for(lambda m: m.get("from") == "alice" and m.get("payload") == payload))
check("unregistered peer gets nothing", eve.wait_for(lambda m: m.get("type") == "msg", timeout=0.5) is None)

carol = Client()
carol.register("carol")
check("third member registered", carol.wait_for(lambda m: m.get("type") == "welcome"))
direct_payload = {"opaque": [2, {"different": False}]}
alice.send({"type": "msg", "payload": direct_payload, "to": ["bob"]})
check("direct recipient gets message", bob.wait_for(lambda m: m.get("payload") == direct_payload and m.get("from") == "alice"))
check("non-recipient gets no direct message", carol.wait_for(lambda m: m.get("payload") == direct_payload, timeout=0.5) is None)
multi_payload = {"opaque": [3]}
alice.send({"type": "msg", "payload": multi_payload, "to": ["bob", "carol", "bob", "alice"]})
check("one request reaches both recipients", all(c.wait_for(lambda m: m.get("payload") == multi_payload and m.get("to") == ["bob", "carol", "bob", "alice"]) for c in (bob, carol)))
check("sender echoed", alice.wait_for(lambda m: m.get("payload") == multi_payload))
with alice.lock, bob.lock:
    check("sender and duplicate recipient delivered once", all(sum(m.get("payload") == multi_payload for m in c.inbox) == 1 for c in (alice, bob)))
rejected = {"opaque": [4]}
alice.send({"type": "msg", "payload": rejected, "to": ["bob", "missing"]})
check("missing recipient rejects entire request", alice.wait_for(lambda m: m.get("error") == "user unavailable") and bob.wait_for(lambda m: m.get("payload") == rejected, timeout=0.5) is None)
for recipients in ("bob", [], ["bob", 1], ["bob"] * 65):
    with alice.lock:
        previous = len(alice.inbox)
    alice.send({"type": "msg", "payload": rejected, "to": recipients})
    check("invalid recipient array rejected", alice.wait_for(lambda m: m.get("error") == "invalid message", since=previous))
alice.send({"type": "msg", "payload": payload})
check("no implicit broadcast", alice.wait_for(lambda m: m.get("error") == "invalid message"))
with alice.lock:
    previous = len(alice.inbox)
alice.send({"type": "msg", "payload": payload, "broadcast": True, "extension": "outside-envelope"})
check("non-routing field rejected", alice.wait_for(lambda m: m.get("error") == "invalid message", since=previous))
alice.send({"type": "ping"})
check("registered keepalive", alice.wait_for(lambda m: m.get("type") == "pong"))

# 5. reclaim an active name via token; old socket loses authority
bob2 = Client()
bob2.register("bob", bob_token)
wb2 = bob2.wait_for(lambda m: m.get("type") == "welcome" and m.get("user") == "bob")
check("token reclaim rotates token", wb2 is not None and wb2.get("token") != bob_token)
bob.t.join(timeout=3)
check("old socket closed", not bob.alive)
bob.close()

# 6. reclaim with wrong token fails while name free? name is now occupied by bob2 -> rejected
bob3 = Client()
bob3.register("bob", bob_token)
check("wrong token + taken name rejected", bob3.wait_for(lambda m: m.get("error") == "name taken"))

# 7. garbage json -> error, connection survives
anon.send(b"not json\n")
check("bad json error", anon.wait_for(lambda m: m.get("error") == "bad json"))
if not TLS_CERT:
    oversized = Client()
    try:
        oversized.send(b"x" * (256 * 1024 + 1))
    except OSError:
        pass
    oversized.t.join(timeout=3)
    check("oversized line closes socket", not oversized.alive)

# 8. alice disconnects; name remains reserved until token expiry
alice.close()
check("disconnect announced", carol.wait_for(lambda m: m.get("type") == "left" and m.get("user") == "alice"))
impostor = Client()
impostor.register("alice")
check("disconnected name reserved", impostor.wait_for(lambda m: m.get("error") == "name taken"))
alice2 = Client()
alice2.register("alice", alice_token)
check("owner reclaims disconnected name", alice2.wait_for(lambda m: m.get("type") == "welcome" and m.get("user") == "alice"))
stale = Client()
stale.register("alice", alice_token)
check("old token revoked on new claim", stale.wait_for(lambda m: m.get("error") == "name taken"))

race = [Client(), Client()]
threads = [threading.Thread(target=c.register, args=("race",)) for c in race]
for thread in threads: thread.start()
for thread in threads: thread.join()
results = [c.wait_for(lambda m: m.get("type") in ("welcome", "error")) for c in race]
check("concurrent claims have one winner", all(m is not None for m in results) and sorted(m["type"] for m in results if m is not None) == ["error", "welcome"])

print("ALL PASS")
