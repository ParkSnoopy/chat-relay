"""Smoke test for chat-relay: needs a running server on 127.0.0.1:9000.

    cargo run -- 127.0.0.1:9000 &
    python3 tests/relay_smoke.py
"""
import json, socket, threading, time, base64

ADDR = ("127.0.0.1", 9000)

class Client:
    def __init__(self):
        self.sock = socket.create_connection(ADDR, timeout=5)
        self.f = self.sock.makefile("rb")
        self.inbox = []
        self.lock = threading.Lock()
        self.alive = True
        self.t = threading.Thread(target=self._read, daemon=True)
        self.t.start()

    def _read(self):
        try:
            for line in self.f:
                msg = json.loads(line)
                with self.lock:
                    self.inbox.append(msg)
        except Exception:
            pass
        self.alive = False

    def close(self):
        # makefile holds the fd; shutdown() is what actually sends FIN.
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
        self.sock.sendall(data)

    def wait_for(self, pred, timeout=2.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for m in self.inbox:
                    if pred(m):
                        return m
            time.sleep(0.05)
        return None

def check(label, cond):
    print(("PASS" if cond else "FAIL"), label)
    assert cond, label

# 1. alice registers first (deterministic order), then bob
alice = Client(); bob = Client()
alice.send({"type": "register", "name": "alice"})
wa = alice.wait_for(lambda m: m.get("type") == "welcome" and m.get("user") == "alice")
check("welcome with token (alice)", wa and wa.get("token"))
alice_token = wa["token"]
bob.send({"type": "register", "name": "bob"})
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
eve.send({"type": "register", "name": "alice"})
check("dup name rejected", eve.wait_for(lambda m: m.get("type") == "error" and m.get("error") == "name taken"))

# 3. msg before register rejected
anon = Client()
anon.send({"type": "msg", "payload": "x"})
check("msg before register rejected", anon.wait_for(lambda m: m.get("error") == "register first"))

# 4. fan-out: msg from alice reaches alice, bob, eve(not registered) not
payload = base64.b64encode(b"\xde\xad\xbe\xef-\xec\x95\x88\xeb\x85\x95").decode()
alice.send({"type": "msg", "payload": payload, "kind": "file"})
check("sender gets own msg", alice.wait_for(lambda m: m.get("from") == "alice" and m.get("payload") == payload and m.get("kind") == "file"))
check("bob gets msg", bob.wait_for(lambda m: m.get("from") == "alice" and m.get("payload") == payload))
check("unregistered peer gets nothing", eve.wait_for(lambda m: m.get("type") == "msg", timeout=0.5) is None)

# 5. disconnect and reclaim name via token
bob.close()
check("existing user sees left", alice.wait_for(lambda m: m.get("type") == "left" and m.get("user") == "bob"))
time.sleep(0.3)
bob2 = Client()
bob2.send({"type": "register", "name": "bob", "token": bob_token})
wb2 = bob2.wait_for(lambda m: m.get("type") == "welcome" and m.get("user") == "bob" and m.get("token") == bob_token)
check("token reclaim", wb2 is not None)

# 6. reclaim with wrong token fails while name free? name is now occupied by bob2 -> rejected
bob3 = Client()
bob3.send({"type": "register", "name": "bob", "token": "deadbeef"})
check("wrong token + taken name rejected", bob3.wait_for(lambda m: m.get("error") == "name taken"))

# 7. garbage json -> error, connection survives
anon.send(b"not json\n")
check("bad json error", anon.wait_for(lambda m: m.get("error") == "bad json"))

# 8. alice disconnects, name freed, plain re-register works
alice.close()
def wait_name_free():
    end = time.time() + 3.0
    while time.time() < end:
        c = Client()
        c.send({"type": "register", "name": "alice"})
        m = c.wait_for(lambda m: m.get("type") in ("welcome", "error"))
        if m and m.get("type") == "welcome":
            return c
        c.close()
        time.sleep(0.2)
    return None
alice2 = wait_name_free()
check("name freed after disconnect", alice2 is not None)

print("ALL PASS")
