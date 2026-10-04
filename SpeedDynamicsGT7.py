import os, sys, json, time, socket, struct, threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from Crypto.Cipher import Salsa20

APP_NAME = "Speed Dynamics GT7"
HTTP_PORT = 8080
GT7_SEND_PORT = 33739
GT7_RECEIVE_PORT = 33740

KEY = b"Simulator Interface Packet GT7 ver 0.0"[:32]
MAGIC = 0x47375330

state = {
    "connected": False, "packets": 0, "valid": 0, "bytes": 0, "packet_size": 0,
    "speed": 0.0, "rpm": 0, "gear": 0, "throttle": 0, "brake": 0,
    "fuel": 0.0, "fuel_capacity": 0.0, "lap": 0, "total_laps": 0,
    "best_lap_ms": -1, "last_lap_ms": -1, "current_lap_ms": -1,
    "position": 0, "cars": 0, "delta_ms": None, "reference_ms": None,
    "reference_ready": False
}
lock = threading.Lock()

def resource_path(relative):
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def decrypt_v05(packet):
    """Keep the V0.5 working Packet-A decrypt path intact."""
    if len(packet) != 296:
        return None
    iv1 = int.from_bytes(packet[0x40:0x44], "little")
    iv2 = iv1 ^ 0xDEADBEAF
    nonce = iv2.to_bytes(4, "little") + iv1.to_bytes(4, "little")
    try:
        plain = Salsa20.new(key=KEY, nonce=nonce).decrypt(packet)
        if int.from_bytes(plain[:4], "little") == MAGIC:
            return plain
    except Exception:
        pass
    return None

def decrypt_c(packet):
    """Packet-C decoder, kept separate so the known-good V0.5 path is untouched."""
    if len(packet) != 368:
        return None

    iv1 = int.from_bytes(packet[0x40:0x44], "little")

    # Packet C uses the extended telemetry XOR constant.
    for constant in (0xDEADBEEF, 0x55FABB4F, 0xDEADBEAF):
        iv2 = iv1 ^ constant
        nonce = iv2.to_bytes(4, "little") + iv1.to_bytes(4, "little")
        try:
            plain = Salsa20.new(key=KEY, nonce=nonce).decrypt(packet)
            if int.from_bytes(plain[:4], "little") == MAGIC:
                return plain
        except Exception:
            pass

    return None

def f32(data, offset):
    return struct.unpack_from("<f", data, offset)[0]

def i16(data, offset):
    return struct.unpack_from("<h", data, offset)[0]

def i32(data, offset):
    return struct.unpack_from("<i", data, offset)[0]

def parse_v05(packet):
    """The exact working V0.5 fields."""
    return {
        "speed": max(0.0, f32(packet, 0x4C) * 3.6),
        "rpm": max(0, round(f32(packet, 0x3C))),
        "fuel": max(0.0, f32(packet, 0x44)),
        "fuel_capacity": max(0.0, f32(packet, 0x48)),
        "lap": max(0, i16(packet, 0x74)),
        "total_laps": max(0, i16(packet, 0x76)),
        "best_lap_ms": i32(packet, 0x78),
        "last_lap_ms": i32(packet, 0x7C),
        "position": max(0, i16(packet, 0x84)),
        "cars": max(0, i16(packet, 0x86)),
        "gear": packet[0x90] & 0x0F,
        "throttle": round(packet[0x91] / 255 * 100),
        "brake": round(packet[0x92] / 255 * 100)
    }

def parse_c(packet):
    """V0.5 fields plus GT7 current-lap field from Packet C."""
    data = parse_v05(packet[:296])
    data["current_lap_ms"] = i32(packet, 0x140)
    return data

class WebHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api"):
            with lock:
                payload = json.dumps(state).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()

    def log_message(self, *args):
        pass

def start_web_server():
    os.chdir(resource_path("web"))
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), WebHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

class GT7Bridge:
    def __init__(self, ps5_ip, callback):
        self.ps5_ip = ps5_ip
        self.callback = callback
        self.running = False
        self.reference_ms = None
        self.last_lap = None

    def start(self):
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

    def stop(self):
        self.running = False

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", GT7_RECEIVE_PORT))
            sock.settimeout(1.0)
        except Exception as exc:
            self.callback("UDP 33740 FEHLER: " + str(exc))
            return

        self.callback("UDP 33740 bereit · Packet C wird angefordert")
        next_heartbeat = 0.0

        while self.running:
            now = time.monotonic()

            if now >= next_heartbeat:
                try:
                    # Keep the V0.5 socket/ports; only the requested telemetry packet changes.
                    sock.sendto(b"C", (self.ps5_ip, GT7_SEND_PORT))
                except Exception as exc:
                    self.callback("Heartbeat-Fehler: " + str(exc))
                next_heartbeat = now + 1.0

            try:
                raw, _ = sock.recvfrom(4096)

                with lock:
                    state["packets"] += 1
                    state["bytes"] += len(raw)
                    state["packet_size"] = len(raw)

                plain = decrypt_c(raw)

                if plain is None:
                    self.callback(
                        f"UDP empfangen: {len(raw)} Bytes · "
                        "Packet C nicht entschlüsselt"
                    )
                    continue

                parsed = parse_c(plain)

                # Detect completed laps using the same V0.5 lap field.
                lap_number = parsed["lap"]
                if self.last_lap is None:
                    self.last_lap = lap_number
                elif lap_number != self.last_lap:
                    # The previous lap's GT7 current-lap time is the completed lap time.
                    previous_time = None
                    with lock:
                        previous_time = state["current_lap_ms"]

                    if previous_time is not None and previous_time > 0:
                        if self.reference_ms is None or previous_time < self.reference_ms:
                            self.reference_ms = previous_time

                    self.last_lap = lap_number

                delta = None
                if self.reference_ms is not None and parsed["current_lap_ms"] >= 0:
                    delta = parsed["current_lap_ms"] - self.reference_ms

                with lock:
                    state.update(parsed)
                    state["connected"] = True
                    state["valid"] += 1
                    state["reference_ms"] = self.reference_ms
                    state["reference_ready"] = self.reference_ms is not None
                    state["delta_ms"] = delta
                    valid = state["valid"]

                self.callback(
                    f"GT7 LIVE VERBUNDEN · Packet C · "
                    f"{len(raw)} Bytes · gültige Pakete: {valid}"
                )

            except socket.timeout:
                pass
            except Exception as exc:
                self.callback("UDP-Fehler: " + str(exc))

        sock.close()

class Application:
    def __init__(self):
        self.bridge = None
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("640x450")
        self.root.configure(bg="#111111")

        frame = tk.Frame(self.root, bg="#111111")
        frame.pack(fill="both", expand=True, padx=32, pady=25)

        tk.Label(frame, text="SPEED DYNAMICS",
                 font=("Segoe UI", 26, "bold"),
                 fg="#d7b45a", bg="#111111").pack(anchor="w")

        tk.Label(frame, text="GT7 Race Engineer · V0.7 / Packet C",
                 font=("Segoe UI", 11),
                 fg="#aaaaaa", bg="#111111").pack(anchor="w", pady=(0, 22))

        tk.Label(frame, text="IP-Adresse deiner PS5",
                 font=("Segoe UI", 10, "bold"),
                 fg="white", bg="#111111").pack(anchor="w")

        self.ip = tk.StringVar(value="192.168.178.200")
        ttk.Entry(frame, textvariable=self.ip,
                  font=("Segoe UI", 14)).pack(fill="x", pady=(6, 12))

        tk.Button(frame, text="MIT GT7 VERBINDEN",
                  command=self.connect,
                  font=("Segoe UI", 12, "bold"),
                  bg="#d7b45a", fg="#111111",
                  relief="flat", pady=10).pack(fill="x")

        self.status = tk.StringVar(value="Bereit")
        tk.Label(frame, textvariable=self.status,
                 font=("Segoe UI", 11, "bold"),
                 fg="#dddddd", bg="#111111",
                 wraplength=570, justify="left").pack(anchor="w", pady=(16, 8))

        self.diag = tk.StringVar(
            value="Empfangen: 0    Gültig: 0    Bytes: 0    Paket: 0"
        )
        tk.Label(frame, textvariable=self.diag,
                 font=("Consolas", 9),
                 fg="#aaaaaa", bg="#111111").pack(anchor="w", pady=(2, 14))

        self.url = f"http://{get_lan_ip()}:{HTTP_PORT}"
        tk.Label(frame, text="iPhone – im selben WLAN in Safari öffnen:",
                 font=("Segoe UI", 9),
                 fg="#888888", bg="#111111").pack(anchor="w")

        tk.Label(frame, text=self.url,
                 font=("Consolas", 14, "bold"),
                 fg="#d7b45a", bg="#111111").pack(anchor="w", pady=(3, 7))

        tk.Button(frame, text="ADRESSE KOPIEREN",
                  command=self.copy_url,
                  bg="#282828", fg="white",
                  relief="flat", pady=7).pack(fill="x")

        start_web_server()

    def callback(self, text):
        with lock:
            diag = (
                f"Empfangen: {state['packets']}    "
                f"Gültig: {state['valid']}    "
                f"Bytes: {state['bytes']}    "
                f"Paket: {state['packet_size']}"
            )
        self.root.after(
            0, lambda: (self.status.set(text), self.diag.set(diag))
        )

    def connect(self):
        ip = self.ip.get().strip()
        try:
            socket.inet_aton(ip)
        except OSError:
            messagebox.showerror(
                "PS5-IP",
                "Bitte eine gültige PS5-IP eingeben."
            )
            return

        if self.bridge:
            self.bridge.stop()

        with lock:
            state.update({
                "connected": False,
                "packets": 0,
                "valid": 0,
                "bytes": 0,
                "packet_size": 0,
                "delta_ms": None,
                "reference_ms": None,
                "reference_ready": False,
                "current_lap_ms": -1
            })

        self.bridge = GT7Bridge(ip, self.callback)
        self.bridge.start()

    def copy_url(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.url)
        self.status.set("iPhone-Adresse kopiert")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    Application().run()
