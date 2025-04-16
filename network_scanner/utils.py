# network_scanner/utils.py
import sys
import time
import threading
import itertools
from typing import Optional
from mac_vendor_lookup import MacLookup, VendorNotFoundError

# --- Inicialización Segura de MacLookup ---
try:
    mac_lookup = MacLookup()
except Exception as e:
    print(f"[!] Advertencia: Error inicializando MacLookup: {e}. Lookup de fabricante desactivado.", file=sys.stderr)
    mac_lookup = None

# --- Clase Spinner (Context Manager) ---
class Spinner:
    """Gestor de contexto para mostrar un spinner en la consola."""
    def __init__(self, message: str = "Procesando...", delay: float = 0.1):
        self.spinner = itertools.cycle(['-', '\\', '|', '/'])
        self.delay = delay
        self.message = message
        self.running = False
        self.spinner_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _spin(self):
        while not self._stop_event.is_set():
            sys.stdout.write(f"{self.message} {next(self.spinner)}")
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b' * (len(self.message) + 2)) # Retrocede para borrar

    def start(self):
        if not self.running:
            self.running = True
            self._stop_event.clear()
            self.spinner_thread = threading.Thread(target=self._spin, daemon=True)
            self.spinner_thread.start()

    def stop(self):
        if self.running:
            self._stop_event.set()
            if self.spinner_thread:
                self.spinner_thread.join(timeout=self.delay * 3) # Espera un poco
            # Limpia la línea
            sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
            sys.stdout.flush()
            self.running = False
            self.spinner_thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

# --- Función MAC Vendor Lookup ---
def get_mac_vendor(mac_address: Optional[str]) -> str:
    """Obtiene el fabricante de una dirección MAC."""
    if not mac_lookup or not mac_address or 'N/A' in mac_address:
        return "N/A"
    try:
        formatted_mac = mac_address.replace("-", ":").upper()
        return mac_lookup.lookup(formatted_mac)
    except (VendorNotFoundError, ValueError):
        return "Desconocido"
    except Exception:
        return "Error Lookup"