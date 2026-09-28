import threading
import time
import webbrowser
from flask import Flask, redirect, render_template
from network_monitoring import NetworkScan


app = Flask(__name__)

# Results of the last scan, shared between requests so a page load doesn't trigger a new scan
cache = {"devices": [], "scanned_at": None, "network": None, "isolation_note": None}
scan_lock = threading.Lock()

def run_scan():

    with scan_lock:
        scanner = NetworkScan()
        cache["devices"] = scanner.do_scan()
        cache["network"] = scanner.network
        cache["isolation_note"] = scanner.isolation_note
        cache["scanned_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

@app.route("/")
def index():
    if cache["scanned_at"] is None:
        run_scan()

    return render_template("index.html", **cache)

@app.route("/refresh", methods=["POST"])
def refresh():
    run_scan()
    return redirect("/")

if __name__ == "__main__":
    url = "http://127.0.0.1:5000"
    print(f"\nOpening {url} in your browser (Ctrl+C to stop)\n")
    # Give the server a moment to start before the browser requests the page
    threading.Timer(1.0, webbrowser.open, args=[url]).start()
    app.run(host="127.0.0.1", port=5000)
