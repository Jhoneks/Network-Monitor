from flask import Flask
from network_monitoring import NetworkScan


app = Flask(__name__)

@app.route("/")
def yo():
    scanner = NetworkScan()
    devices = scanner.do_scan()
    ret_str = "<h1 style='color: blue;'>Network Monitor</h1><br><h3>"
    for data in devices:
        ret_str += f" {data['IP']}&nbsp;&nbsp; {data['MAC']}&nbsp;&nbsp; {data['Hostname']} "
    ret_str += "</h3>"
    return ret_str

if __name__ == "__main__":
    app.run()