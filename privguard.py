import sys, os, csv, json, hmac, hashlib, datetime as dt
from collections import defaultdict 

SECRET_KEY = "Browniee_2019"
FAILED_LOGIN_WINDOW_MINUTES = 10
FAILED_LOGIN_THRESHOLD = 3
LARGE_TRANSFER_MB_THRESHOLD = 100
OUTPUT_DIR = "output"   

def pseudonymize(value: str, prefix: str) -> str:
    """Consistent pseudonym using HMAC-SHA256 (truncated)"""
    digest = hmac.new(SECRET_KEY.encode('utf-8'), value.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{prefix}_{digest[:12]}"

def parse_timestamp(ts: str) -> dt.datetime:
    try:
        return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return dt.datetime.fromisoformat(ts.replace('Z', '+00:00'))

def parse_size(size_str: str) -> float:
    if not size_str:
        return 0.0
    s = size_str.strip().upper()
    if s.endswith("MB"):
        return float(s[:-2])
    if s.endswith("GB"):
        return float(s[:-2]) * 1024.0
    if s.endswith("KB"):
        return float(s[:-2]) / 1024.0
    try:
        return float(s)
    except:
        return 0.0

def parse_log_line(line: str):
    line = line.strip()
    if not line:
        return None
    parts = line.split()
    timestamp = parts[0]
    kv = {}
    for token in parts[1:]:
        if '=' in token:
            k, v = token.split('=', 1)
            kv[k] = v
    return timestamp, kv

def process_logs(input_path: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    mappings = {"users": {}, "ips": {}}
    anonymized_rows = []
    alerts = []

    failed_logins = defaultdict(list)
    last_ip_for_user = {}

    with open(input_path, 'r', encoding='utf-8') as fh:
        lines = fh.readlines()

    for line in lines:
        parsed = parse_log_line(line)
        if not parsed:
            continue
        ts_raw, kv = parsed
        try:
            ts = parse_timestamp(ts_raw)
        except Exception:
            continue

        user = kv.get('user', '[unknown]')
        ip = kv.get('ip', '[unknown]')
        action = kv.get('action', '[unknown]')
        status = kv.get('status', '')
        size = kv.get('size', '')
        extra = {k:v for k,v in kv.items() if k not in ('user','ip','action','status','size')}

        if user not in mappings['users']:
            mappings['users'][user] = pseudonymize(user, 'USR')
        pseudo_user = mappings['users'][user]

        if ip not in mappings['ips']:
            mappings['ips'][ip] = pseudonymize(ip, 'IP')
        pseudo_ip = mappings['ips'][ip]

        anonymized_rows.append({
            'timestamp': ts_raw,
            'pseudouser': pseudo_user,
            'pseudoip': pseudo_ip,
            'action': action,
            'status': status,
            'size': size,
            'extra': json.dumps(extra)
        })

        if action == 'login' and status.lower() == 'failed':
            failed_logins[pseudo_user].append(ts)
            cutoff = ts - dt.timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
            failed_logins[pseudo_user] = [t for t in failed_logins[pseudo_user] if t >= cutoff]
            if len(failed_logins[pseudo_user]) >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    'timestamp': ts_raw,
                    'type': 'Brute-force / repeated failed logins',
                    'pseudouser': pseudo_user,
                    'details': f"{len(failed_logins[pseudo_user])} failed logins within {FAILED_LOGIN_WINDOW_MINUTES} minutes from {pseudo_ip}"
                })

        if action == 'login' and status.lower() == 'success':
            if 0 <= ts.hour < 4:
                alerts.append({
                    'timestamp': ts_raw,
                    'type': 'Odd-hour successful login',
                    'pseudouser': pseudo_user,
                    'details': f"Successful login at {ts.hour:02d}:{ts.minute:02d} from {pseudo_ip}"
                })
            last_ip = last_ip_for_user.get(pseudo_user)
            if last_ip and last_ip != pseudo_ip:
                alerts.append({
                    'timestamp': ts_raw,
                    'type': 'New IP / Device for user',
                    'pseudouser': pseudo_user,
                    'details': f"Login from a different IP: {pseudo_ip} (previous: {last_ip})"
                })
            last_ip_for_user[pseudo_user] = pseudo_ip

        if action in ('download', 'upload') and size:
            size_mb = parse_size(size)
            if size_mb >= LARGE_TRANSFER_MB_THRESHOLD:
                alerts.append({
                    'timestamp': ts_raw,
                    'type': 'Large data transfer',
                    'pseudouser': pseudo_user,
                    'details': f"{action} of {size_mb:.1f} MB from {pseudo_ip}"
                })

        sensitive_actions = ('delete_record','change_password','modify_acl')
        if action in sensitive_actions:
            alerts.append({
                'timestamp': ts_raw,
                'type': 'Sensitive action performed',
                'pseudouser': pseudo_user,
                'details': f"Action {action} performed. Extra: {json.dumps(extra)}"
            })

    # Save CSV
    csv_path = os.path.join(OUTPUT_DIR, 'anonymized_logs.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['timestamp','pseudouser','pseudoip','action','status','size','extra']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in anonymized_rows:
            writer.writerow(r)

    # Save mappings
    mappings_path = os.path.join(OUTPUT_DIR, 'mappings.json')
    with open(mappings_path, 'w', encoding='utf-8') as mf:
        json.dump(mappings, mf, indent=2)

    # Count alerts by type for the graph
    alert_counts = defaultdict(int)
    for a in alerts:
        alert_counts[a['type']] += 1

    # Save HTML Report
    report_path = os.path.join(OUTPUT_DIR, 'privguard_report.html')
    with open(report_path, 'w', encoding='utf-8') as rf:
        rf.write("<html><head><meta charset='utf-8'><title>PrivGuard Report</title>")
        rf.write("<style>body { font-family: Arial, sans-serif; background-color: #f5f7fa; padding: 20px; } h1 { color: #2c3e50; } h2 { color: #34495e; margin-top: 30px; } table { border-collapse: collapse; width: 100%; margin-top: 20px; } th, td { border: 1px solid #ccc; padding: 10px; text-align: left; } th { background-color: #34495e; color: white; } tr:nth-child(even) { background-color: #ecf0f1; } tr:hover { background-color: #dcdde1; }</style></head><body>")
        rf.write("<h1>PrivGuard-Lite Report</h1>")
        rf.write("<h2>Detected Alerts</h2>")
        if not alerts:
            rf.write("<p><em>No alerts detected.</em></p>")
        else:
            rf.write("<table><tr><th>Timestamp</th><th>Type</th><th>Pseudouser</th><th>Details</th></tr>")
            for a in alerts:
                rf.write(f"<tr><td>{a['timestamp']}</td><td>{a['type']}</td><td>{a['pseudouser']}</td><td>{a['details']}</td></tr>")
            rf.write("</table>") 

        # ✅ Insert Chart.js graph here
        rf.write("""
        <h2>Alerts Summary (Graph)</h2>
        <canvas id="alertsChart" width="600" height="300"></canvas>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
        const ctx = document.getElementById('alertsChart').getContext('2d');
        const alertsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: %s,
                datasets: [{
                    label: 'Number of Alerts',
                    data: %s,
                    backgroundColor: ['#e74c3c','#3498db','#2ecc71','#f39c12','#9b59b6','#1abc9c']
                }]
            },
            options: { responsive: true, plugins: { legend: { display: false } } }
        });
        </script>
        """ % (json.dumps(list(alert_counts.keys())), json.dumps(list(alert_counts.values()))))

        rf.write("<h2>Anonymized Logs (sample)</h2>")
        rf.write("<table><tr><th>Timestamp</th><th>Pseudouser</th><th>PseudoIP</th><th>Action</th><th>Status</th><th>Size</th></tr>")
        for row in anonymized_rows[:200]:
            rf.write("<tr>")
            rf.write(f"<td>{row['timestamp']}</td><td>{row['pseudouser']}</td><td>{row['pseudoip']}</td><td>{row['action']}</td><td>{row['status']}</td><td>{row['size']}</td>")
            rf.write("</tr>")
        rf.write("</table>")
        rf.write("<h2>Notes</h2><ul>")
        rf.write("<li>Pseudonymization uses HMAC-SHA256 with a secret key. Mappings are stored separately.</li>")
        rf.write("<li>Alerts are generated using simple rule-based heuristics for demo purposes.</li>")
        rf.write("<li>Production: rotate secret keys, integrate federated learning or differential privacy for better guarantees.</li>")
        rf.write("</ul></body></html>")

    print("Done. Outputs in:", OUTPUT_DIR)
    print(" -", csv_path)
    print(" -", mappings_path)
    print(" -", report_path)

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv)>=2 else "sample_logs.txt"
    if not os.path.exists(input_file):
        print("Input file not found:", input_file)
        sys.exit(1)
    process_logs(input_file)
