from flask import Flask, jsonify, render_template_string
import os
import psutil

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Botリソース監視</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reset-css@5.0.1/reset.min.css" />
    <link href="https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/odometer@0.4.8/themes/odometer-theme-default.min.css" />
    <script src="https://cdn.jsdelivr.net/npm/odometer@0.4.8/odometer.min.js"></script>
    <style>
        body { font-family: 'SF Pro Display', 'Segoe UI', Arial, sans-serif; background: var(--bg, #f8f8ff); color: var(--fg, #222); margin:0; transition: background 0.3s, color 0.3s; }
        .container { max-width: 800px; margin: 2.5em auto 1.5em auto; padding: 2.2em 1.2em 1.5em 1.2em; background: var(--card, #fff); border-radius: 22px; }
        h1 { color: var(--fg, #222); font-size: 2.3em; text-align: left; margin-bottom: 0.2em; letter-spacing: 0.04em; font-weight: 700; }
        .desc { font-size: 1.1em; color: var(--sub, #888); margin-bottom: 1.5em; text-align: left; }
        .stats-grid { display: flex; flex-wrap: wrap; gap: 1.5em; justify-content: flex-start; margin-bottom: 1.5em; }
        .stat-card { flex: 1 1 320px; background: var(--card2, #f4f6fa); border-radius: 14px; padding: 1.2em 1em; margin-bottom: 0; min-width: 260px; display: flex; flex-direction: row; align-items: flex-start; justify-content: space-between; }
        .stat-left { display: flex; flex-direction: column; align-items: flex-start; }
        .stat-title { font-size: 1em; color: var(--sub, #888); margin-bottom: 0.2em; text-align: left; }
        .stat-value { font-size: 2em; font-weight: bold; margin-bottom: 0.2em; padding: 0.1em 0.5em; border-radius: 8px; transition: background 0.2s, color 0.2s; text-align: left; min-width: 90px; }
        .odometer { display: inline-block; }
        .stat-value.green { background: var(--green-bg); color: var(--green-fg); }
        .stat-value.yellow { background: var(--yellow-bg); color: var(--yellow-fg); }
        .stat-value.red { background: var(--red-bg); color: var(--red-fg); }
        .stat-details { font-size: 0.98em; color: var(--fg, #222); text-align: right; margin-left: 1.2em; min-width: 120px; }
        .stat-details p { margin: 0.2em 0; padding: 0; line-height: 1.5; font-size: 0.98em; }
        @media (max-width: 900px) {
            .container { max-width: 99vw; padding: 0.5em; }
            .stats-grid { flex-direction: column; gap: 0.8em; }
            .stat-card { min-width: unset; flex-direction: column; align-items: flex-start; }
            .stat-details { margin-left: 0; margin-top: 0.5em; text-align: left; }
        }
        .chart-wrap { background: var(--card2, #f4f6fa); border-radius: 14px; padding: 1.2em 1em; margin-bottom: 1.5em; }
        .mode-toggle { display: flex; justify-content: flex-end; margin-bottom: 0.5em; }
        .toggle-btn { background: var(--card2, #f4f6fa); border: 1px solid var(--sub, #888); border-radius: 8px; padding: 0.3em 1em; font-size: 1em; color: var(--fg, #222); cursor: pointer; transition: background 0.2s, color 0.2s; margin-left: 0.5em; }
        .toggle-btn.active { background: var(--accent, #2a4d8f); color: #fff; border-color: var(--accent, #2a4d8f); }
        .footer { text-align: center; color: var(--sub, #888); font-size: 0.95em; margin-top: 2.5em; letter-spacing: 0.05em; }
        :root {
            --bg: #f8f8ff;
            --fg: #222;
            --card: #fff;
            --card2: #f4f6fa;
            --sub: #888;
            --accent: #2a4d8f;
            --green-bg: #eafbe6;
            --green-fg: #1cae4a;
            --yellow-bg: #fffbe6;
            --yellow-fg: #e6b800;
            --red-bg: #ffeaea;
            --red-fg: #d32f2f;
        }
        body.dark {
            --bg: #181c1f;
            --fg: #f8f8ff;
            --card: #23272a;
            --card2: #23272a;
            --sub: #aaa;
            --accent: #4fa3ff;
            --green-bg: #1e2d1e;
            --green-fg: #7fffa7;
            --yellow-bg: #2d2d1e;
            --yellow-fg: #ffe066;
            --red-bg: #2d1e1e;
            --red-fg: #ff7f7f;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="mode-toggle">
            <button class="toggle-btn" id="lightBtn">ライト</button>
            <button class="toggle-btn" id="darkBtn">ダーク</button>
        </div>
        <h1>Botリソース監視</h1>
        <div class="desc">SYCS-Voldemort Bot Status</div>
        <div class="chart-wrap">
            <canvas id="loadChart" height="80" style="max-width:100%;"></canvas>
        </div>
        <div class="chart-wrap">
            <canvas id="memChart" height="80" style="max-width:100%;"></canvas>
        </div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-title">ロードアベレージ</div>
                    <div class="stat-value" id="loadavg"><span class="odometer" id="od_loadavg">0</span></div>
                </div>
                <div class="stat-details" id="loadavg_detail">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-title">CPU使用率</div>
                    <div class="stat-value" id="cpu"><span class="odometer" id="od_cpu">0</span>%</div>
                </div>
                <div class="stat-details" id="cpu_detail">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-title">メモリ使用率</div>
                    <div class="stat-value" id="mem"><span class="odometer" id="od_mem">0</span>%</div>
                </div>
                <div class="stat-details" id="mem_detail">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-title">送信量</div>
                    <div class="stat-value" id="net_sent"><span class="odometer" id="od_net_sent">0</span> MB</div>
                </div>
                <div class="stat-details" id="net_sent_detail">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-title">受信量</div>
                    <div class="stat-value" id="net_recv"><span class="odometer" id="od_net_recv">0</span> MB</div>
                </div>
                <div class="stat-details" id="net_recv_detail">-</div>
            </div>
        </div>
        <div class="footer">&copy; SYCS</div>
    </div>
    <script>
        // クッキー操作
        function setCookie(name, value, days) {
            let d = new Date(); d.setTime(d.getTime() + (days*24*60*60*1000));
            document.cookie = name + "=" + value + ";expires=" + d.toUTCString() + ";path=/";
        }
        function getCookie(name) {
            let v = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
            return v ? v[2] : null;
        }
        // モード切替
        function setMode(mode) {
            document.body.classList.toggle('dark', mode === 'dark');
            document.getElementById('lightBtn').classList.toggle('active', mode === 'light');
            document.getElementById('darkBtn').classList.toggle('active', mode === 'dark');
            setCookie('mode', mode, 365);
        }
        document.getElementById('lightBtn').onclick = () => setMode('light');
        document.getElementById('darkBtn').onclick = () => setMode('dark');
        // 初期モード
        let loadChart, memChart;
        let loadData = Array(50).fill(0);
        let memData = Array(50).fill(0);
        let labels = Array.from({length: 50}, (_, i) => '');
        window.onload = function() {
            let mode = getCookie('mode') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
            setMode(mode);
            const loadCtx = document.getElementById('loadChart').getContext('2d');
            loadChart = new Chart(loadCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'ロードアベレージ(1min)',
                        data: loadData,
                        borderColor: '#007aff',
                        backgroundColor: 'rgba(0,122,255,0.08)',
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 3,
                        fill: true,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    layout: { padding: 0 },
                    scales: {
                        x: { display: false },
                        y: {
                            min: 0,
                            max: 8,
                            ticks: { stepSize: 1, color: '#888', font: { size: 12 } },
                            grid: { color: '#e0e0e0' }
                        }
                    }
                }
            });
            const memCtx = document.getElementById('memChart').getContext('2d');
            memChart = new Chart(memCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'メモリ使用率(%)',
                        data: memData,
                        borderColor: '#2ecc40',
                        backgroundColor: 'rgba(46,204,64,0.08)',
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 3,
                        fill: true,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    layout: { padding: 0 },
                    scales: {
                        x: { display: false },
                        y: {
                            min: 0,
                            max: 100,
                            ticks: { stepSize: 20, color: '#888', font: { size: 12 } },
                            grid: { color: '#e0e0e0' }
                        }
                    }
                }
            });
            updateStats();
            setInterval(updateStats, 3000);
        }
        function updateStats() {
            fetch('/api/stats').then(r=>r.json()).then(d=>{
                // 色分岐関数（iOS26風ライト/ダーク専用色）
                function getColor(val) {
                    if(document.body.classList.contains('dark')) {
                        if (val < 50) return 'green';
                        if (val < 80) return 'yellow';
                        return 'red';
                    } else {
                        if (val < 50) return 'green';
                        if (val < 80) return 'yellow';
                        return 'red';
                    }
                }
                // ロードアベレージ
                let la = d.loadavg[0] || 0;
                loadData.push(la); loadData.shift();
                loadChart.data.datasets[0].data = loadData;
                loadChart.update('none');
                let laColor = getColor(la*12.5); // 8.0=100%換算
                let loadavgElem = document.getElementById('loadavg');
                loadavgElem.className = 'stat-value ' + laColor;
                if(window.od_loadavg) od_loadavg.innerHTML = la.toFixed(2);
                // 詳細（ロードアベレージ）
                let laDetail = `<p>5min: ${d.loadavg[1].toFixed(2)}</p><p>15min: ${d.loadavg[2].toFixed(2)}</p>`;
                document.getElementById('loadavg_detail').innerHTML = laDetail;
                // CPU
                let cpuColor = getColor(d.cpu);
                let cpuElem = document.getElementById('cpu');
                cpuElem.className = 'stat-value ' + cpuColor;
                if(window.od_cpu) od_cpu.innerHTML = d.cpu;
                // 詳細（CPU）
                let cpuDetail = `<p>${d.cpu_count}コア</p>` + (d.cpu_freq ? `<p>${d.cpu_freq}MHz</p>` : '');
                document.getElementById('cpu_detail').innerHTML = cpuDetail;
                // メモリ
                let memColor = getColor(d.mem);
                let memElem = document.getElementById('mem');
                memElem.className = 'stat-value ' + memColor;
                if(window.od_mem) od_mem.innerHTML = d.mem;
                memData.push(d.mem); memData.shift();
                memChart.data.datasets[0].data = memData;
                memChart.update('none');
                // 詳細（メモリ）
                let memDetail = `<p>Free: ${d.mem_free.toFixed(0)}MB</p>` + (d.mem_cached ? `<p>Cache: ${d.mem_cached.toFixed(0)}MB</p>` : '');
                document.getElementById('mem_detail').innerHTML = memDetail;
                // ネットワーク
                if(window.od_net_sent) od_net_sent.innerHTML = d.net_sent_MB.toFixed(2);
                if(window.od_net_recv) od_net_recv.innerHTML = d.net_recv_MB.toFixed(2);
                // 詳細（ネットワーク）
                document.getElementById('net_sent_detail').innerHTML = `<p>合計: ${d.net_sent_MB.toFixed(0)}MB</p>`;
                document.getElementById('net_recv_detail').innerHTML = `<p>合計: ${d.net_recv_MB.toFixed(0)}MB</p>`;
            });
        }
    </script>
</body>
</html>
'''

@app.route("/")
def index():
    # ロードアベレージ
    if hasattr(os, "getloadavg"):
        loadavg = ", ".join(f"{x:.2f}" for x in os.getloadavg())
    else:
        loadavg = "N/A (Windows)"
    # CPU
    cpu = psutil.cpu_percent(interval=0.5)
    # メモリ
    mem = psutil.virtual_memory().percent
    # ネットワーク
    net = psutil.net_io_counters()
    net_sent = f"{net.bytes_sent / 1024 / 1024:.2f}"
    net_recv = f"{net.bytes_recv / 1024 / 1024:.2f}"
    return render_template_string(HTML, loadavg=loadavg, cpu=cpu, mem=mem, net_sent=net_sent, net_recv=net_recv)


@app.route("/api/stats")
def api_stats():
    if hasattr(os, "getloadavg"):
        loadavg = os.getloadavg()
    else:
        loadavg = (0, 0, 0)
    cpu = psutil.cpu_percent(interval=0.5)
    cpu_count = psutil.cpu_count(logical=True)
    try:
        cpu_freq = int(psutil.cpu_freq().current)
    except Exception:
        cpu_freq = None
    vmem = psutil.virtual_memory()
    mem = vmem.percent
    mem_free = vmem.available / 1024 / 1024
    mem_cached = getattr(vmem, 'cached', 0) / 1024 / 1024
    net = psutil.net_io_counters()
    return jsonify({
        "loadavg": loadavg,
        "cpu": cpu,
        "cpu_count": cpu_count,
        "cpu_freq": cpu_freq,
        "mem": mem,
        "mem_free": mem_free,
        "mem_cached": mem_cached,
        "net_sent_MB": net.bytes_sent / 1024 / 1024,
        "net_recv_MB": net.bytes_recv / 1024 / 1024
    })


def start_status_server():
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
