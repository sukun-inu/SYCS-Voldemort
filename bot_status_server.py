from flask import Flask, jsonify, render_template_string
import os
import psutil
import time

app = Flask(__name__)

last_net = psutil.net_io_counters()
last_time = time.time()

HTML = '''
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>SYCS-Voldemort Bot Status</title>
<link rel="icon" href="https://files.kawasaki-n3t.f5.si/apps/theming/favicon/dashboard">
<meta name="viewport" content="width=device-width, initial-scale=1">

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reset-css@5.0.1/reset.min.css" />
<link href="https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@400;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/odometer@0.4.8/themes/odometer-theme-default.min.css" />
<script src="https://cdn.jsdelivr.net/npm/odometer@0.4.8/odometer.min.js"></script>

<style>
body {
  font-family: 'SF Pro Display','Segoe UI',Arial,sans-serif;
  background: var(--bg);
  color: var(--fg);
  margin: 0;
  transition: background .3s,color .3s;
}

:root {
  --bg:#f8f8ff; --fg:#222; --card:#fff; --stat-bg:#f4f6fa;
  --sub:#888; --accent:#2a4d8f;
  --green-bg:#eafbe6; --green-fg:#1cae4a;
  --yellow-bg:#fffbe6; --yellow-fg:#e6b800;
  --red-bg:#ffeaea; --red-fg:#d32f2f;
}

body.dark {
  --bg:#181c1f; --fg:#f8f8ff; --card:#23272a; --stat-bg:#232b33;
  --sub:#aaa; --accent:#4fa3ff;
  --green-bg:#1e2d1e; --green-fg:#7fffa7;
  --yellow-bg:#2d2d1e; --yellow-fg:#ffe066;
  --red-bg:#2d1e1e; --red-fg:#ff7f7f;
}

.container {
  max-width:800px;
  margin:2.5em auto 1.5em;
  padding:2.2em 20px 1.5em;
  background:var(--card);
  border-radius:22px;
}

/* ===== Header ===== */
.header {
  display:flex;
  align-items:center;
  justify-content:space-between;
  margin-bottom:1.2em;
}

.header-left h1 {
  font-size:2.3em;
  font-weight:700;
  margin-bottom:.15em;
}

.desc { color:var(--sub); }

/* ===== Theme toggle ===== */
.theme-toggle {
  font-size:1.4em;
  cursor:pointer;
  color:var(--sub);
}
.theme-toggle:hover { color:var(--accent); }

/* ===== Stats ===== */
.stats-grid {
  display:flex;
  flex-wrap:wrap;
  gap:1.5em;
  justify-content:center;
}

.stat-card {
  flex:1 1 320px;
  max-width:360px;
  background:var(--stat-bg);
  border-radius:14px;
  padding:1.2em 1em;
  display:flex;
  align-items:center;
  justify-content:center;
}

.stat-left {
  display:flex;
  flex-direction:column;
  align-items:center;
}

.stat-title {
  font-size:1em;
  color:var(--sub);
  margin-bottom:.3em;
}

.stat-value {
  font-size:2em;
  font-weight:bold;
  padding:.1em .6em;
  border-radius:8px;
}

.stat-value.green { background:var(--green-bg); color:var(--green-fg); }
.stat-value.yellow { background:var(--yellow-bg); color:var(--yellow-fg); }
.stat-value.red { background:var(--red-bg); color:var(--red-fg); }

/* ===== Network ===== */
.net-line {
  display:flex;
  gap:1.2em;
  align-items:center;
  font-size:1.1em;
}

.net-up { color:#ff6b6b; }
.net-down { color:#4dabf7; }

/* ===== Chart ===== */
.chart-wrap {
  background:var(--stat-bg);
  border-radius:14px;
  padding:1.2em;
  margin-bottom:1.5em;
}

/* ===== Footer ===== */
.footer {
  text-align:center;
  color:var(--sub);
  font-size:.95em;
  margin-top:2.2em;
  letter-spacing:.04em;
}
</style>
</head>

<body>
<div class="container">

  <div class="header">
    <div class="header-left">
      <h1>Botリソース監視</h1>
      <div class="desc">SYCS-Voldemort Bot Status</div>
    </div>
    <div class="theme-toggle" id="themeToggle">
      <i class="fa-solid fa-sun"></i>
    </div>
  </div>

  <div class="chart-wrap">
    <canvas id="loadChart" height="80"></canvas>
  </div>

  <div class="stats-grid">

    <div class="stat-card">
      <div class="stat-left">
        <div class="stat-title">正規化LoadAvg</div>
        <div class="stat-value" id="loadavg">
          <span class="odometer" id="od_loadavg">0</span>%
        </div>
      </div>
    </div>

    <div class="stat-card">
      <div class="stat-left">
        <div class="stat-title">CPU使用率</div>
        <div class="stat-value" id="cpu">
          <span class="odometer" id="od_cpu">0</span>%
        </div>
      </div>
    </div>

    <div class="stat-card">
      <div class="stat-left">
        <div class="stat-title">メモリ使用率</div>
        <div class="stat-value" id="mem">
          <span class="odometer" id="od_mem">0</span>%
        </div>
      </div>
    </div>

    <div class="stat-card">
      <div class="stat-left">
        <div class="stat-title">Network</div>
        <div class="net-line">
          <div class="net-up">
            <i class="fa-solid fa-arrow-up"></i>
            <span id="up">0</span> KB/s
          </div>
          <div class="net-down">
            <i class="fa-solid fa-arrow-down"></i>
            <span id="down">0</span> KB/s
          </div>
        </div>
      </div>
    </div>

  </div>

  <div class="footer">© 2025 SYCS.</div>

</div>

<script>
function setCookie(n,v){document.cookie=n+"="+v+";path=/;max-age=31536000"}
function getCookie(n){return document.cookie.split('; ').find(r=>r.startsWith(n+'='))?.split('=')[1]}

const toggle=document.getElementById('themeToggle');
function applyTheme(d){
  document.body.classList.toggle('dark',d);
  toggle.innerHTML=d?'<i class="fa-solid fa-moon"></i>':'<i class="fa-solid fa-sun"></i>';
  setCookie('theme',d?'dark':'light');
}
applyTheme(getCookie('theme')==='dark');
toggle.onclick=()=>applyTheme(!document.body.classList.contains('dark'));

let loadData=Array(50).fill(0);
const loadChart=new Chart(document.getElementById('loadChart'),{
  type:'line',
  data:{labels:Array(50).fill(''),datasets:[{
    data:loadData,borderColor:'#007aff',backgroundColor:'rgba(0,122,255,.08)',
    tension:.4,pointRadius:0,borderWidth:3,fill:true
  }]},
  options:{plugins:{legend:{display:false}},scales:{x:{display:false},y:{min:0,max:100}}}
});

async function update(){
  const d=await fetch('/api/stats').then(r=>r.json());
  const color=v=>v<50?'green':v<80?'yellow':'red';

  od_cpu.innerHTML=d.cpu;
  cpu.className='stat-value '+color(d.cpu);

  od_mem.innerHTML=d.mem;
  mem.className='stat-value '+color(d.mem);

  const ln=Math.min(100,Math.round(d.load_norm));
  od_loadavg.innerHTML=ln;
  loadavg.className='stat-value '+color(ln);

  loadData.push(ln); loadData.shift();
  loadChart.update('none');

  up.textContent=d.net_up;
  down.textContent=d.net_down;
}
setInterval(update,3000); update();
</script>
</body>
</html>
'''

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/stats")
def api_stats():
    global last_net,last_time
    now=time.time()
    net=psutil.net_io_counters()
    dt=now-last_time

    up=(net.bytes_sent-last_net.bytes_sent)/dt/1024
    down=(net.bytes_recv-last_net.bytes_recv)/dt/1024
    last_net, last_time = net, now

    cores=psutil.cpu_count() or 1
    load=os.getloadavg()[0] if hasattr(os,'getloadavg') else 0
    load_norm=(load/cores)*100

    return jsonify({
        "cpu": psutil.cpu_percent(),
        "mem": psutil.virtual_memory().percent,
        "load_norm": load_norm,
        "net_up": round(up,1),
        "net_down": round(down,1)
    })

def start_status_server():
    app.run(host="0.0.0.0",port=8080)
