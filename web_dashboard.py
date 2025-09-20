#!/usr/bin/env python3
"""
Network Security Monitor - Web Dashboard
Dashboard web real-time per monitoraggio sicurezza di rete
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import threading
import time
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
import plotly.graph_objs as go
import plotly.utils
from src.network_monitor import NetworkMonitor
from src.threat_detector import ThreatDetector
from src.alert_system import AlertSystem
import psutil

class WebDashboard:
    def __init__(self, config_path="config/settings.json"):
        # Carica configurazione
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # Inizializza Flask e SocketIO
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'security-monitor-secret-key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Inizializza componenti di sicurezza
        self.network_monitor = NetworkMonitor(self.config)
        self.threat_detector = ThreatDetector(self.config)
        self.alert_system = AlertSystem(self.config)
        
        # Dati per dashboard
        self.dashboard_data = {
            'alerts': deque(maxlen=100),
            'traffic_data': deque(maxlen=50),
            'threat_stats': {'total': 0, 'blocked': 0, 'active': 0},
            'top_ips': {},
            'geographic_data': [],
            'timeline_data': deque(maxlen=100)
        }
        
        # Setup routes e eventi
        self._setup_routes()
        self._setup_socketio_events()
        
        # Thread per aggiornamento dati
        self.running = False
        self.update_thread = None

    def _setup_routes(self):
        """Configura le route Flask"""
        
        @self.app.route('/')
        def index():
            return render_template('dashboard.html')
        
        @self.app.route('/api/stats')
        def get_stats():
            """API per statistiche generali"""
            return jsonify({
                'network_stats': self.network_monitor.get_stats(),
                'threat_stats': self.threat_detector.get_threat_stats(),
                'alert_stats': self.alert_system.get_alert_statistics(),
                'uptime': str(datetime.now() - self.start_time).split('.')[0] if hasattr(self, 'start_time') else '0:00:00'
            })
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """API per alert recenti"""
            return jsonify(list(self.dashboard_data['alerts']))
        
        @self.app.route('/api/traffic')
        def get_traffic():
            """API per dati traffico"""
            return jsonify(self._generate_traffic_chart())
        
        @self.app.route('/api/block/<ip>')
        def block_ip(ip):
            """API per bloccare un IP"""
            self.threat_detector._block_ip(ip)
            return jsonify({'status': 'blocked', 'ip': ip})

    def _setup_socketio_events(self):
        """Configura eventi SocketIO per real-time"""
        
        @self.socketio.on('connect')
        def handle_connect():
            print(f"🌐 Client connesso: {request.sid}")
            emit('status', {'message': 'Connesso al Security Monitor'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            print(f"🌐 Client disconnesso: {request.sid}")
        
        @self.socketio.on('get_live_data')
        def handle_live_data():
            """Invia dati live al client"""
            data = {
                'alerts': list(self.dashboard_data['alerts'])[-10:],
                'traffic': self._generate_traffic_chart(),
                'stats': {
                    'network_stats': self.network_monitor.get_stats(),
                    'threat_stats': self.threat_detector.get_threat_stats(),
                    'alert_stats': self.alert_system.get_alert_statistics()
                }
            }
            emit('live_data', data)

    def _generate_traffic_chart(self):
        """Genera grafico traffico di rete"""
        timestamps = []
        bytes_sent = []
        bytes_recv = []
        
        for entry in self.dashboard_data['traffic_data']:
            timestamps.append(entry['timestamp'])
            bytes_sent.append(entry.get('bytes_sent', 0))
            bytes_recv.append(entry.get('bytes_recv', 0))
        
        traces = [
            {
                'x': timestamps,
                'y': bytes_sent,
                'type': 'scatter',
                'mode': 'lines+markers',
                'name': 'Bytes Sent',
                'line': {'color': '#ff6b6b'}
            },
            {
                'x': timestamps,
                'y': bytes_recv,
                'type': 'scatter',
                'mode': 'lines+markers',
                'name': 'Bytes Received',
                'line': {'color': '#4ecdc4'}
            }
        ]
        
        layout = {
            'title': 'Traffico di Rete Real-Time',
            'xaxis': {'title': 'Tempo'},
            'yaxis': {'title': 'Bytes'},
            'template': 'plotly_dark'
        }
        
        return {'data': traces, 'layout': layout}

    def _update_dashboard_data(self):
        """Aggiorna i dati della dashboard"""
        while self.running:
            try:
                # Aggiorna traffico di rete
                current_time = datetime.now().strftime('%H:%M:%S')
                
                # Usa psutil per dati traffico reali
                net_io = psutil.net_io_counters()
                
                traffic_entry = {
                    'timestamp': current_time,
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv
                }
                self.dashboard_data['traffic_data'].append(traffic_entry)
                
                # Aggiorna statistiche minacce
                self.dashboard_data['threat_stats'] = {
                    'total': self.threat_detector.threats_detected,
                    'blocked': self.threat_detector.threats_blocked,
                    'active': len(self.threat_detector.blocked_ips)
                }
                
                # Emetti aggiornamenti via SocketIO
                self.socketio.emit('dashboard_update', {
                    'traffic': traffic_entry,
                    'threat_stats': self.dashboard_data['threat_stats'],
                    'timestamp': current_time
                })
                
                time.sleep(2)  # Aggiorna ogni 2 secondi
                
            except Exception as e:
                print(f"⚠️  Errore aggiornamento dashboard: {e}")
                time.sleep(5)

    def add_alert(self, alert_data):
        """Aggiunge un nuovo alert alla dashboard"""
        alert_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.dashboard_data['alerts'].append(alert_data)
        
        # Emetti alert via SocketIO
        self.socketio.emit('new_alert', alert_data)

    def start(self, host='0.0.0.0', port=5000, debug=False):
        """Avvia la dashboard web"""
        self.start_time = datetime.now()
        self.running = True
        
        # Avvia thread aggiornamento dati
        self.update_thread = threading.Thread(target=self._update_dashboard_data)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        print(f"🌐 Dashboard web avviata su http://{host}:{port}")
        print("📊 Interfaccia: Dashboard di sicurezza real-time")
        
        # Avvia server Flask
        self.socketio.run(self.app, host=host, port=port, debug=debug)

    def stop(self):
        """Ferma la dashboard"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=1)

def create_dashboard_template():
    """Crea il template HTML per la dashboard"""
    # Crea directory templates se non esiste
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    html_content = """<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 Network Security Monitor</title>
    <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #ffffff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0,0,0,0.3);
            padding: 1rem 2rem;
            border-bottom: 2px solid #4ecdc4;
        }
        
        .header h1 {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.8rem;
        }
        
        .status-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 0.5rem;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(0,0,0,0.2);
            padding: 0.5rem 1rem;
            border-radius: 25px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            grid-template-rows: auto auto auto;
            gap: 1.5rem;
            padding: 2rem;
            height: calc(100vh - 120px);
        }
        
        .widget {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
        }
        
        .widget h3 {
            margin-bottom: 1rem;
            color: #4ecdc4;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }
        
        .stat-card {
            background: rgba(0,0,0,0.2);
            padding: 1rem;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #4ecdc4;
        }
        
        .alert-item {
            background: rgba(0,0,0,0.2);
            margin: 0.5rem 0;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #ff6b6b;
        }
        
        .alert-time {
            font-size: 0.8rem;
            opacity: 0.7;
        }
        
        .controls {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .btn {
            background: #4ecdc4;
            color: #1e3c72;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .btn:hover {
            background: #45b7b8;
            transform: translateY(-2px);
        }
        
        .btn-danger {
            background: #ff6b6b;
            color: white;
        }
        
        .btn-danger:hover {
            background: #ff5252;
        }
        
        #traffic-chart {
            height: 300px;
            width: 100%;
        }
        
        .full-width {
            grid-column: 1 / -1;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
                padding: 1rem;
            }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>
            <i class="fas fa-shield-alt"></i>
            Network Security Monitor
        </h1>
        <div class="status-bar">
            <div class="status-indicator">
                <i class="fas fa-circle pulse" style="color: #4ecdc4;"></i>
                <span>Sistema Attivo</span>
            </div>
            <div class="status-indicator">
                <i class="fas fa-clock"></i>
                <span id="uptime">00:00:00</span>
            </div>
            <div class="status-indicator">
                <i class="fas fa-wifi"></i>
                <span id="connection-status">Connesso</span>
            </div>
        </div>
    </header>
    
    <main class="dashboard-grid">
        <!-- Statistiche Generali -->
        <div class="widget">
            <h3><i class="fas fa-chart-bar"></i> Statistiche Live</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="total-threats">0</div>
                    <div>Minacce Rilevate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="blocked-threats">0</div>
                    <div>IP Bloccati</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="active-connections">0</div>
                    <div>Connessioni Attive</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="total-packets">0</div>
                    <div>Pacchetti Analizzati</div>
                </div>
            </div>
        </div>
        
        <!-- Alert Recenti -->
        <div class="widget">
            <h3><i class="fas fa-exclamation-triangle"></i> Alert Recenti</h3>
            <div id="alerts-container" style="max-height: 300px; overflow-y: auto;">
                <!-- Gli alert saranno inseriti qui dinamicamente -->
            </div>
        </div>
        
        <!-- Grafico Traffico -->
        <div class="widget full-width">
            <h3><i class="fas fa-chart-line"></i> Traffico di Rete Real-Time</h3>
            <div id="traffic-chart"></div>
        </div>
        
        <!-- Controlli di Sicurezza -->
        <div class="widget">
            <h3><i class="fas fa-cogs"></i> Controlli di Sicurezza</h3>
            <div class="controls">
                <button class="btn" onclick="refreshData()">
                    <i class="fas fa-sync-alt"></i> Aggiorna
                </button>
                <button class="btn" onclick="exportReport()">
                    <i class="fas fa-download"></i> Esporta Report
                </button>
                <button class="btn btn-danger" onclick="emergencyBlock()">
                    <i class="fas fa-ban"></i> Blocco Emergenza
                </button>
            </div>
            <div id="blocked-ips" style="margin-top: 1rem;">
                <h4>IP Bloccati:</h4>
                <div id="blocked-list"></div>
            </div>
        </div>
        
        <!-- Sistema Status -->
        <div class="widget">
            <h3><i class="fas fa-heartbeat"></i> Stato Sistema</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="cpu-usage">0%</div>
                    <div>CPU</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="memory-usage">0%</div>
                    <div>Memoria</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="network-usage">0 KB/s</div>
                    <div>Rete</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="alert-rate">0/min</div>
                    <div>Rate Alert</div>
                </div>
            </div>
        </div>
    </main>
    
    <script>
        // Inizializza SocketIO
        const socket = io();
        
        // Variabili globali
        let trafficChart = null;
        
        // Gestione connessione
        socket.on('connect', function() {
            console.log('Connesso al server');
            document.getElementById('connection-status').textContent = 'Connesso';
            socket.emit('get_live_data');
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnesso dal server');
            document.getElementById('connection-status').textContent = 'Disconnesso';
        });
        
        // Aggiornamento dati live
        socket.on('live_data', function(data) {
            updateStats(data.stats);
            updateAlerts(data.alerts);
            updateTrafficChart(data.traffic);
        });
        
        // Nuovo alert
        socket.on('new_alert', function(alert) {
            addAlert(alert);
        });
        
        // Aggiornamento dashboard
        socket.on('dashboard_update', function(data) {
            if (data.traffic) {
                updateTrafficChart(data.traffic);
            }
            if (data.threat_stats) {
                updateStats({threat_stats: data.threat_stats});
            }
        });
        
        // Funzioni di aggiornamento
        function updateStats(stats) {
            if (stats.threat_stats) {
                document.getElementById('total-threats').textContent = stats.threat_stats.threats_detected || 0;
                document.getElementById('blocked-threats').textContent = stats.threat_stats.threats_blocked || 0;
            }
            
            if (stats.network_stats) {
                document.getElementById('active-connections').textContent = stats.network_stats.recent_connections || 0;
                document.getElementById('total-packets').textContent = stats.network_stats.total_packets || 0;
            }
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            container.innerHTML = '';
            
            alerts.forEach(alert => {
                addAlert(alert);
            });
        }
        
        function addAlert(alert) {
            const container = document.getElementById('alerts-container');
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert-item';
            
            const icon = getAlertIcon(alert.level || alert.severity);
            
            alertDiv.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>${icon} ${alert.threat_type || alert.reason || 'Alert'}</strong>
                        <div>IP: ${alert.source_ip || alert.ip || 'Unknown'}</div>
                        <div class="alert-time">${alert.timestamp}</div>
                    </div>
                    <button class="btn btn-danger" onclick="blockIP('${alert.source_ip || alert.ip}')">
                        Blocca
                    </button>
                </div>
            `;
            
            container.insertBefore(alertDiv, container.firstChild);
            
            // Mantieni solo ultimi 10 alert
            while (container.children.length > 10) {
                container.removeChild(container.lastChild);
            }
        }
        
        function getAlertIcon(level) {
            const icons = {
                'info': '🔵',
                'warning': '🟡',
                'critical': '🔴',
                'blocked': '🚫',
                'low': '🔵',
                'medium': '🟡',
                'high': '🔴'
            };
            return icons[level] || '⚠️';
        }
        
        function updateTrafficChart(trafficData) {
            if (trafficData && trafficData.data) {
                if (!trafficChart) {
                    trafficChart = Plotly.newPlot('traffic-chart', trafficData.data, trafficData.layout, {
                        responsive: true,
                        displayModeBar: false
                    });
                } else {
                    Plotly.redraw('traffic-chart');
                }
            }
        }
        
        // Funzioni di controllo
        function refreshData() {
            socket.emit('get_live_data');
        }
        
        function blockIP(ip) {
            if (ip && ip !== 'Unknown') {
                fetch(`/api/block/${ip}`)
                    .then(response => response.json())
                    .then(data => {
                        console.log('IP bloccato:', data);
                        updateBlockedList();
                    });
            }
        }
        
        function exportReport() {
            alert('Funzionalità di export in sviluppo');
        }
        
        function emergencyBlock() {
            if (confirm('Attivare il blocco di emergenza?')) {
                alert('Blocco di emergenza attivato');
            }
        }
        
        function updateBlockedList() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    console.log('Stats aggiornate:', data);
                });
        }
        
        // Aggiorna uptime
        setInterval(() => {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.uptime) {
                        document.getElementById('uptime').textContent = data.uptime;
                    }
                })
                .catch(err => console.log('Errore stats:', err));
        }, 5000);
        
        // Richiedi dati iniziali
        setTimeout(() => {
            socket.emit('get_live_data');
        }, 1000);
    </script>
</body>
</html>"""
    
    with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ Template dashboard creato in templates/dashboard.html")

if __name__ == "__main__":
    # Crea template se non esiste
    create_dashboard_template()
    
    # Avvia dashboard
    dashboard = WebDashboard()
    dashboard.start(host='0.0.0.0', port=5000, debug=True)
