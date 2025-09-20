#!/usr/bin/env python3
import threading
from web_dashboard import WebDashboard
from src.network_monitor import NetworkMonitor
from src.threat_detector import ThreatDetector

class UnifiedSecurityMonitor:
    def __init__(self):
        self.dashboard = WebDashboard()
        # Integra monitoring con dashboard
        
    def start(self):
        # Avvia tutto insieme
        dashboard_thread = threading.Thread(target=self.dashboard.start)
        dashboard_thread.start()
