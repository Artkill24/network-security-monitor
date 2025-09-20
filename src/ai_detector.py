import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf

class AIThreatDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def extract_features(self, network_data):
        # Estrai features da traffico di rete
        features = [
            network_data.get('packet_count', 0),
            network_data.get('bytes_sent', 0),
            network_data.get('bytes_recv', 0),
            len(network_data.get('unique_ips', [])),
            network_data.get('port_scans', 0)
        ]
        return np.array(features).reshape(1, -1)
    
    def detect_anomaly(self, network_data):
        if not self.is_trained:
            return False
        
        features = self.extract_features(network_data)
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)
        return prediction[0] == -1  # -1 indica anomalia
