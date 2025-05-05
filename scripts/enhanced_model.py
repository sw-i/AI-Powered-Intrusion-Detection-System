import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import os
import time
from datetime import datetime

class EnhancedIDSModel:
    def __init__(self):
        self.base_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.model_path = os.path.join('models', 'enhanced_ids_model.pkl')
        self.scaler_path = os.path.join('models', 'enhanced_scaler.pkl')
        os.makedirs('models', exist_ok=True)
        self.last_retrain_time = time.time()

    def load_or_initialize(self):
        """Load existing model or initialize new one"""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.base_model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                print("[OK] Loaded existing enhanced model")
                return True
            except Exception as e:
                print(f"[WARNING] Error loading model: {str(e)}")
                print("[INFO] Initializing new enhanced model")
                return False
        else:
            print("[INFO] Initializing new enhanced model")
            return False

    def extract_enhanced_features(self, packet):
        """Extract relevant features from a packet for model prediction
        
        Args:
            packet (dict): A packet dictionary with network traffic information
            
        Returns:
            numpy.ndarray: A feature vector for model prediction
        """
        # Define the features to extract from packet
        features = np.zeros(20)  # Our model uses 20 features
        
        # Basic packet features 
        try:
            # Map string protocol to integer if needed
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'TCP': 6, 'UDP': 17, 'ICMP': 1}
            
            # Set basic features
            features[0] = packet.get('protocol_type', 0)  # If already numeric use as is
            if isinstance(features[0], str) and features[0].lower() in proto_map:
                features[0] = proto_map[features[0].lower()]
                
            # Service type (treat as categorical but use a simple hash for numeric value)
            service = packet.get('service', '')
            features[1] = hash(service) % 100 if service else 0
            
            # Flag (convert to numeric if needed)
            flag = packet.get('flag', '')
            features[2] = hash(flag) % 100 if flag else 0
            
            # Numeric packet features
            features[3] = float(packet.get('src_bytes', 0))
            features[4] = float(packet.get('dst_bytes', 0))
            features[5] = float(packet.get('land', 0))
            features[6] = float(packet.get('wrong_fragment', 0))
            features[7] = float(packet.get('urgent', 0))
            
            # Advanced features
            features[8] = float(packet.get('time_since_last', 0))
            features[9] = float(packet.get('packet_rate', 0))
            features[10] = float(packet.get('burst_count', 0))
            features[11] = float(packet.get('unique_ports', 0))
            features[12] = float(packet.get('port_entropy', 0))
            features[13] = float(packet.get('ip_entropy', 0))
            features[14] = float(packet.get('tcp_syn_count', 0))
            features[15] = float(packet.get('tcp_ack_count', 0))
            features[16] = float(packet.get('flow_duration', 0))
            features[17] = float(packet.get('flow_packets', 0))
            features[18] = float(packet.get('flow_bytes', 0))
            features[19] = float(packet.get('avg_packet_size', 0))
            
        except Exception as e:
            print(f"[WARNING] Error extracting features: {str(e)}")
            # Return zeros if there's an error
            return np.zeros(20)
            
        return features

    def fit(self, X, y):
        """Train the model on the given data"""
        # Scale the features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train the model
        self.base_model.fit(X_scaled, y)
        
        # Update last retrain time
        self.last_retrain_time = time.time()
        
        # Save the model and scaler
        self.save()
        
        return self

    def predict(self, X):
        """Make predictions on new data"""
        # Check if X is a dictionary (packet) and extract features if needed
        if isinstance(X, dict):
            X = self.extract_enhanced_features(X)
            X = X.reshape(1, -1)  # Reshape for a single sample
            
        # Scale the features
        X_scaled = self.scaler.transform(X)
        
        # Make predictions
        predictions = self.base_model.predict(X_scaled)
        
        # If it's a packet analysis, also return confidence and anomaly score
        if isinstance(X, np.ndarray) and X.shape[0] == 1:
            probas = self.base_model.predict_proba(X_scaled)[0]
            max_confidence = np.max(probas)
            anomaly_score = probas[1]  # Assuming class 1 is 'attack'
            return predictions[0], max_confidence, anomaly_score
            
        return predictions

    def predict_proba(self, X):
        """Get prediction probabilities"""
        # Check if X is a dictionary (packet) and extract features if needed
        if isinstance(X, dict):
            X = self.extract_enhanced_features(X)
            X = X.reshape(1, -1)  # Reshape for a single sample
            
        X_scaled = self.scaler.transform(X)
        return self.base_model.predict_proba(X_scaled)

    def decision_function(self, X):
        """Get anomaly scores"""
        # Check if X is a dictionary (packet) and extract features if needed
        if isinstance(X, dict):
            X = self.extract_enhanced_features(X)
            X = X.reshape(1, -1)  # Reshape for a single sample
            
        X_scaled = self.scaler.transform(X)
        return self.base_model.predict_proba(X_scaled)[:, 1]

    def save(self):
        """Save the model and scaler"""
        joblib.dump(self.base_model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

    def load(self):
        """Load the model and scaler"""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.base_model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            return True
        return False

    def explain_prediction(self, features):
        """Explain the prediction for a single sample"""
        if not hasattr(self.base_model, 'feature_importances_'):
            return "Feature importance not available for this model type"
            
        # Scale the features
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get prediction
        pred = self.predict(features.reshape(1, -1))[0]
        proba = self.predict_proba(features.reshape(1, -1))[0]
        
        # Get feature importance
        importances = self.base_model.feature_importances_
        
        # Create explanation
        explanation = f"Prediction: {pred} (confidence: {proba[1]:.2f})\n"
        explanation += "Top contributing features:\n"
        
        # Sort features by importance
        sorted_idx = np.argsort(importances)[::-1]
        for i in range(min(5, len(sorted_idx))):
            idx = sorted_idx[i]
            explanation += f"- Feature {idx}: importance={importances[idx]:.4f}, value={features[idx]:.2f}\n"
            
        return explanation

    def get_model_info(self):
        """Get model information and statistics"""
        return {
            'type': 'Enhanced IDS Model',
            'base_model': 'Random Forest',
            'n_estimators': self.base_model.n_estimators,
            'last_retrain': datetime.fromtimestamp(self.last_retrain_time).strftime('%Y-%m-%d %H:%M:%S'),
            'model_path': self.model_path,
            'scaler_path': self.scaler_path
        } 