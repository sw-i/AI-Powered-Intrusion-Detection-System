import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

# Paths
DATA_PATH = "data/KDDTrain+.txt"
SCALER_PATH = "models/scaler.pkl"
PREPROCESSED_DATA_PATH = "data/preprocessed_data.npz"

# NSL-KDD feature columns
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

# Load data
df = pd.read_csv(DATA_PATH, names=columns)

# Label: normal vs attack
df['label'] = df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

# Encode categorical features
encoders = {}
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

# Final features used for training
selected_features = [
    'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'count', 'srv_count', 'dst_host_srv_count'
]

X = df[selected_features].copy()

# Add simulated smart features (we use safe constant placeholders for now)
X['packet_rate'] = 0.5         # avg 0.5 packets/sec
X['unique_ports'] = 3          # 3 unique destination ports per IP
X['tcp_syn_count'] = 10        # 10 SYNs per time window

y = df['label']

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save scaler and dataset
os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
joblib.dump(scaler, SCALER_PATH)
np.savez_compressed(PREPROCESSED_DATA_PATH, X=X_scaled, y=y.to_numpy())

print(" Data preprocessing done with smart features included.")
