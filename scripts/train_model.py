import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os

# Create models directory if it doesn't exist
os.makedirs('models', exist_ok=True)

# Load and preprocess the KDD dataset
print("Loading and preprocessing KDD dataset...")

# Define columns
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
]

categorical_columns = ['protocol_type', 'service', 'flag']

# Load data
train_data = pd.read_csv('data/KDDTrain+.txt', names=columns)
test_data = pd.read_csv('data/KDDTest+.txt', names=columns)

# Combine train and test data
data = pd.concat([train_data, test_data])

# Convert categorical features to numerical
label_encoders = {}
for col in categorical_columns:
    le = LabelEncoder()
    data[col] = le.fit_transform(data[col].astype(str))
    label_encoders[col] = le

# Convert labels to binary (normal/attack)
data['label'] = data['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

# Convert numeric columns to float
numeric_columns = [col for col in columns if col not in categorical_columns + ['label']]
for col in numeric_columns:
    data[col] = pd.to_numeric(data[col], errors='coerce')

# Fill any missing values
data = data.fillna(0)

# Prepare features and labels
X = data.drop('label', axis=1)
y = data['label']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train the model
print("Training Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# Evaluate the model
print("\nModel Evaluation:")
print(f"Training Accuracy: {model.score(X_train_scaled, y_train):.4f}")
print(f"Test Accuracy: {model.score(X_test_scaled, y_test):.4f}")

# Save the model, scaler, and label encoders
joblib.dump(model, 'models/rf_ids_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(label_encoders, 'models/label_encoders.pkl')
print("\nModel and scaler saved to 'models' directory")

# Save preprocessed data for retraining
np.savez('data/preprocessed_data.npz', X=X_train_scaled, y=y_train)
print("Preprocessed data saved for future retraining") 