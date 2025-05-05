#!/usr/bin/env python3
import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from enhanced_model import EnhancedIDSModel

import matplotlib.pyplot as plt
import seaborn as sns

# Paths
DATA_DIR = 'data'
MODERN_DATASET = os.path.join(DATA_DIR, 'modern_ids_dataset.csv')
PREPROCESSED_DATA = os.path.join(DATA_DIR, 'modern_preprocessed_data.npz')
MODEL_DIR = 'models'
os.makedirs(MODEL_DIR, exist_ok=True)

def plot_confusion_matrix(y_true, y_pred, classes):
    """Plot confusion matrix"""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.title('Confusion Matrix')
    plt.savefig(os.path.join(MODEL_DIR, 'confusion_matrix.png'))
    print(f"Confusion matrix saved to {os.path.join(MODEL_DIR, 'confusion_matrix.png')}")

def plot_feature_importance(model, feature_names):
    """Plot feature importance"""
    # Get feature importance from base model
    if hasattr(model.base_model, 'feature_importances_'):
        importances = model.base_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(12, 8))
        plt.title("Feature Importance")
        plt.bar(range(len(indices)), importances[indices], align='center')
        plt.xticks(range(len(indices)), [feature_names[i] for i in indices], rotation=90)
        plt.tight_layout()
        plt.savefig(os.path.join(MODEL_DIR, 'feature_importance.png'))
        print(f"Feature importance plot saved to {os.path.join(MODEL_DIR, 'feature_importance.png')}")

def main():
    try:
        print(">>> Enhanced IDS Model Training <<<")
        print("=" * 60)
        
        # Check if preprocessed data exists
        if os.path.exists(PREPROCESSED_DATA):
            print(f">>> Loading preprocessed data from {PREPROCESSED_DATA}")
            data = np.load(PREPROCESSED_DATA)
            X = data['X']
            y = data['y']
            
            # Feature names (for importance plot)
            feature_names = [
                'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
                'time_since_last', 'packet_rate', 'burst_count',
                'unique_ports', 'port_entropy', 'ip_entropy', 'tcp_syn_count', 'tcp_ack_count',
                'flow_duration', 'flow_packets', 'flow_bytes', 'avg_packet_size'
            ]
        elif os.path.exists(MODERN_DATASET):
            print(f">>> Loading dataset from {MODERN_DATASET}")
            # Load and preprocess dataset
            df = pd.read_csv(MODERN_DATASET)
            
            # Feature names for later use
            feature_names = df.columns.tolist()
            feature_names.remove('label')
            
            # Prepare data
            X = df.drop('label', axis=1).values
            y = df['label'].values
            
            print(f"Dataset shape: {df.shape}")
            print(f"Attack ratio: {np.mean(y == 'attack') * 100:.2f}%")
        else:
            print(f"WARNING: No dataset found. Please run scripts/modern_dataset_builder.py first.")
            sys.exit(1)  # Exit with error code
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Initialize and train the enhanced model
        print("\n>>> Training Enhanced IDS Model...")
        model = EnhancedIDSModel()
        
        start_time = time.time()
        model.fit(X_train, y_train)
        training_time = time.time() - start_time
        
        print(f"Training completed in {training_time:.2f} seconds")
        
        # Save the model
        model.save()
        print(f"Model saved to {model.model_path}")
        
        # Evaluate the model
        print("\n>>> Evaluating model performance...")
        
        # Predictions
        start_time = time.time()
        y_pred = model.predict(X_test)
        inference_time = time.time() - start_time
        
        # Performance metrics
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Average inference time: {inference_time/len(X_test)*1000:.2f} ms per sample")
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Anomaly scores
        if hasattr(model, 'decision_function'):
            anomaly_scores = model.decision_function(X_test)
            print(f"Anomaly score range: {np.min(anomaly_scores):.2f} to {np.max(anomaly_scores):.2f}")
        
        # Plot confusion matrix
        plot_confusion_matrix(y_test, y_pred, classes=['normal', 'attack'])
        
        # Plot feature importance
        plot_feature_importance(model, feature_names)
        
        # Example explanation
        print("\n>>> Example explanation for a test sample:")
        if len(X_test) > 0:
            example_idx = 0
            example_features = X_test[example_idx]
            true_label = y_test[example_idx]
            pred_label = y_pred[example_idx]
            
            explanation = model.explain_prediction(example_features)
            print(f"True label: {true_label}, Predicted: {pred_label}")
            print(explanation)
        
        print("\n>>> Model training and evaluation complete! <<<")
        print(f"The enhanced model is now ready for use in your IDS system.")
        print("To use it in the dashboard, make sure to update your detector to use EnhancedIDSModel.")
        
        return 0  # Successful exit
    
    except Exception as e:
        print(f"ERROR: Error during model training: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1  # Error exit code


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)  # Ensure proper exit code is returned 