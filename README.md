# AI-Powered Intrusion Detection System

A modern intrusion detection system powered by machine learning for real-time network traffic analysis and threat detection.

## Overview

This project is an AI-powered Intrusion Detection System (IDS) with a modern, Flask-based dashboard for real-time monitoring and visualization of network traffic and security threats.

## Features

- **Modern Flask-Based Dashboard:** Clean, responsive UI built with Flask, Jinja2, Bootstrap, and Chart.js.
- **Real-time Monitoring:** Live traffic analysis and threat detection with instant visual feedback.
- **AI-Powered Detection:** Machine learning algorithms to identify suspicious patterns and potential attacks.
- **Comprehensive Analytics:** Detailed traffic statistics, attack patterns, and security insights.
- **Threat Management:** View, analyze, and respond to detected threats with detailed information.
- **System Settings:** Configure detection sensitivity, notifications, and system maintenance.
- **User-Friendly Interface:** Intuitive controls and visualizations for security professionals of all skill levels.

## Project Structure

```
├── app.py                  # Main Flask application entry point
├── static/                 # Static assets
│   ├── dashboard.css       # Custom CSS styles
│   └── dashboard.js        # Dashboard JavaScript functionality
├── templates/              # Jinja2 templates
│   ├── base.html           # Base template with common structure
│   ├── dashboard.html      # Main dashboard template
│   ├── analytics.html      # Analytics page template
│   ├── threats.html        # Threats management template
│   └── settings.html       # System settings template
├── scripts/                # Backend scripts
│   ├── dashboard.py        # Backend dashboard functionality
│   ├── enhanced_model.py   # AI model for threat detection
│   └── ...                 # Other backend scripts
├── data/                   # Data storage directory
├── models/                 # AI model storage
├── run_dashboard.py        # Launcher script
└── requirements.txt        # Python dependencies
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ai-powered-ids.git
cd ai-powered-ids
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Dashboard

You can run the dashboard using the launcher script:

```bash
python run_dashboard.py
```

Alternatively, you can start it directly:

```bash
python app.py
```

The dashboard will be available at http://localhost:5000 in your web browser.

### Dashboard Pages

1. **Dashboard**: Main overview with real-time monitoring controls, packet statistics, traffic graphs, and recent alerts.
2. **Analytics**: Detailed traffic analysis with hourly traffic patterns, attack distribution, and traffic source analysis.
3. **Threats**: Comprehensive threat management interface to view, analyze, and respond to detected security threats.
4. **Settings**: System configuration for monitoring settings, notifications, and system maintenance.

## System Components

- **Enhanced IDS Model**: Machine learning model for traffic classification
- **Real-time Detector**: Network packet capture and analysis engine
- **Interactive Dashboard**: Web interface for monitoring and control
- **Dataset Builder**: Tool to create training datasets from network traffic
- **Training Scripts**: Utilities to train and improve detection models

## Advanced Usage

### Building a Custom Dataset

To build a custom dataset from your network traffic:

```
python scripts/modern_dataset_builder.py
```

### Training an Enhanced Model

To train a customized detection model:

```
python scripts/train_enhanced_model.py
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- KDD Cup 1999 Dataset for baseline training data
- Scapy and PyShark libraries for packet handling
- Scikit-learn for machine learning algorithms 
