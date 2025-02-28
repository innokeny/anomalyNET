import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import time
import numpy as np
import logging
from capture_traffic import capture_traffic
from data_digitization import pcap_to_matrix
from report_generation import generate_report
import joblib
from sklearn.preprocessing import StandardScaler


logging.basicConfig(filename='anomaly_detection.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')


class AnomalyDetector(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(24, 32), 
            nn.ReLU(),
            nn.Linear(32, 16)
        )

        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 24) 
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

def detect_anomalies(data_loader, model, threshold):
    model.eval()
    anomalies = []
    anomaly_indices = []
    total_processed = 0

    with torch.no_grad():
        for batch in data_loader:
            inputs = batch[0].to(device).float()
            batch_size = inputs.size(0)

            outputs = model(inputs)
            loss = torch.mean((outputs - inputs)**2, dim=1)
            batch_anomalies = (loss > threshold).cpu().numpy()

            batch_anomaly_indices = np.where(batch_anomalies)[0]

            global_indices = batch_anomaly_indices + total_processed
            anomaly_indices.extend(global_indices.tolist())

            total_processed += batch_size

            anomalies.extend(batch_anomalies)

    return anomalies, anomaly_indices

DURATION = 300  # Traffic capture period in seconds
OUTPUT_PCAP = "network_traffic.pcap"
OUTPUT_CSV = "traffic_features.csv"
MODEL_PATH = "anomaly_detector.pth"
THRESHOLD = 0.0054  # Anomaly threshold
REPORT_FILE = "anomaly_report.csv"

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = AnomalyDetector().to(device)
model.load_state_dict(torch.load(MODEL_PATH))
model.eval()

while True:
    try:
        # Capture traffic
        logging.info("Starting traffic capture.")
        capture_traffic(DURATION, OUTPUT_PCAP, interval=60)
        
        # Digitize data
        logging.info("Digitizing data.")
        df = pcap_to_matrix(OUTPUT_PCAP, OUTPUT_CSV)
        
        # Load data for anomaly detection
        data = df.values.astype(np.float32)
        loaded_scaler = joblib.load('scaler.pkl')
        data = loaded_scaler.transform(data)
        dataset = TensorDataset(torch.tensor(data))
        data_loader = DataLoader(dataset, batch_size=256, shuffle=False)
        
        # Detect anomalies
        logging.info("Detecting anomalies.")
        anomalies, anomaly_indices = detect_anomalies(data_loader, model, THRESHOLD)
        
        # Generate report
        logging.info("Generating report.")
        generate_report(anomalies, anomaly_indices, df, REPORT_FILE)
        
        logging.info(f'Number of anomalies detected: {sum(anomalies)}')
        
        # Wait before next cycle
        time.sleep(60)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        break


