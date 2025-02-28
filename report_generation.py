import pandas as pd


def generate_report(anomalies, anomaly_indices, df, report_file):
    
    anomalous_data = df.iloc[anomaly_indices].copy()
    
    print("\nAnomalous rows:")
    print(anomalous_data)
    
    with open(report_file, 'w') as f:
        anomalous_data.to_csv(f, index=False)
