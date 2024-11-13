import time
import pandas as pd
from scapy.all import sniff, rdpcap
import joblib
from pathlib import Path
from ext_features_preprocess import extract_features


model = joblib.load("path/to/your_trained_model.pkl")



def handle_packet(packet):
    
    features = extract_features(packet)

    if features:
        df = pd.DataFrame([features])

        categorical_columns = df.select_dtypes(include=['object', 'category']).columns.tolist()
        df = pd.get_dummies(df, columns=categorical_columns)
        
        X_new = df.reindex(columns=categorical_columns, fill_value=0)

        prediction = model.predict(X_new)
        
        df['Prediction'] = prediction
        
        df.to_csv("live_predictions.csv", mode='a', header=not Path("live_predictions.csv").exists(), index=False)


def capture_live_traffic(duration=300):
    # Sniff packets for a certain duration
    sniff(prn=handle_packet, timeout=duration)

# Main loop to run the capture, predict, and save process periodically
while True:
    capture_live_traffic(duration=300)  # Capture for 5 minutes
    print("Captured and predicted on live traffic. Waiting for the next round...")
    time.sleep(60)  # Wait for 1 minute before the next round
