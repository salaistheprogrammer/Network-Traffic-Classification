import time
import pandas as pd
from scapy.all import sniff, rdpcap
import joblib
from pathlib import Path
from ext_features_preprocess import extract_features


model = joblib.load("path\to\model.pkl")

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
    sniff(prn=handle_packet, timeout=duration)

while True:
    capture_live_traffic(duration=300)  
    print("Captured and predicted on live traffic. Waiting for the next round...")
    time.sleep(60)  
