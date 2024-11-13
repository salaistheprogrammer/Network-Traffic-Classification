import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from sklearn.metrics import accuracy_score
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import HistGradientBoostingClassifier

from scapy.all import rdpcap
from pyshark import FileCapture

from ext_features_preprocess import extract_features, preprocess
from categorical_columns_sc import select_categorical_columns
from multi_dataset import for_extract

packets1 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.UDP.DNSANY.pcap")
packets2 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.dns.RRSIG.fragmented.pcap")
# packets3 = FileCapture("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.TCP.syn.optionallyACK.optionallysamePort.pcapng")
# packets4 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.UDP.bacnet.IOT.37810.pcapng")
packets5 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.UDP.IOT.port37810.JSON.pcap")

packets = [packets1, packets2, packets5]

features = for_extract(packets)


df, y = preprocess(features, "C:\SIH Classification\SIH Datasets\DDoS\PCAPs\\amp.TCP.reflection.SYNACK.pcap".replace('\\', '\\\\'))

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

X = df.drop(columns=['Label']).copy()

categorical_columns = select_categorical_columns(df)
print(categorical_columns)

preprocessor = ColumnTransformer(
    transformers=[
        ('pre', OneHotEncoder(sparse=False, handle_unknown='ignore'), categorical_columns)
    ],
    remainder='passthrough'
)


pipeline = Pipeline(steps=[('preprocessor', preprocessor)])
X_encoded = pipeline.fit_transform(X)

encoded_column_names = pipeline.named_steps['preprocessor'].named_transformers_['pre'].get_feature_names_out(categorical_columns)
column_names = list(encoded_column_names) + list(X.columns.difference(categorical_columns))


X = pd.DataFrame(X_encoded, columns=column_names)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

class_counts = np.bincount(y_train)
print(f'Count for DDoS: {class_counts[0]}')

model = HistGradientBoostingClassifier()
model.fit(X_train, y_train)

y_pred = model.predict(X_test) 

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy * 100:.2f}%")