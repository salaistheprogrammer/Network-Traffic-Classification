from scapy.all import rdpcap
import pandas as pd

packets_path = "path/to/pacap_file"
packets = rdpcap(packets_path.replace("\\", "\\\\"))

def extract_features(packets: str) -> dict:

    features = {}
        
    if packets.haslayer('IP'):
        features['ip.src'] = packets['IP'].src
        features['ip.dst'] = packets['IP'].dst
        
    if packets.haslayer('TCP'):
        features['tcp.srcport'] = packets['TCP'].sport
        
    if packets.haslayer('UDP'):
        udp_layer = packets['UDP']
        features['udp.srcport'] = udp_layer.sport
        features['udp.dstport'] = udp_layer.dport
        
    if packets.haslayer('Ethernet'):
        eth_layer = packets['Ethernet']
        features['eth.src'] = eth_layer.src
        features['eth.dst'] = eth_layer.dst
        
    if packets.haslayer('HTTP'):
        http_layer = packets['HTTP']
        features['http.host'] = http_layer.fields.get('Host', '')
        features['http.user_agent'] = http_layer.fields.get('User-Agent', '')
        
    features['frame.len'] = len(packets)
        
    return features


def preprocess(features: dict, packet_path: str):

    df = pd.DataFrame(features)
    df.dropna(axis=1)

    df['Label'] = 'Attack'

    packet_path.replace('\a', '\\\\a')
    packet_path.replace('\\', '\\\\')
    df.to_csv(f"{packet_path}.csv")

    y = df['Label']

    df1 = pd.read_csv(f"{packet_path}.csv")

    return df1, y

