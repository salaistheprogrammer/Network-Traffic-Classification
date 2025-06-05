from ext_features_preprocess import extract_features

def for_extract(packets_list: list):

    feature = []
    n = 0
    for packets in packets_list:
        feature.append([extract_features(packet) for packet in packets])
        n += 1
        
    return feature
