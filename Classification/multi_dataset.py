from ext_features_preprocess import extract_features
# from scapy.all import rdpcap
# from pyshark import FileCapture


def for_extract(packets_list: list):

    feature = []
    n = 0
    for packets in packets_list:
        feature.append([extract_features(packet) for packet in packets])
        n += 1
        
    return feature























# features = for_extract(packets)
# print(features[0])

# packets1 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.UDP.DNSANY.pcap")
# packets2 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.dns.RRSIG.fragmented.pcap")
# # packets3 = FileCapture("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.TCP.syn.optionallyACK.optionallysamePort.pcapng")
# # packets4 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.UDP.bacnet.IOT.37810.pcapng")
# packets5 = rdpcap("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.UDP.IOT.port37810.JSON.pcap")

# packets = [packets1, packets2, packets5]