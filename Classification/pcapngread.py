from pyshark import FileCapture

packets3 = FileCapture("C:\SIH Classification\SIH Datasets\DDoS\PCAPs\packet-captures-main\\amp.TCP.syn.optionallyACK.optionallysamePort.pcapng")

print(packet for packet in packets3)
