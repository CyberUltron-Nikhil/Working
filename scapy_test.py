from scapy.all import sniff , IP  ,TCP , Packet
from scapy.config import conf

conf.debug_dissector = 2

def packet_handler(pkt):
    if TCP in pkt and IP in pkt and pkt[TCP].payload:
        tcp_sport=pkt[TCP].sport
        tcp_dport=pkt[TCP].dport
        payload_len=len(pkt[TCP].payload)
        tcp_dataofs=pkt[TCP].dataofs
        tcp_flags=pkt[TCP].flags.value
        payload_bytes=list(pkt[TCP].payload.load)
        ip_len=pkt[IP].len
        ip_ttl=pkt[IP].ttl
        ip_tos=pkt[IP].tos
        print(ip_len , ip_tos , ip_ttl , tcp_sport ,  tcp_dport , payload_len , tcp_dataofs , tcp_flags , payload_bytes)

   
    

p=sniff(prn=packet_handler)
print(p)
