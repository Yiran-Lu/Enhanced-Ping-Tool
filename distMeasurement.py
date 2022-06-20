from os import read
import socket
import time
import struct



SOURCE_IP = socket.gethostbyname(socket.gethostname())
MSG = "measurement for class project. questions to Yiran Lu yxl2297@case.edu or professor mxr136@case.edu"
MAX_ATTEMPTS = 5
SENDINGTIMES = {}
DATAGRAM_TTL = 64
DEST_PORT = 33434
max_length_of_expected_packet = 1500
MY_IP = '172.30.245.102' # for local test only
UNEXPECTED_PACKET = "Caution: Recieve Packet From Unrelated Scource"

MAX = 5000
UDP_HEADER = struct.Struct("!HHHH")
IP_HEADER = struct.Struct('!BBHHHBBH4s4s')
PAYLOAD_LENGTH = 1500 - IP_HEADER.size - UDP_HEADER.size
UDP_PAYLOAD = bytes(MSG	+ 'a'*(1472 - len(MSG)), 'ascii')

# Read the target information from the txt file
def read_targets():
    target = {}
    for line in open('targets.txt'):
        name = line.rstrip()
        target[name] = socket.gethostbyname(name)
    return target

# Generate the sending raw socket
def generate_send_socket():
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    return send_socket

# Generate the receiving raw socket
def generate_recv_socket():
    receive_sock =	socket.socket(socket.AF_INET, socket.SOCK_RAW,	socket.IPPROTO_ICMP)
    receive_sock.setblocking(0)
    receive_sock.bind(("", 0))
    return receive_sock

# Calculate the checksum
def checksum(msg):
	s = 0
	for i in range(0, len(msg), 2):
		w = msg[i] + (msg[i+1] << 8 )
		s = s + w
	s = (s>>16) + (s & 0xffff)
	s = s + (s >> 16)
	s = ~s & 0xffff
	return s

#  Create the IP Header
def create_ip_header(src_ip, dest_ip, ipid):
    # reference from tutorial: 
    # https://www.binarytides.com/raw-socket-programming-in-python-linux/
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0	
    ip_id = ipid
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_saddr = socket.inet_aton ( src_ip )
    ip_daddr = socket.inet_aton ( dest_ip )
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    return IP_HEADER.pack(ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# Create the UDP Header
def create_udp_header(src_port, dest_port, dest_ip, source_ip):
    packet_length = UDP_HEADER.size + PAYLOAD_LENGTH
    current_header = struct.pack('!4s4sBBH', socket.inet_aton ( source_ip ), 
     socket.inet_aton ( dest_ip ), 0, socket.IPPROTO_UDP, packet_length)
    message = current_header + UDP_HEADER.pack(src_port, dest_port, packet_length, 0)
    check = socket.htons(checksum(message + UDP_PAYLOAD))
    udp_header = UDP_HEADER.pack(src_port, dest_port, packet_length, check)
    return udp_header

# Create the Probe Packet that we need to send
def create_probe_packet(src_port, dest_port, src_ip, dest_ip, ipid):
    udp_header = create_udp_header(src_port, dest_port, dest_ip, src_ip)
    ip_header = create_ip_header(src_ip, dest_ip, ipid)
    return ip_header + udp_header + UDP_PAYLOAD

# Calculate the total websites we need to test
def total():
    total_num = 0
    for line in open('targets.txt'):
        total_num = total_num + 1
    return total_num

# Information of the webs
host_info = read_targets()
info = host_info.items()

# Sending Thread
def send_thread(): 
    send_socket = generate_send_socket()
    src_port = DEST_PORT + 1
    for item in info:
        host_name = item[0]
        host_ip = item[1]     
        attempt = 0
        successful_send = False
        id = int(time.time() * 1000) & 0xFFFF
        probe = create_probe_packet(src_port, DEST_PORT, SOURCE_IP, host_ip, id)
        while not successful_send and attempt < MAX_ATTEMPTS:
            try:
                packet_send_time = time.time()
                send_socket.sendto(probe, (host_ip, DEST_PORT))
                SENDINGTIMES[host_name] = packet_send_time
                successful_send = True
                src_port = src_port + 1
            except socket.error:
                print("Sending Failed, Hostname is: {}".format(host_name))
                attempt += 1
        if not successful_send:
            print("Timed Out")
    send_socket.close()

# Receiving Thread
def receiving_thread(): 
        Rcv_socket = generate_recv_socket()
        print("Begin to Receive")
        times_rcved = 0
        hops_rcved = {}
        RTTs = {}
        succeed = {}
        for itm in info: 
            succeed[itm[0]] = False
            host_name = itm[0]
            
        while(times_rcved < total()): 
            times = 0
            try: 
                response = Rcv_socket.recv(MAX)
                pkt_receive_time = time.time()
                found = False
                source_ip = socket.inet_ntoa(response[12:16])
                host_ip = source_ip
                
                dest_port = struct.unpack("!H", response[50:52])[0]
                dest_ip = socket.inet_ntoa(response[16:20])
                for item in info: 
                    if(item[1] == host_ip): 
                        host_name = item[0]
                        print("Now Testing: {}".format(host_name))
                        found = True
                if(found == True): 
                    if(succeed[host_name] != True): 
                        times_rcved = times_rcved + 1
                        R_TTL = response[36]
                        
                        hops = DATAGRAM_TTL - R_TTL
                        hops_rcved[host_name] = hops
                        succeed[host_name] = True

                        request_infos = IP_HEADER.unpack(response[28:48])
                        id =  request_infos[3]

                        RTT = 1000 * (pkt_receive_time - SENDINGTIMES[host_name])
                        RTTs[host_name] = RTT
                        print("Testing Target: {}:{}; Hops: {}; RTT: {}ms; Dest IP: {}, IPID: {}, Dest Port: {}".format(host_name, host_ip, hops, RTT, dest_ip, id, dest_port))

                    else: 
                        print("host already received: {}".format(host_name))

                else: 
                    print("Host name not found")


            except socket.error:
                times = times + 1
                if(times > 8): 
                    send_thread()

        Rcv_socket.close

# Run it!
def run():
    start_time = time.time()
    send_thread()
    receiving_thread()
    end_time = time.time()
    print("Times taken: {}".format(end_time - start_time))

if __name__ == "__main__":
    run()