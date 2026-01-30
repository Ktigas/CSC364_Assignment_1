import socket
import sys
import traceback
from threading import Thread


# Helper Functions

def create_socket(host, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    return soc


def read_csv(path):
    table_file = open(path, "r")
    table = table_file.readlines()
    table_list = []
    for line in table:
        row = line.strip().split(',')
        row = [item.strip() for item in row]
        table_list.append(row)
    table_file.close()
    return table_list


def find_default_gateway(table):
    for row in table:
        if row[0] == '0.0.0.0':
            return row[3]


def generate_forwarding_table_with_range(table):
    new_table = []
    for row in table:
        if row[0] != '0.0.0.0':
            network_dst_string = row[0]
            netmask_string = row[1]
            network_dst_bin = ip_to_bin(network_dst_string)
            netmask_bin = ip_to_bin(netmask_string)
            network_dst_int = int(network_dst_bin, 2)
            netmask_int = int(netmask_bin, 2)
            ip_range = find_ip_range(network_dst_int, netmask_int)
            new_row = [network_dst_string, netmask_string, row[2], row[3], ip_range[0], ip_range[1]]
            new_table.append(new_row)
    return new_table


def ip_to_bin(ip):
    ip_octets = ip.split('.')
    ip_bin_string = ""
    for octet in ip_octets:
        int_octet = int(octet)
        bin_octet = bin(int_octet)
        bin_octet_string = bin_octet[2:]
        while len(bin_octet_string) < 8:
            bin_octet_string = '0' + bin_octet_string
        ip_bin_string = ip_bin_string + bin_octet_string
    ip_int = int(ip_bin_string, 2)
    return bin(ip_int)


def find_ip_range(network_dst, netmask):
    bitwise_and = network_dst & netmask
    compliment = bit_not(netmask)
    min_ip = bitwise_and
    max_ip = min_ip + compliment
    return [min_ip, max_ip]


def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


def receive_packet(connection, max_buffer_size):
    received_packet = connection.recv(max_buffer_size)
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)
    decoded_packet = received_packet.decode().strip()
    print("received packet", decoded_packet)
    write_to_file('./output/received_by_router_4.txt', decoded_packet)
    packet = decoded_packet.split(',')
    return packet


def write_to_file(path, packet_to_write, send_to_router=None):
    out_file = open(path, "a")
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    out_file.close()


def start_server():
    # Router 4 ONLY listens on port 8004
    host = '127.0.0.1'
    port = 8004
    
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")
    
    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()
    
    soc.listen(5)
    print("Router 4 now listening on port 8004")

    # Read forwarding table
    forwarding_table = read_csv('input/router_4_table.csv')
    default_gateway_port = find_default_gateway(forwarding_table)
    forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

    while True:
        connection, address = soc.accept()
        ip, port_num = address
        print(f"Connected with {ip}:{port_num}")
        try:
            Thread(target=processing_thread, args=(connection, ip, port_num, forwarding_table_with_range, default_gateway_port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()


# Also update the processing_thread to handle connections properly
def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, max_buffer_size=5120):
    # Router 4 connects to other routers as a CLIENT
    # But we only create sockets when needed, not at thread start
    
    while True:
        packet = receive_packet(connection, max_buffer_size)

        if not packet or len(packet) < 4:
            break

        sourceIP = packet[0]
        destinationIP = packet[1]
        payload = packet[2]
        ttl = int(packet[3])

        new_ttl = ttl - 1
        new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"

        destinationIP_bin = ip_to_bin(destinationIP)
        destinationIP_int = int(destinationIP_bin, 2)

        sending_port = None
        for row in forwarding_table_with_range:
            min_ip = int(row[4])
            max_ip = int(row[5])
            if min_ip <= destinationIP_int <= max_ip:
                sending_port = row[3]
                break

        if sending_port is None:
            sending_port = default_gateway_port

        # Router 4 routing logic - create sockets only when needed
        if new_ttl <= 0:
            print("DISCARD:", new_packet)
            write_to_file('./output/discarded_by_router_4.txt', new_packet)
        elif sending_port == '8005':  # To Router 5
            print("sending packet", new_packet, "to Router 5")
            try:
                router5_socket = create_socket('127.0.0.1', 8005)
                router5_socket.sendall(new_packet.encode())
                router5_socket.close()
            except:
                print("Failed to send to Router 5")
            write_to_file('./output/sent_by_router_4.txt', new_packet, '5')
        elif sending_port == '8006':  # To Router 6
            print("sending packet", new_packet, "to Router 6")
            try:
                router6_socket = create_socket('127.0.0.1', 8006)
                router6_socket.sendall(new_packet.encode())
                router6_socket.close()
            except:
                print("Failed to send to Router 6")
            write_to_file('./output/sent_by_router_4.txt', new_packet, '6')
        elif sending_port == '8002':  # Port 'b' to Router 2
            print("sending packet", new_packet, "to Router 2")
            try:
                router2_socket = create_socket('127.0.0.1', 8002)
                router2_socket.sendall(new_packet.encode())
                router2_socket.close()
            except:
                print("Failed to send to Router 2")
            write_to_file('./output/sent_by_router_4.txt', new_packet, '2')
        elif sending_port == '127.0.0.1':  # Local destinations
            print("OUT:", payload)
            write_to_file('./output/out_router_4.txt', payload)
        else:
            print("DISCARD:", new_packet)
            write_to_file('./output/discarded_by_router_4.txt', new_packet)
    
    connection.close()


# Main Program
if __name__ == "__main__":
    start_server()