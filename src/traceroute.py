"""
By Ben Pasternak 
Must be run with root privileges
"""


import socket
import struct
import sys
import time
import json


def traceroute(destination, port=33434, timeout=1, max_hops=30):
    """
    Traceroute function.
    param destination: The destination hostname or IP address
    """
    dest_addr = socket.gethostbyname(destination)

    # get appropriate socket type
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')

    # set time to live
    ttl = 1

    # capture hops
    hops = []



    while True:
        # create raw socket
        try:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        except socket.error as e:
            print("Socket could not be created. Error Code : %s" % e)
            sys.exit()

        # set time to live
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, struct.pack("I", ttl))
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TOS, struct.pack("I", 0x02))

        # set timeout
        recv_socket.settimeout(timeout)

        # set source and destination address
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, struct.pack("I", ttl))
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TOS, struct.pack("I", 0x02))
        recv_socket.bind(("", port))

        # send packet
        send_socket.sendto(b"", (dest_addr, port))

        # receive packet
        try:
            recv_socket.sendto(b"", (dest_addr, port))
            _, addr = recv_socket.recvfrom(512)
            host_ip = addr[0]
            

            try:
                hops.append({'ip': host_ip, 'hostname': socket.gethostbyaddr(host_ip)[0], 'ttl': ttl})
                
            except:
                hops.append({'ip': host_ip, 'hostname': None, 'ttl': ttl})
            try:
                print("%d\t%s (%s)" % (ttl, socket.gethostbyaddr(host_ip)[0], host_ip))
            except:
                print("%d\t%s (%s)" % (ttl, host_ip, host_ip))

            # if host_ip is the destination we will finish
            if host_ip == dest_addr:
                break

        except socket.timeout:
            print("%d\t*" % ttl)


        # increment ttl
        ttl += 1

        # break if max hops reached
        if ttl > max_hops:
            send_socket.close()
            recv_socket.close()
            break


        # sleep for 1 second
        time.sleep(1)
    return hops


def write_json(hops):
    """
    Write the hops to a json file
    :param hops: A list of dictionaries that contain the hops
    """
    with open('../data/hops.json', 'w') as fp:
        json.dump(hops, fp)

    

if __name__ == "__main__":
    write_json(traceroute("google.com"))

