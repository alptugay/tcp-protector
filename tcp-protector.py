#!/usr/bin/python3
from bcc import BPF, table
import socket
import struct
import ctypes as ct
import json
import os
from datetime import datetime
import time
import ipaddress
import threading
import sys

SYNFLOOD_BLOCK_DURATION_SECONDS = 10
SYNFIN_BLOCK_DURATION_SECONDS = 5
DATAONSYN_BLOCK_DURATION_SECONDS = 3

SYNFLOOD_PPS_THRESHOLD = 25

block_ip_map = {}
# { srcip : [time_of_packet, block_duration] }

syn_flood_map = {}
# { srcip : [time_of_first_syn_packet_in_last_second, syn_packet_count_in_last_second] }


def uint32_to_ip(ipn):
    t = struct.pack('I', ipn)
    return socket.inet_ntoa(t)


def ip_to_uint32(ip):
    t = socket.inet_aton(ip)
    return struct.unpack('I', t)[0]

# This function runs in a thread, and every second it checks if there is an IP whose block duration has ended and removes the IP from
# both block_ip_map and the BPF map blacklist
def remove_block():
    while True:
        for ip in list(block_ip_map.keys()):
            block_duration = block_ip_map[ip][1]
            block_time = block_ip_map[ip][0]
            if time.time() - block_duration >= block_time:
                print ("Unblocking: " + uint32_to_ip(ip))
                del block_ip_map[ip]
                del blacklist[ct.c_uint32(ip)]

        time.sleep(1)

# This function runs in a thread, and every second it checks if there is an IP who has exceeded the syn packet count threshold and adds that IP
# to both block_ip_map and the BPF map blacklist
def add_syn_flood_block():
    while True:
        for ip in list(syn_flood_map.keys()):
            count = syn_flood_map[ip][1]
            syn_time = syn_flood_map[ip][0]
            if count > SYNFLOOD_PPS_THRESHOLD:
                print ("Blocking " + uint32_to_ip(ip) + " for " + str(SYNFLOOD_BLOCK_DURATION_SECONDS) + " sec due to "+str(count)+" SYN packets in 1 sec")
                block_ip_map[ip] = [time.time(), SYNFLOOD_BLOCK_DURATION_SECONDS]
                blacklist[ct.c_uint32(ip)] = ct.c_uint32(1)
            # If the pps threshold is not exceeded, I am deleting the IP from the map but his is not the ideal way for pps calculation
            # It could be improved
            del syn_flood_map[ip]
        time.sleep(1)

# This is the main function which analyses the traffic with the data supplied from our BPF program with the perf buffer
# There are 3 attack types that are analysed: DATA on SYN packet, packets with both FIN and SYN set, and SYNFLOOD
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    print(uint32_to_ip(event.srcip) +" DATA:"+ str(event.data)+ " ISSYN:"+str(event.issyn) + " ISFIN:" + str(event.isfin))
    if event.issyn == 1 and event.data > 0:
        print ("Blocking " + uint32_to_ip(event.srcip) + "for " + str(DATAONSYN_BLOCK_DURATION_SECONDS) + " sec" + "due to Data on SYN packet")
        block_ip_map[event.srcip] = [time.time(), DATAONSYN_BLOCK_DURATION_SECONDS]
        blacklist[ct.c_uint32(event.srcip)] = ct.c_uint32(1)
    elif event.issyn == 1 and event.isfin == 1:
        print ("Blocking " + uint32_to_ip(event.srcip) + "for " + str(SYNFIN_BLOCK_DURATION_SECONDS) + " sec" + "due to both SYN and FIN set")
        block_ip_map[event.srcip] = [time.time(), SYNFIN_BLOCK_DURATION_SECONDS]
        blacklist[ct.c_uint32(event.srcip)] = ct.c_uint32(1)
    elif event.issyn == 1 :
        if event.srcip in syn_flood_map:
            syn_flood_map[event.srcip] = [syn_flood_map[event.srcip][0], syn_flood_map[event.srcip][1] + 1]
        else:
            syn_flood_map[event.srcip] = [time.time(),1]
if len(sys.argv) != 2:
    print("USAGE: tcp_protector.py interface")
    sys.exit(1)
else:
    device = sys.argv[1]

#device = "veth-adv04"
src_file = 'tcp-protector.c'

#open eBPF c source code
with open(src_file, 'r') as f:
    file = ''.join(f.readlines())

b = BPF(text=file)
functions = b.load_func('xdp_prog', BPF.XDP)
print("eBPF progam loaded")
b.attach_xdp(device, functions, 0)
print("eBPF program attached")

#load blacklist map
blacklist = b["iplist"]
blacklist.clear()


b["events"].open_perf_buffer(handle_event)
t1 = threading.Thread(target=remove_block)
t2 = threading.Thread(target=add_syn_flood_block)
t1.start()
t2.start()
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

t1.join()
t2.join()
b.remove_xdp(device, 0)
print('done')
