#!/bin/python
import sys

# Ignore Future warning error
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

# Check that the python version being used is Python3
major_python_version = sys.version_info[0]
if major_python_version != 3:
	print("ERROR: You need to use Python 3 to run this program")
	exit(1)

import os
from utils.PcapParserHelper import PcapParserHelper
from utils.KNN import KNN
import pcapy as p
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re
import json
import sys

device_identifiers = []
CONVERSATION_THRESHOLD = 5

def getDeviceFileName(packet):
	found = False

	# Get identifiying attributes
	src_mac = "Unknown"
	src_ip = "Unknown"

	if packet.haslayer(Ether):
		src_mac = str(packet[Ether].src)

	if packet.haslayer(IP):
		src_ip = str(packet[IP])

	# Detemine if the device already exists
	if len(device_identifiers) > 0:
		for device in device_identifiers:
			if device['Ethernet_Source_MAC'] == src_mac:
				return device["name"]

	# Add new device to list
	new_device_name = "device_" + str(len(device_identifiers))
	device_identifiers.append({
		"name": new_device_name,
		"Ethernet_Source_MAC": src_mac,
		"IP_Source_Address": src_ip
	})

	return new_device_name

def getFlowFilePath(packet, flow_json_dir, device_name):
	# Get packet information for filename
	ip_src = ""
	ip_dest = ""
	if packet.haslayer(IP):
		ip_src = str(packet[IP].src)
		ip_dest = str(packet[IP].dst)

	if ip_src == "" and ip_dest == "":
		return "none"
	
	# Determine if device directory exists
	device_flow_dir = os.path.join(flow_json_dir, device_name)
	if not os.path.exists(device_flow_dir):
		os.makedirs(device_flow_dir)

	# Get filename if it is an existing file
	device_flow_path = ""
	for filename in os.listdir(device_flow_dir):
		if	(filename == ip_src + "-" + ip_dest + ".json"):
			return os.path.join(device_flow_dir, filename)

	# Make new file if a file doesn't exist for the flow
	device_flow_path = os.path.join(device_flow_dir, ip_src + "-" + ip_dest + ".json")
	device_flow_file = open(device_flow_path, "w")
	device_flow_file.write("{\n")
	device_flow_file.write("	src_ip: '" + ip_src + "',\n")
	device_flow_file.write("	src_name: '" + device_name + "',\n")
	device_flow_file.write("	dest_ip: '" + ip_dest + "',\n")
	device_flow_file.write("	dest_name: '',\n")
	device_flow_file.write("	packets: [\n")
	device_flow_file.close()
	return device_flow_path

def getConversationAttributesForFlow(flow_file_name):
	# Get the contents of the flow file
	flow_file_path = os.path.join(device_dir_path, flow_file_name)
	flow_file = open(flow_file_path, "r")
	start_reading_packets = False
	row = 0
	packets = []
	packet = {}
	flow_src_ip = ""
	for line in flow_file.readlines():
		if row == 2:
			# Get source IP for flow
			lineRe = list(re.finditer(r"\tsrc_ip: '(?P<ip>\d*.\d*.\d*.\d*)',", line))
			if len(lineRe) > 0:
				outputDict = lineRe[0].groupdict()
				flow_src_ip = outputDict["ip"]
		elif row > 5:
			if "{" in line:
				# Do nothing
				pass
			elif "\t}" in line:
				# Add packet to list of packets for flow
				num_packets = len(packets)
				if num_packets > 0:
					spot_found = False
					# Sort the packets based on timestamp
					for packet_index in range(num_packets):
						current_packet = packets[packet_index]

						# Determine if the current packet time is greater than the time of the packet being placed
						if spot_found == False and packet["Packet_Timestamp"] < current_packet["Packet_Timestamp"]:
							after_packets = packets[packet_index:num_packets]
							packets[packet_index] = packet
							packets[packet_index + 1: num_packets + 1] = after_packets
							spot_found = True
					if spot_found == False:
						packets.append(packet)
				else:
					packets.append(packet)
							
				packet = {}
			else:
				# Pull out a line from the packet and add it to the packet object
				lineRe = list(re.finditer(r"\t\t\t(?P<key>[^ ]*): '(?P<value>.*)',", line))
				if len(lineRe) > 0:
					outputDict = lineRe[0].groupdict()
					key = outputDict["key"]
					value = outputDict["value"]
					# Determine if the key is necessary to calculate the conversation information
					if	key == "Packet_Timestamp" or\
						key == "Packet_Type" or\
						key == "Packet_Length" or\
						key == "Ethernet_Source_MAC" or\
						key == "Ethernet_Destination_MAC" or\
						key == "IP_Source_Address" or\
						key == "IP_Destination_Address" or\
						key == "IP_Source_Version" or\
						key == "TCP_Source_Port" or\
						key == "TCP_Destination_Port" or\
						key == "TCP_Sequence_Number" or\
						key == "TCP_Acknowledge_Number" or\
						key == "UDP_Source_Port" or\
						key == "UDP_Destination_Port" or\
						key == "DNS_Identifier" or\
						key == "DNS_Query_Or_Response" or\
						key == "DNS_Response_Code":
						packet[key] = value
		row += 1

	# Pull out the conversations from the flow packets
	conversation_attributes = []
	conversations = {
		"TCP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"UDP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"DNS": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"IP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"ICMP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"ARP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"Ethernet": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		}
	}

	for packet in packets:
		ptype = packet["Packet_Type"]
		ptime = packet["Packet_Timestamp"]
		if float(conversations[ptype]["last_packet_timestamp"]) + float(CONVERSATION_THRESHOLD) >= float(ptime):
			conv = conversations[ptype]
			conv_stats = []
	
			# Add attribute for number of TCP packets
			if "TCP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)
	
			# Add attribute for number of UDP packets
			if "UDP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of DNS packets
			if "DNS" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of IP packets
			if "IP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of ICMP packets
			if "ICMP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of ARP packets
			if "ARP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of Ethernet packets
			if "Ethernet" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add the average packet length
			conv_stats.append(float(conv["total_packet_length"]) / float(conv["num_packets_total"]))
			# Add number of packets sent
			conv_stats.append(conv["num_packets_sent"])

			# Add the number of packets received
			conv_stats.append(conv["num_packets_received"])

			# Add the number of packets sent to devices inside the network
			conv_stats.append(conv["num_packets_sent_to_in_network_devices"])

			# Add the number of packets sent to devices outside the network
			conv_stats.append(conv["num_packets_sent_to_out_network_devices"])

			# Add the information from the current conversation to the list of information about the conversations for this flow
			conversation_attributes.append(conv_stats)
			
			# Reset everything
			conv_stats = []

			# Reset the conversation information for the stats of the new packet
			conv["num_packets"] = 1
			conv["total_packet_length"] = packet["Packet_Length"]
			conv["num_packets_total"] = 1
			conv["num_packets_sent"] = 0
			conv["num_packets_received"] = 0
			conv["num_packets_sent_to_in_network_devices"] = 0
			conv["num_packets_sent_to_out_network_devices"] = 0

			# Check if the packet is being sent or received
			if packet["IP_Source_Address"] == flow_src_ip:
				conv["num_packets_sent"] += 1
			else:
				conv["num_packets_received"] += 1
		
			# Check if the packet is being sent to a device inside or outside the network
			network_ip_found = False
			dest_ip = packet["IP_Destination_Address"]
			for label_row in ip_labels:
				if label_row["IP"] == dest_ip:
					network_ip_found = True
					conv["num_packets_sent_to_in_network_devices"] += 1

			if network_ip_found == False:
				conv["num_packets_sent_to_out_network_devices"] += 1
		else:
			conv = conversations[ptype]

			conv["last_packet_timestamp"] = packet["Packet_Timestamp"]
			
			# Update the number of packets
			conv["num_packets"] += 1
			conv["num_packets_total"] += 1

			# Update total packet length
			conv["total_packet_length"] = float(conv["total_packet_length"]) + float(packet["Packet_Length"])

			# Check if the packet is being sent or received
			if packet["IP_Source_Address"] == flow_src_ip:
				conv["num_packets_sent"] += 1
			else:
				conv["num_packets_received"] += 1

			# Check if the packet is being sent to a device inside or outside the network
			network_ip_found = False
			dest_ip = packet["IP_Destination_Address"]
			for label_row in ip_labels:
				if label_row["IP"] == dest_ip:
					network_ip_found = True
					conv["num_packets_sent_to_in_network_devices"] += 1

			if network_ip_found == False:
				conv["num_packets_sent_to_out_network_devices"] += 1

	return conversation_attributes

# Check the number of arguments
if len(sys.argv) != 3:
	print('ERROR: Incorrect number of arguments provided')
	print('python3 DeviceDetector.py <experiment_directory> <verbose>')
	exit(-1)

# Get the experiment directory
experiment_dir = sys.argv[1]
experiment_parent_dir =  ''
if ((experiment_dir[0] != '/') or (experiment_dir[0] != '~')):
	experiment_parent_dir = os.getcwd()
else:
	experiment_parent_dir = ''
experiment_dir = os.path.join(experiment_parent_dir, experiment_dir)

if not os.path.isdir(experiment_dir):
	print('ERROR: The experiment directory provided does not exist')
	exit(-1)

verbose = sys.argv[2]

print("Processing the PCAP files")

devices_identifiers = []
#CONVERSATION_THRESHOLD = 5

# Check if the content JSON files have already been created
flow_json_dir =  os.path.join(experiment_dir, 'flow_json')
if os.path.isdir(flow_json_dir):
	print('The pcap files from this experiment have already been converted to flow JSON files')
else:
	print('The pcap files for this experiment are being converted to flow JSON files')
	# Make the content_json directory
	os.makedirs(flow_json_dir)

	# Get the directory for the pcap files
	pcap_dir = os.path.join(experiment_dir, 'pcaps')
	if not os.path.isdir(pcap_dir):
		print('ERROR: The pcap directory provided does not exist')

	for pcap_file in os.listdir(pcap_dir):
		# Create the dictionary of packet information split by pcap file
		parser = PcapParserHelper()

		# Set up the input file path
		pcap_path = os.path.join(pcap_dir, pcap_file)

		# Check if file exists
		if not os.path.isfile(pcap_path):
			print("PCAP was not a file")
			continue

		# Get packet info
		for packet in rdpcap(pcap_path):
			# Get path for the file of the device that this packet is associated with
			device_name = getDeviceFileName(packet)

			device_flow_path = getFlowFilePath(packet, flow_json_dir, device_name)
			if device_flow_path != "none":
				device_flow_file = open(device_flow_path, "a")
				device_flow_file.write("		{\n")
				device_flow_file.close()

				# Get packet attributes
				parser.getHeader(packet, device_flow_path, verbose)
				#body = self.__getBody(packet, device_flow_path, verbose)

				device_flow_file = open(device_flow_path, "a")
				device_flow_file.write("		},\n")
				device_flow_file.close()

	# Close all the flow files
	for dirname in os.listdir(flow_json_dir):
		device_flow_path = os.path.join(flow_json_dir, dirname)
		if os.path.isdir(device_flow_path):
			for filename in os.listdir(device_flow_path):
				device_flow_file_path = os.path.join(device_flow_path, filename)
				flow_file = open(device_flow_file_path, "a")
				flow_file.write("	]\n")
				flow_file.write("}\n")
				flow_file.close()
		else:
			print("Unexpected file found in " + flow_json_dir + " called " + dirname)	

# Tell the user to add the labels to the JSON files
print(('You need to do the following before continuing:\n'
	'1) Create a training_json directory\n'
	'2) Create an eval_json directory\n'
	'3) You need to move files from the json directory into the training_json and eval_json directory based on what you are trying to evaluate\n'
	'4) You need to put the device label in each of the json files in the training_json and eval_json directories\n'
	'5) Press enter to continue on this prompt\n\n'
	'Note: The previous steps will not be repeated unless you delete the json directory. So you can safely stop the program here and restart it.'))
input("Press Enter to continue...")

training_json_dir = os.path.join(experiment_dir, "training_json")
eval_json_dir = os.path.join(experiment_dir, "eval_json")
if not os.path.exists(training_json_dir) or not os.path.exists(eval_json_dir):
	print("ERROR: You need to create training and eval directories and put your flow json files in them before you can continue.")
	sys.exit(-1)

# Read in the set of labels
import csv

ip_labels = []
unique_labels = []
labels_path = os.path.join(experiment_dir, 'device_labels.csv')

line_count = 0
labels_file = csv.reader(open(labels_path, newline='\r'), delimiter=',', quotechar='|')
for row in labels_file:
	if line_count > 0 and len(row) > 0:
		# Add the current entry to the list of IP labels
		ip_labels.append({
			"IP": row[0],
			"Label": row[1],
		})

		# Add the device label to the list of unique labels if it isn't already present
		if row[1] not in unique_labels:
			unique_labels.append(row[1])
	line_count += 1

print("Processing the training data")

# Load in all the flow information for the devices in the training set
training_data = []
training_labels = []
for device_dir in os.listdir(training_json_dir):
	conversation_attributes = []
	conversation_labels = []

	device_dir_path = os.path.join(training_json_dir, device_dir)
	if os.path.isdir(device_dir_path):
		# Get the conversation for the flow
		for flow_file_name in os.listdir(device_dir_path):
			# Get the label for the device based on the source IP on the file
			src_ip = ""
			flowRe = list(re.finditer(r"(?P<src_ip>\d*.\d*.\d*.\d*)-(?P<dst_ip>\d*.\d*.\d*.\d*).json", flow_file_name))
			if len(flowRe) > 0:
				flowElems = flowRe[0].groupdict()
				src_ip = flowElems["src_ip"]
	
			label = "Unknown"
			for iplabel in ip_labels:
				if iplabel["IP"] == src_ip:
					label = iplabel["Label"] 

			ca = getConversationAttributesForFlow(flow_file_name)
			num_conv_attributes = len(conversation_attributes)
			num_ca = len(ca)
			conversation_attributes += ca
			conversation_labels += [label] * num_ca
	training_data += conversation_attributes
	training_labels += conversation_labels

print("Processing the evaluation data")

# Load in the flow information for the devices in the eval set
for device_dir in os.listdir(eval_json_dir):
	conversation_attributes = []
	conversation_labels = []

	device_dir_path = os.path.join(eval_json_dir, device_dir)
	if os.path.isdir(device_dir_path):
		# Get the conversation for the flow
		for flow_file_name in os.listdir(device_dir_path):
			# Get the label for the device based on the source IP on the file
			src_ip = ""
			flowRe = list(re.finditer(r"(?P<src_ip>\d*.\d*.\d*.\d*)-(?P<dst_ip>\d*.\d*.\d*.\d*).json", flow_file_name))
			if len(flowRe) > 0:
				flowElems = flowRe[0].groupdict()
				src_ip = flowElems["src_ip"]


			label = "Unknown"
			for iplabel in ip_labels:
				if iplabel["IP"] == src_ip:
					label = iplabel["Label"]

			ca = getConversationAttributesForFlow(flow_file_name)
			#print(ca)
			num_conv_attributes = len(conversation_attributes)
			num_ca = len(ca)
			conversation_attributes += ca
			conversation_labels += [label] * num_ca

	print("Starting to run KNN for device " + device_dir)
	# Run the KNN analysis per evaluation device
	k = KNN()
	k.runKNN(training_data, training_labels, conversation_attributes, conversation_labels, unique_labels)

