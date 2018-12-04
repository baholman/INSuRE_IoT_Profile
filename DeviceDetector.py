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
#from utils.DeviceConversations import DeviceConversations
#from utils.KNN import KNN
import pcapy as p
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re

device_identifiers = []

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
	
	# Determine if device directory exists
	device_flow_dir = os.path.join(flow_json_dir, device_name)
	if not os.path.exists(device_flow_dir):
		os.makedirs(device_flow_dir)

	# Get filename if it is an existing file
	device_flow_path = ""
	for filename in os.listdir(device_flow_dir):
		if	(filename == ip_src + "-" + ip_dest + ".json") or\
			(filename == ip_dest + "-" + ip_src + ".json"):
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



"""
	# Create the device specific json files with packets
	sorter = DevicePacketSorter()
	sorter.genDeviceFiles(pcap_dict, content_json_dir)

	print("Determining the time flows of the content JSON files")

	# Check if the traffic JSON files have already been created
	flow_json_dir =  os.path.join(experiment_dir, 'flow_json')
	if os.path.isdir(flow_json_dir):
		print('The pcap files from this experiment have already been converted to flow JSON files')
	else:
		# Create the dictionary of packet information split by pcap file
		flowGenerator = TrafficFlow()
		flow_dict = flowGenerator.getTrafficFlows(content_json_dir)
	
		if flow_dict == []:
			print("ERROR: Empty flow dictionary")
			exit(-1)

		# Make a directory for the training output
		os.makedirs(flow_json_dir)

		# Create the device specific json files with packets
		convCollector = DeviceConversations()
		convCollector.getConversations(flow_dict, flow_json_dir, 5000)

# Tell the user to add the labels to the JSON files
print(('You need to do the following before continuing:\n'
	'1) Create a training_json directory\n'
	'2) Create an eval_json directory\n'
	'3) You need to move files from the json directory into the training_json and eval_json directory based on what you are trying to evaluate\n'
	'4) You need to put the device label in each of the json files in the training_json and eval_json directories\n'
	'5) Press enter to continue on this prompt\n\n'
	'Note: The previous steps will not be repeated unless you delete the json directory. So you can safely stop the program here and restart it.'))
input("Press Enter to continue...")

# Run the data through the K-Nearest Neighbor algorithm
print("Running the KNN algorithm")
knn = KNN()
knn.isDir(experiment_dir, 'content_features.json')
"""
