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
from utils.DevicePacketSorter import DevicePacketSorter
from utils.TrafficFlow import TrafficFlow
from utils.DeviceConversations import DeviceConversations
from utils.KNN import KNN
import pcapy as p
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re

# Check the number of arguments
if len(sys.argv) != 2:
	print('ERROR: Incorrect number of arguments provided')
	print('python3 DeviceDetector.py <experiment_directory>')
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

print("Processing the PCAP files")

devices_identifiers = []

# Check if the content JSON files have already been created
flow_json_dir =  os.path.join(experiment_dir, 'flow_json')
if os.path.isdir(flow_json_dir):
	print('The pcap files from this experiment have already been converted to flow JSON files')
	for flow_file in os.path.listdir(flow_json_dir):
		flow_info_file = open(os.path.join(flow_json_dir, flow_file))
		flow_info = json.loads(flow_info_file)
else:
	print('The pcap files for this experiment are being converted to flow JSON files')
	# Make the content_json directory
	os.makdirs(content_json_dir)

	# Get the directory for the pcap files
	pcap_dir = os.path.join(experiment_dir, 'pcaps')
	if not os.path.isdir(pcap_dir):
		print('ERROR: The pcap directory provided does not exist')

	for pcap_file in pcap_dir:
		# Create the dictionary of packet information split by pcap file
		parser = WlanPcapFileParser()
		pcap_dict = parser.getJson(pcap_dir)

		file_dict = {}
		file_dict['file_path'] = file_name
		file_dict['protocol'] = 'WLAN'
		file_dict['identifiers'] = ['Ethernet_Source_MAC']
		file_dict['packets'] = []
																				
		# Get file contents
		input_filename_base = os.path.splitext(os.path.basename(input_filename))[0]
		print('Input File Name: ' + input_filename_base)

		# Set up the input file path
		pcap_path = os.path.join(pcap_dir, pcap_file)

		# Get packet info
		for packet in rdpcap(pcap_path):
			packet_dict = {}
			packet_dict['header'] = self.__getHeader(packet)
			packet_dict['body'] = self.__getBody(packet)
			file_dict['packets'].append(packet_dict)

			if len(device_identifiers) == 0:
				# Add device to list of devices
				device_identifiers.append({
					"name": "device_0",
					"Ethernet_Source_MAC": packet_dict['header']['Ethernet_Source_MAC'],
					"IP_Source_Address": packet_dict['header']['IP_Source_Address']
					})
			else:
				found = False
				# Determine if the device already exists
				for device in device_identifiers:
					if device['Ethernet_Source_MAC'] == packet_dict['header']['Ethernet_Source_MAC']:
						found = True

						flow


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

