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
#from utils.DevicePacketSorter import DevicePacketSorter
#from utils.TrafficFlow import TrafficFlow
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
		"name": "device_" + new_device_name,
		"Ethernet_Source_MAC": src_mac,
		"IP_Source_Address": src_ip
	})
	return new_device_name

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
verbose = True

# Check if the content JSON files have already been created
content_json_dir = os.path.join(experiment_dir, 'content_json')
flow_json_dir =  os.path.join(experiment_dir, 'flow_json')
if os.path.isdir(content_json_dir) and os.path.isdir(flow_json_dir):
	print('The pcap files from this experiment have already been converted to flow JSON files')
else:
	print('The pcap files for this experiment are being converted to flow JSON files')
	# Make the content_json directory
	os.makedirs(content_json_dir)
	os.makedirs(flow_json_dir)

	# Get the directory for the pcap files
	pcap_dir = os.path.join(experiment_dir, 'pcaps')
	print("PCAP dir: " + pcap_dir)
	if not os.path.isdir(pcap_dir):
		print('ERROR: The pcap directory provided does not exist')

	for pcap_file in os.listdir(pcap_dir):
		# Create the dictionary of packet information split by pcap file
		parser = PcapParserHelper()
		#pcap_dict = parser.getJson(pcap_dir)

		#file_dict = {}
		#file_dict['file_path'] = file_name
		#file_dict['protocol'] = 'WLAN'
		#file_dict['identifiers'] = ['Ethernet_Source_MAC']
		#file_dict['packets'] = []
																				
		# Get file contents
		#input_filename_base = os.path.splitext(os.path.basename(input_filename))[0]
		#print('Input File Name: ' + input_filename_base)

		# Set up the input file path
		print("PCAP file: " + pcap_file)
		pcap_path = os.path.join(pcap_dir, pcap_file)
		print("PCAP path: " + pcap_path)

		# Check if file exists
		if not os.path.isfile(pcap_path):
			print("PCAP was not a file")
			continue

		# Get packet info
		for packet in rdpcap(pcap_path):
			# Get path for the file of the device that this packet is associated with
			device_name = getDeviceFileName(packet)
			device_content_path = os.path.join(content_json_dir, device_name + ".json")

			# See if the file already exists
			if os.path.isfile(device_content_path):
				device_file = open(device_content_path, "a")
			else:
				# Add header to device file
				device_file = open(device_content_path, "w")
				device_file.write("{")
				device_file.write("	name: '" + device_name + "',")
				device_file.write("	protocol: 'WLAN',")
				device_file.write("	identifiers: ['Ethernet_Source_MAC'],")
				device_file.write("	packets: [")

			
			# Get packet attributes
			device_file.write("		{")
			device_file.close()

			parser.getHeader(packet, device_content_path, verbose)
			parser.getBody(packet, device_content_path, verbose)

			device_file = open(device_content_path, "a")
			device_file.write("		}")
			device_file.close()

			# Get path for the file of the device that this packet is associated with
			ip_src = ""
			ip_dest = ""
			if packet.haslayer(IP):
				ip_src = str(packet[IP].src)
				ip_dest = str(packet[IP].dst)
			device_flow_dir = os.path.join(flow_json_dir, device_name)
			device_flow_path = ""
			for filename in os.listdir(device_flow_path):
				if	(filename == ip_src + "-" + ip_dest + ".json") or\
					(filename == ip_dest + "-" + ip_src + ".json"):
					device_flow_path = os.path.join(device_flow_dir, filename)
				else:
					device_flow_path = os.path.join(device_flow_dir, header["IP_Source_Address"] + "-" + header["IP_Destination_Address"] + ".json")
					device_flow_file = open(device_flow_path, "w")
					device_flow_file.write("{")
					device_flow_file.write("	src_ip: '" + ip_src + "',")
					device_flow_file.write("	src_name: '" + device_name + "',")
					device_flow_file.write("	dest_ip: '" + ip_dest + "',")
					device_flow_file.write("	dest_name: '',")
					device_flow_file.write("	packets: [")
					device_flow_file.close()

			device_flow_file = open(device_flow_path, "a")
			device_flow_file.write("		{")
			device_flow_file.close()

			# Get packet attributes
			header = self.__getHeader(packet, device_flow_path, False)
			body = self.__getBody(packet, device_flow_path, False)

			device_flow_file = open(device_flow_path, "a")
			device_flow_file.write("		}")
			device_flow_file.close()

	# Close all the device files
	for device in device_identifiers:
		device_name = device["name"]
		device_path = os.path.join(flow_json_dir, device_name + ".json")
		
		device_file = open(device_path, "a")
		device_file.write("	}")
		device_file.write("}")
		device_file.close()

	# Close all the flow files
	for dirname in os.list.dir(flow_json_dir):
		if os.path.isdir(dirname):
			device_flow_path = os.path.join(flow_json_dir, dirname)
			for filename in os.listdir(device_flow_path):
				device_flow_file_path = os.path.join(device_flow_path, filename)
				flow_file = open(device_flow_file_path, "a")
				flow_file.write("	]")
				flow_file.write("}")
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
