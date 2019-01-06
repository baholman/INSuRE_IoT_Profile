#!/bin/python
import sys

# Check that the python version being used is Python3
major_python_version = sys.version_info[0]
if major_python_version != 3:
	print("ERROR: You need to use Python 3 to run this program")
	exit(1)

import os
from utils.PcapParserHelper import PcapParserHelper
import pcapy as p
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re
import json
import sys
import csv
import signal
import functools
from contextlib import contextmanager
from multiprocessing import Process, Pool

device_identifiers = []
CONVERSATION_THRESHOLD = 5
CORES = 4

experiment_dir = ""
files_already_closed = False

def getDeviceFileName(packet):
	found = False

	# Get identifiying attributes
	src_mac = "Unknown"
	src_ip = "Unknown"

	if packet.haslayer(Ether):
		src_mac = str(packet[Ether].src)

	if packet.haslayer(IP):
		src_ip = str(packet[IP].src)

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
		return "none", True
	
	# Determine if device directory exists
	device_flow_dir = os.path.join(flow_json_dir, device_name)
	if not os.path.exists(device_flow_dir):
		os.makedirs(device_flow_dir)

	# Get filename if it is an existing file
	device_flow_path = ""
	for filename in os.listdir(device_flow_dir):
		if	(filename == ip_src + "-" + ip_dest + ".json"):
			return os.path.join(device_flow_dir, filename), False

	# Make new file if a file doesn't exist for the flow
	device_flow_path = os.path.join(device_flow_dir, ip_src + "-" + ip_dest + ".json")
	device_flow_file = open(device_flow_path, "w")
	device_flow_file.write('{\n')
	device_flow_file.write('	"src_ip": "' + ip_src + '",\n')
	device_flow_file.write('	"src_name": "' + device_name + '",\n')
	device_flow_file.write('	"dest_ip": "' + ip_dest + '",\n')
	device_flow_file.write('	"dest_name": "",\n')
	device_flow_file.write('	"packets": [\n')
	device_flow_file.close()
	return device_flow_path, True

def closeAllFlowFiles(flow_json_dir):
	global files_already_closed

	if files_already_closed == False:
		# Close all the flow files
		for dirname in os.listdir(flow_json_dir):
			device_flow_path = os.path.join(flow_json_dir, dirname)
			if os.path.isdir(device_flow_path):
				for filename in os.listdir(device_flow_path):
					device_flow_file_path = os.path.join(device_flow_path, filename)
					flow_file = open(device_flow_file_path, "a")
					flow_file.write('\n')
					flow_file.write('	]\n')
					flow_file.write('}\n')
					flow_file.close()
			else:
				print("Unexpected file found in " + flow_json_dir + " called " + dirname)

	files_already_closed = True

def download_pcap_files(pcap_file_names, pcap_dir, flow_json_dir):
	# Create the dictionary of packet information split by pcap file
	parser = PcapParserHelper()

	for pcap_file in pcap_file_names:
		print("Currently processing the " + pcap_file + " PCAP file")

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
				device_flow_file.write('		{\n')
				device_flow_file.close()

				# Get packet attributes
				parser.getHeader(packet, device_flow_path, verbose)
				#body = self.__getBody(packet, device_flow_path, verbose)

				device_flow_file = open(device_flow_path, "a")
				device_flow_file.write('		},\n')
				device_flow_file.close()

def signal_handler(sig, frame):
	flow_json_dir = os.path.join(experiment_dir, 'flow_json')
	closeAllFlowFiles(flow_json_dir)
	sys.exit(0)

def main():
	global experiment_dir

	# Check the number of arguments
	if len(sys.argv) != 3 and len(sys.argv) != 4:
		print('ERROR: Incorrect number of arguments provided')
		print('python3 DeviceDetector.py <experiment_directory> <verbose> <device_names_file>')
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
		return

	# Get the whether the user wants verbose results
	verbose = False
	if sys.argv[2].lower() == "true" or sys.argv[2].lower == "t":
		verbose = True

	# Get the name of the device names file
	if len(sys.argv) == 4:
		device_names = sys.argv[3]
		device_names_parent = ''
		if ((device_names[0] != '/') or (device_names[0] != '~')):
			device_names_parent = os.getcwd()
		else:
			device_names_parent = ''
		device_names_path = os.path.join(device_names_parent, device_names)

		if not os.path.isfile(device_names_path):
			print('ERROR: The device names file provided does not exist')
			return

		device_names_file = open(device_names_path, "r")
		device_names_json = json.loads(device_names_file.read())

		for device_name in device_names_json:
			device = device_names_json[device_name]
			device_identifiers.append({
				"name": device_name,
				"Ethernet_Source_MAC": device["Source MAC Address"],
				"IP_Source_Address": device["IP Address"]
			})

	print("Processing the PCAP files")

	devices_identifiers = []
	CONVERSATION_THRESHOLD = 5

	# Check if the content JSON files have already been created
	flow_json_dir =  os.path.join(experiment_dir, 'flow_json')
	if os.path.isdir(flow_json_dir):
		print('The pcap files from this experiment have already been converted to flow JSON files')
	else:
		print('The pcap files for this experiment are being converted to flow JSON files')
		# Make the content_json directory
		os.makedirs(flow_json_dir)

		# Handle Ctrl+C event
		signal.signal(signal.SIGINT, signal_handler)

		# Get the directory for the pcap files
		pcap_dir = os.path.join(experiment_dir, 'pcaps')
		if not os.path.isdir(pcap_dir):
			print('ERROR: The pcap directory provided does not exist')

		# Create the dictionary of packet information split by pcap file
		parser = PcapParserHelper()

		# Split up available PCAPs based on number of cores
		pcap_dir = os.path.join(experiment_dir, "pcaps")
		# Create the dictionary of packet information split by pcap file
		parser = PcapParserHelper()

		for pcap_file in os.listdir(pcap_dir):
			print("Currently processing the " + pcap_file + " PCAP file")

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

				device_flow_path, is_new_file = getFlowFilePath(packet, flow_json_dir, device_name)
				if device_flow_path != "none":
					device_flow_file = open(device_flow_path, "a")
					if is_new_file:
						device_flow_file.write('		{\n')
					else:
						device_flow_file.write(',\n')
						device_flow_file.write('		{\n')

					device_flow_file.close()

					# Get packet attributes
					parser.getHeader(packet, device_flow_path, verbose)
					#body = self.__getBody(packet, device_flow_path, verbose)

					device_flow_file = open(device_flow_path, "a")

					device_flow_file.write('		}')

					device_flow_file.close()


			print("Finished processing the " + pcap_file + " PCAP file")

		# Close all the flow files
		closeAllFlowFiles(flow_json_dir)

		print(device_identifiers)

		print("Finished processing all files in this run")
			
main()
