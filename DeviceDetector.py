#!/bin/python
import sys

# Check that the python version being used is Python3
major_python_version = sys.version_info[0]
if major_python_version != 3:
	print("ERROR: You need to use Python 3 to run this program")
	exit(1)

import os
from utils.WlanPcapFileParser import WlanPcapFileParser
from utils.DeviceTrafficSorter import DeviceTrafficSorter
from utils.KNN import KNN

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

# Check if the training pcap files have already been processed
json_dir =  os.path.join(experiment_dir, 'json')
if os.path.isdir(json_dir):
	print('The pcap files from this experiment have already been converted to JSON files')
else:
	# Get the directory for the pcap files
	pcap_dir = os.path.join(experiment_dir, 'pcaps')
	if not os.path.isdir(pcap_dir):
		print('ERROR: The pcap directory provided does not exist')

	# Create the dictionary of packet information split by pcap file
	parser = WlanPcapFileParser()
	pcap_dict = parser.getJson(pcap_dir)

	# Make a directory for the training output
	json_dir = os.path.join(experiment_dir, 'json')
	os.makedirs(json_dir)

	# Create the device specific json files with packets
	sorter = DeviceTrafficSorter()
	sorter.genDeviceFiles(pcap_dict, json_dir)

# Tell the user to add the labels to the JSON files
print('You need to put labels in each of the JSON files for both the training and the evaluation data. Press any button to contiue when you are done.')
input("Press Enter to continue...")

# Run the data through the K-Nearest Neighbor algorithm
print("Running the KNN algorithm")
knn = KNN()
knn.isDir(experiment_dir)

