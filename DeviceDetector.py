#!/bin/pythonccess VCenter



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

def getPcapJson(experiment_dir, type_of_data):
	# Get the directory for the pcap files
	pcap_dir = os.path.join(experiment_dir, type_of_data + '_pcaps')
	if not os.path.isdir(pcap_dir):
		print('ERROR: The ' + type_of_data + ' pcap directory provided does not exist')

	# Create the dictionary of packet information split by pcap file
	parser = WlanPcapFileParser()
	pcap_dict = parser.getJson(pcap_dir)

	# Make a directory for the training output
	json_dir = os.path.join(experiment_dir, type_of_data + '_json')
	os.makedirs(json_dir)

	# Create the device specific json files with packets
	sorter = DeviceTrafficSorter()
	sorter.genDeviceFiles(pcap_dict, json_dir)

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

print("Processing the training data")

# Check if the training pcap files have already been processed
training_json_dir =  os.path.join(experiment_dir, 'training_json')
if os.path.isdir(training_json_dir):
	print('The training pcap files from this experiment have already been converted to JSON files')
else:
	getPcapJson(experiment_dir, 'training')

print("Processing the evaluation data")

# Check if the evaluation pcap files have already been processed
eval_json_dir = os.path.join(experiment_dir, 'eval_json')
if os.path.isdir(eval_json_dir):
	print('The evaluation pcap files from this experiment have already been converted to JSON files')
else:
	getPcapJson(experiment_dir, 'eval')

print("Running the KNN algorithm")

# Run the data through the K-Nearest Neighbor algorithm
knn = KNN()
knn.isDir(experiment_dir)

