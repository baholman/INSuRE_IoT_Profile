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

# Check the number of arguments
if len(sys.argv) != 3:
	print('ERROR: Incorrect number of arguments provided')
	print('python3 DeviceDetector <pcap_input_directory> <json_output_directory>')
	exit(-1)

# Create the dictionary of packet information split by pcap file
parser = WlanPcapFileParser()
pcap_dict = parser.getJson(sys.argv[1])

# Create the device specific json files with packets
sorter = DeviceTrafficSorter()
sorter.genDeviceFiles(pcap_dict, sys.argv[2])
