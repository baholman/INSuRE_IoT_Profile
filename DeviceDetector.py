#!/bin/python

import os
import sys
from utils.WlanPcapFileParser import WlanPcapFileParser
from utils.DeviceTrafficSorter import DeviceTrafficSorter

if len(sys.argv) != 3:
	print('ERROR: Incorrect number of arguments provided')
	print('python3 DeviceDetector <pcap_input_directory> <json_output_directory>')
	exit(-1)

parser = WlanPcapFileParser()
pcap_dict = parser.getJson(sys.argv[1])

sorter = DeviceTrafficSorter()
sorter.genDeviceFiles(pcap_dict, sys.argv[2])
