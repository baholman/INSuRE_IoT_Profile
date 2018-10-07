#!/bin/python

import os
import sys
from utils.WlanPcapFileParser import WlanPcapFileParser

if len(sys.argv) != 3:
	print('ERROR: Incorrect number of arguments provided')
	print('python3 DeviceDetector <pcap_input_directory> <json_output_directory>')
	exit(-1)

parser = WlanPcapFileParser()
print(parser.getJson(sys.argv[1], sys.argv[2]))
