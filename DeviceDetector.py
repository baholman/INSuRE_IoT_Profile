#!/bin/python

import os
from utils.WlanPcapFileParser import WlanPcapFileParser

parser = WlanPcapFileParser()

file_path = os.path.join(os.getcwd(), 'pcap_files')
print(parser.getJson(file_path))
