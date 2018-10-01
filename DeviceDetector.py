#!/bin/python

import os
from utils import WlanPcapFileParser

parser = WlanPcapFileParser()
print(parser.getJson(os.getcwd() + '/pcap_files/'))
