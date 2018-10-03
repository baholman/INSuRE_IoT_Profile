#!/bin/python

import os
from utils.DeviceFileCreator import DeviceFileCreator

def generatePacket(packet_info):
	packet = {}
	
	# Set header info
	packet['header'] = {}
	packet['header']['source_ip'] = packet_info['source_ip']
	packet['header']['destination_ip'] = packet_info['dest_ip']
	packet['header']['extra'] = 'text'

	# Set body info
	packet['body'] = {}
	packet['body']['blah'] = 'de blah'

	return packet
	

def generateTempFileDict(file_name, packet_info_array):
	file_dict = {}
	file_dict['file_path'] = file_name
	file_dict['protocol'] = 'WLAN'
	file_dict['identifiers'] = ['source_ip', 'destination_ip']
	file_packets = []
	for packet_info in packet_info_array:
		file_packets.append(generatePacket(packet_info))
	file_dict['packets'] = file_packets

	return file_dict

def generateTestDataForDeviceFileCreator():
	files = []
	files.append(generateTempFileDict(
		'file.pcap',
		[{
			'source_ip':'123.456.789.0',
			'dest_ip':'980.123.345.675'
		},
		{
			'source_ip': '874.16.571.123',
			'dest_ip': '132.43.2.1'
		}]))
	files.append(generateTempFileDict(
		'file2.pcap',
		[{
			'source_ip': '123.456.789.0', 
			'dest_ip': '980.123.345.675'
		},
		{
			'source_ip': '1.1.1.1',
			'dest_ip': '2.2.2.2'
		}]))

	return files

sorter = DeviceFileCreator()
test_data = generateTestDataForDeviceFileCreator()
sorter.genDeviceFiles(test_data, '/mnt/c/Users/joyha/Documents/Classes/CIS 890/INSuRE_IoT_Profile/tests')
