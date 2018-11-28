#!/bin/python

import os
import json

"""
Device File Creator

Converts a python dictionary of the contents of different PCAP files and sorts them based on device.
It outputs the device files into JSON.
"""
class DevicePacketSorter:
	"""
	Generate the Device Files

	Generates a file for each device represented in the PCAP files with the packets for that device.

	Params:
	input_data - an array of dictionaries containing the input from the PCAP files
	output_dir - a string that is the location where the output files should be saved to
	"""
	def genDeviceFiles(self, input_data, output_dir):
		device_dict = self.__sortPacketsByDevice(input_data)
		self.__outputDeviceFiles(device_dict, output_dir)

	"""
	Sort Packets By Device

	Looking at all the packets for each PCAP file and putting them into a dictionary of device specific packets.

	Params:
	input_data - an array of dictionaries containing the input from the PCAP files
	"""
	def __sortPacketsByDevice(self, input_data):
		devices = []

		for file_dict in input_data:
			# Get the file path from the file
			if 'file_path' not in file_dict.keys():
				print('ERROR: File path was not provided for file')
				continue
			
			file_path = file_dict['file_path']

			# Get identifiers from the file
			if 'identifiers' not in file_dict.keys():
				print('ERROR: File path was not provided for file')
				continue
			
			identifiers = file_dict['identifiers']

			# Handle no identifiers being provided
			if len(identifiers) < 1:
				print('ERROR: No identifiers were provided to label the packets in the file')
				continue

			# Get packets from file
			if 'packets' not in file_dict.keys():
				print('ERROR: Packets array was not defined for the file')
				continue

			for packet in file_dict['packets']:
				packet_identifiers = self.__getPacketIdentifierValues(packet, identifiers)

				# Check if a device for the specific set of identifers for the packet exists
				device_matches = 0
				for device in devices:
					identifiers_match = self.__isIdentifiersMatch(identifiers, device['identifiers'], packet_identifiers)
					# Handle the first packet to device match
					if identifiers_match and device_matches == 0:
						device['packets'].append(packet)
						device_matches += 1
					# Handle subsequent packet to device matches
					elif identifiers_match and device_matches > 0:
						print('ERROR: The packet identifiers are not specific enough to uniquely identify devices')
						error(-1)

				# Handle if the device doesn't match any existing device
				if device_matches == 0:
					# Add a new device for the packet
					devices.append(self.__createNewDevice(packet_identifiers, packet))

		return devices

	"""
	Is Identifiers Match

	Check if the identifiers for the device match the identifiers for the packet.

	Params:
	identifiers - a list of strings that is the set of identifiers
	device_identifiers - a dictionary containing the device identifiers
	packet_identifiers - a dictionary containing the packet identifiers

	Returns: a boolean that specifies if the two have the same values for their identifiers	
	"""
	def __isIdentifiersMatch(self, identifiers, device_identifiers, packet_identifiers):
		match = True
		for identifier in identifiers:
			# Check if the device identifier matches the packet identifier
			if device_identifiers[identifier] != packet_identifiers[identifier]:
				match = False

		return match

	"""
	Create New Device

	Create a dictionary for a new device containing the provided information.

	Params:
	device_identifiers - a dictionary of identifiers for the device
	packet - the packet to add to the device
	"""
	def __createNewDevice(self, device_identifiers, packet):
		device_dict = {}
		device_dict['identifiers'] = device_identifiers
		device_dict['packets'] = []
		device_dict['packets'].append(packet)
		return device_dict

	"""
	Get Packet Idenifier Values

	Get a list of the values in the packet for each identifier of the device.

	Params:
	packet_dict - a dictionary containing the contents of the packet
	identifiers - a list of strings that are the identifiers for a device
	"""
	def __getPacketIdentifierValues(self, packet_dict, identifiers):
		packet_identifiers = {}
		
		# Go through all the identifiers for the device
		for identifier in identifiers:
			# Check if the identifier field is in the header
			if identifier in packet_dict['header'].keys():
				packet_identifiers[identifier] = packet_dict['header'][identifier]
			# Check if the identifier field is in the body
			elif identifier in packet_dict['body'].keys():
				packet_identifiers[identifier] = packet_dict['body'][identifier]
			# Handle the case that the identifier doesn't exist in the packet
			else:
				print('ERROR: Could not find identifier ' + identifier + ' in the packet')
				packet_identifiers[identifier] = 'Unknown'

		return packet_identifiers

	"""
	Output Device Files

	Output the information for each device present to a different JSON file.

	Params:
	device_dict - an array of dictionaries containing information about specific devices
	output_dir - the directory to put the output files in
	"""
	def __outputDeviceFiles(self, device_dict, output_dir):
		device_index = 0
		for device in device_dict:
			# Output dictionary contents to new file as JSON
			output_path = os.path.join(output_dir, 'device_' + str(device_index) + '.json')
			output_file = open(output_path, 'w')
			output_file.write(json.dumps(device))
			device_index += 1
