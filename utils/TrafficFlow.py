#!/bin/python

import os
import json

"""
Traffic Flow

Creates flows of packets between two different devices and attempts to associate requests and responses.
"""
class TrafficFlow:
	"""
	Get the Traffic Flows

	Get a dictionary of the traffic flows between devices.

	Params:
	input_dir - a string with the directory of the json files for each device

	Returns: an array of dictionaries with flows between two devices
	"""
	def getTrafficFlows(self, input_dir):
		output = []
		
		for file_name in os.listdir(input_dir):
			# Load in the input file
			input_file_path = os.path.join(input_dir, file_name)
			input_file = open(input_file_path, "r")
			input_json = json.loads(input_file.read())

			# Get the packets for the input file
			packets = input_json['packets']
			src_mac = input_json['identifiers']['Ethernet_Source_MAC']

			# Get the flows for the device
			output = self.__getDeviceFlows(packets, src_mac, file_name, output)

		return output

	"""
	Get Device Flows

	Sorts out the packets based on which packets are talking from a specific IP address to a specific
	IP address.

	Params:
	packets - a list of all the packets from the device JSON file
	device_src_mac - a string containing the MAC address of the device
	file_name - a string containing the name of the device file
	all_flows - an array of all flows between devices

	Returns: an array of dictionaries containing the flow information
	"""
	def __getDeviceFlows(self, packets, device_src_mac, file_name, flows):
		for packet in packets:
			# Ignore the packet if it doesn't have source and destination IP addresses
			if 'IP_Source_Address' not in packet['header'].keys() or 'IP_Destination_Address' not in packet['header'].keys():
				continue

			src_addr = packet['header']['IP_Source_Address']
			dest_addr = packet['header']['IP_Destination_Address']
			packet_src_mac = packet['header']['Ethernet_Source_MAC']
			packet_dest_mac = packet['header']['Ethernet_Destination_MAC']
			device_name = os.path.splitext(file_name)[0]

			flows = self.__createNewFlow(src_addr, dest_addr, packet_src_mac, packet_dest_mac, device_src_mac, device_name, flows)

			flows = self.__addPacketToFlow(packet, src_addr, dest_addr, flows)

		return flows

	"""
	Create New Flow

	Create a new flow between the two identifiers if one does not currently exist.

	Params:
	src_addr - a string containing the source IP address
	dest_addr - a string containing the destination IP address
	src_mac - the mac address of the source device
	src_device_name - a string that specifies the name of the source device
	flows - an array of dictionaries containing the flow information for all devices
	
	Returns: an array of dictionaries containing the flow information for all devices
	"""
	def __createNewFlow(self, src_addr, dest_addr, src_mac, dest_mac, device_mac, src_device_name, flows):
		# Search for existing conversation
		found = False
		if len(flows) > 0:
			for flow in flows:
				if (flow['Device_A_Addr'] == src_addr) and\
					(flow['Device_B_Addr'] == dest_addr):
					found = True
					if flow['Device_A_Name'] == "" and src_mac == device_mac:
						flow['Device_A_Name'] = src_device_name
				elif (flow['Device_B_Addr'] == src_addr) and\
					(flow['Device_A_Addr'] == dest_addr):
					found = True
					if flow['Device_B_Name'] == "" and dest_mac == device_mac:
						flow['Device_B_Name'] = src_device_name

		# Create new conversation if one does not exist
		if found == False:
			flows.append(
				{
					'Device_A_Addr': src_addr,
					'Device_A_Name': src_device_name,
					'Device_B_Addr': dest_addr,
					'Device_B_Name': '',
					'packets': [],
					'conversations': [],
				}
			)

		return flows

	"""
	Add Packet to Flow

	Add the specified packet to the proper flow.

	Params:
	packet - a dictionary of information about a packet
	src_addr - a string containing the source IP address specified in the packet
	dest_addr - a string containing the destination IP address specified in the packet
	flows - an array of dictionaries containing the flow information

	Returns: an array of dictionaries containing the flows for all devices
	"""
	def __addPacketToFlow(self, packet, src_addr, dest_addr, flows):
		# Add packet to existing flow
		found = False
		for flow in flows:
			if ((flow['Device_A_Addr'] == src_addr) and\
				(flow['Device_B_Addr'] == dest_addr)) or\
				((flow['Device_B_Addr'] == src_addr) and\
				(flow['Device_A_Addr'] == dest_addr)):
				found = True
				flow['packets'].append(packet)

		# Create new conversation if one does not exist
		if found == False:
			print('ERROR: Flow was not found for packet')
			exit(-1)

		return flows
