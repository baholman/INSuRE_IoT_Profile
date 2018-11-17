#!/bin/python

import os
import json

"""
Time Flow Analyzer

Creates different items for each segment of time in a packet capture.
"""
class TimeFlowAnalyzer:
	"""
	Generate the Time Flow Files

	Generates a file for each time flow segment represented in the content JSON files with the packets for that device.

	Params:
	input_dir - a string with the directory of the json files for each device
	output_dir - a string that is the location where the output files should be saved to
	window_size - a number containing the amount of time each segment will be
	"""
	def genFlowFiles(self, input_dir, output_dir, window_size):
		time_flow_dict = self.__sortPacketsByFlow(input_dir, window_size)
		self.__outputFiles(time_flow_dict, output_dir)

	"""
	Sort Packets By Flow

	Sort all the packets in all the input files in the input directory based on the specified flow window size.

	Params:
	input_dir - a string with the directory of the json files for eaach device
	window_size - a number containing the amount of time each segment will be

	Returns: a dictionary with the file name as the main separator then split out with time windows
	"""
	def __sortPacketsByFlow(self, input_dir, window_size):
		output = []
		for file_name in os.listdir(input_dir):
			input_file_path = os.path.join(input_dir, file_name)
			output = self.__getFlowsForDevice(input_file_path, file_name, output)

		output = self.__getPacketFlowInformation(output)

		return output

	"""
	Get Flows for Device

	Get the flows for a specific device.

	Params:
	input_file_path - a string containing the path to the input file
	file_name - a string containing the name of the device file
	all_flows - an array of all the flows between devices

	Returns: an array of all conversations between devices
	"""
	def __getFlowsForDevice(self, input_file_path, file_name, all_flows):
		# Read in the input file and convert it to a dictionary
		input_file = open(input_file_path, "r")
		input_json = json.loads(input_file.read())

		# Get the packets from the input file
		packets = input_json["packets"]

		# Determine the conversations in the packets (packets between a specific source and destination MAC address)
		all_flows = self.__getFlows(packets, file_name, all_flows)

		return all_flows

	"""
	Get Flows

	Sorts out the packets based on which packets are talking from a specific IP address to a specific
	IP address.

	Params:
	packets - a list of all the packets from the device JSON file
	file_name - a string containing the name of the device file
	all_flows - an array of all flows between devices

	Returns: an array of dictionaries containing the flow information
	"""
	def __getFlows(self, packets, file_name, all_flows):
		output = all_flows

		for packet in packets:
			source_MAC_address = packet["Ethernet_Source_MAC_Address"]
			destination_MAC_address = packet["Ethernet_Destination_MAC_Address"]

			conversations, current_elem = self.__getConversationElem(output, source_MAC_address, file_name, destination_MAC_address)
			output = conversations

			current_elem["packets"].append(packet)

		return output

	"""
	Get Conversation Elem

	Determines which conversation element the current packet belongs to given the source MAC address and destination
	MAC address. If one does not exist, it creates a new element for the packet.

	Params:
	conversations - an array of dictionaries containing the conversation information
	source_MAC - a string containing the source MAC address specified in the packet
	source_device_name - a string containing the source device file name
	destination_MAC - a string containing the destination MAC address specified in the packet

	Returns: an array of dictionaries containing the conversation information and a dictionary of the conversation
		that the specified information fits into
	"""
	def __getConversationElem(self, conversations, source_MAC, source_device_name, destination_MAC):
		current_elem = NULL

		# Search for existing conversation
		found = False
		for elem in conversations:
			if elem["conversation"]["Device_A_MAC_address"] == source_MAC and
				elem["conversation"]["Device_B_MAC_address"] == destination_MAC:
				found = True
				current_elem = elem
				if elem["conversation"]["Device_A_File_Name"] == "":
					elem["conversation"]["Device_A_File_Name"] = source_device_name
			elif elem["conversation"]["Device_B_MAC_Address"] == source_MAC and
				elem["conversation"]["Device_A_MAC_Address"] == destination_MAC:
				found = True
				current_elem = elem
				if elem["conversation"]["Device_B_File_Name"] == "":
					elem["conversation"]["Device_B_File_Name"] = source_device_name

		# Create new conversation if one does not exist
		if found == False:
			conversations.append(
				{
					"conversation":
						{
							"Device_A_MAC_Address": source_MAC,
							"Device_A_File_Name": source_device_name,
							"Device_B_MAC_Address": destination_MAC
						},
					"packets": {}
				}
			)
			current_elem = output[len(output) - 1]

		return conversations, current_elem

	"""
	Get Conversation Flows

	Get the flows for the in the conversation for the specified window size.

	Params:

	"""


	"""
	Output Device Files

	Output the information for each device present to a different JSON file.

	Params:
	device_dict - an array of dictionaries containing information about specific devices
	output_dir - the directory to put the output files in
	"""
	def __outputFiles(self, time_flow_dict, output_dir):
		time_flow_index = 0
		for elem in time_flow_dict:
			# Output dictionary contents to new file as JSON
			output_path = os.path.join(output_dir, 'device_' + device_num + '_' + str(device_index) + '.json')
			output_file = open(output_path, 'w')
			output_file.write(json.dumps(device))
			device_index += 1
