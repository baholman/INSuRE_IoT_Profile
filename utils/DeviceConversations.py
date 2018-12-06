#!/bin/python

import os
import json

"""
Device Conversations

Collections conversation information about the different flows handled by the device files.
"""
class DeviceConversations:
	"""
	Get Conversations

	Gets the information about conversations between devices and saves information about those
	conversations to JSON files.

	Params:
	flows - an array of dictionaries which contains the flows for the devices
	output_dir - a string that is the location where the output files should be saved to
	conv_sep_time - a number containing the amount of time between conversations
	"""
	def getConversations(self, flows, output_dir, conv_sep_time):
		flows = self.__getConversationsForFlows(flows, conv_sep_time)
		flows = self.__analyzeConversationAttributes(flows)
		self.__outputFiles(flows, output_dir)

	"""
	Get Conversations for Flows

	Get a set of conversations from the traffic flows of the different devices from the PCAP files.

	Params:
	flows - an array of dictionaries that contain the flow inforamtion for two devices
	conv_sep_time - the number of milliseconds to separate the conversations
	
	Returns: an array of dictionaries that contain the flows and conversations
	"""
	def __getConversationsForFlows(self, flows, conv_sep_time):
		if len(flows) > 0:
			for flow_id in range(len(flows)):
				flows = self.__getConversationsForFlow(flow_id, conv_sep_time, flows)

		return flows

	"""
	Get Conversations for Flow
	
	Get a set of conversations from the current traffic flow.

	flow - an integer identifier for the flow
	conv_sep_time - the number of milliseeconds to separate the conversations
	flows - an array of dictionaries that contain the flows for all devices

	Returns: an array of dictionaries that contian the flows and conversations
	"""
	def __getConversationsForFlow(self, flow_id, conv_sep_time, flows):
		flow = flows[flow_id]
		for packet_type in ['DNS', 'TCP', 'UDP', 'IP', 'ICMP', 'ARP', 'Ethernet']:
			conversation_packets = []
			for packet_id in range(len(flow['packets']) - 1):
				# Ignore the packet if it isn't of the correct type
				if flow['packets'][packet_id]['header']['Packet_Type'] != packet_type:
					continue

				# Check if the packet is the end of a conversation
				current_packet = flow['packets'][packet_id]
				next_packet = flow['packets'][packet_id + 1]

				current_packet_time = current_packet['header']['time']
				next_packet_time = next_packet['header']['time']
				if current_packet_time + conv_sep_time >= next_packet_time:
					conversation_packets.append(current_packet)
					conversation = {}
					conversation['packets'] = conversation_packets
					conversation['protocol'] = packet_type
					flow['conversations'].append(conversation)
					conversation_packets = []
				else:
					conversation_packets.append(current_packet)

			# Check if there were any conversations that have not been added to the flow yet
			if len(conversation_packets) != 0:
				conversation = {'packets': conversation_packets}
				conversation['protocol'] = packet_type
				flow['conversations'].append(conversation)

		return flows

	"""
	Analyze Conversation Attributes

	Analyze the attributes of a conversation to provide a good idea to machine learning of
	what the conversation consists of.

	Params:
	flows - an array of dictionaries that contains the conversations for all devices

	Returns: an array of dictionaries that contain the conversations for all devices
	"""
	def __analyzeConversationAttributes(self, flows):
		for flow in flows:
			for conversation in flow['conversations']:
				tcp_num = 0
				udp_num = 0
				dns_num = 0
				icmp_num = 0
				ip_num = 0
				arp_num = 0
				eth_num = 0

				conversation['Num_Packets'] = len(conversation['packets'])

		return flows

	"""
	Output Device Files

	Output the information for each device present to a different JSON file.

	Params:
	flows_dict - an array of dictionaries containing conversation information
	output_dir - the directory to put the output files in
	"""
	def __outputFiles(self, flows_dict, output_dir):
		# Output dictionary contents to new file as JSON
		output_path = os.path.join(output_dir, 'traffic_flows_conversations.json')
		output_file = open(output_path, 'w')
		output_file.write(json.dumps(flows_dict))
