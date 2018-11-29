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
	devices_flows - an array of dictionaries which contains the flows for the devices
	output_dir - a string that is the location where the output files should be saved to
	conv_sep_time - a number containing the amount of time between conversations
	"""
	def getConversations(self, devices_flows, output_dir, conv_sep_time):
		for device_flows in devices_flows:
			device_conv_info = []
			file_name = device_flows['file_name']
			for flow in device_flows['flows']:
				device_conversations = self.__getConversationsForFlow(flow, conv_sep_time)
				for conversation in device_conversations:
					device_conv_info.append(self.__analyzeConversationAttributes(conversation))
			self.__outputFiles(device_conv_info, file_name,output_dir)

	"""
	Get Conversations for Flow
	
	Get a set of conversations from the current traffic flow.

	flow - a dictionary of the flow data
	conv_sep_time - the number of milliseeconds to separate the conversations

	Returns: an array of dictionaries that contain the conversations
	"""
	def __getConversationsForFlow(self, flow, conv_sep_time):
		conversations = []

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
					conversations.append(conversation)
					conversation_packets = []
				else:
					conversation_packets.append(current_packet)

			# Check if there were any conversations that have not been added to the flow yet
			if len(conversation_packets) != 0:
				conversation = {'packets': conversation_packets}
				conversation['protocol'] = packet_type
				conversations.append(conversation)

		return conversations

	"""
	Analyze Conversation Attributes

	Analyze the attributes of a conversation to provide a good idea to machine learning of
	what the conversation consists of.

	Params:
	conversation - a dictionary of the information about a conversation

	Returns: an array of dictionaries that contain the conversations for all devices
	"""
	def __analyzeConversationAttributes(self, conversation):
		conv_info = {}

		num_tcp_packets = 0
		num_udp_packets = 0
		num_dns_packets = 0
		num_ip_packets = 0
		num_icmp_packets = 0
		num_arp_packets = 0
		num_ethernet_packets = 0

		total_packet_size = 0

		for packet in conversation['packets']:
			# Increment counters for packet type
			if packet['header']['Packet_Type'] == "TCP":
				num_tcp_packets += 1
			elif packet['header']['Packet_Type'] == "UDP":
				num_udp_packets += 1
			elif packet['header']['Packet_Type'] == 'DNS':
				num_dns_packets += 1
			elif packet['header']['Packet_Type'] == 'IP':
				num_ip_packets += 1
			elif packet['header']['Packet_Type'] == 'ICMP':
				num_icmp_packets += 1
			elif packet['header']['Packet_Type'] == 'ARP':
				num_arp_packets += 1
			elif packet['header']['Packet_Type'] == 'Ethernet':
				num_ethernet_packets += 1

			# Increase the packet size for all packets in conversation
			if 'IP_Packet_Length' in packet['header'].keys():
				total_packet_size += packet['header']['IP_Packet_Length']
			else:
				# Handling IPv4 ARP packets
				total_packet_size += 48

		num_packets = len(conversation['packets'])
		conv_info = {
			"Total_Num_Packets": num_packets,
			"Num_TCP_Packets": num_tcp_packets,
			"Num_UDP_Packets": num_udp_packets,
			"Num_DNS_Packets": num_dns_packets,
			"Num_IP_Packets": num_ip_packets,
			"Num_ICMP_Packets": num_icmp_packets,
			"Num_ARP_Packets": num_arp_packets,
			"Num_Ethernet_Packets": num_ethernet_packets,
			"Average_Packet_Length": total_packet_size / num_packets,
		}

		return conv_info

	"""
	Output Device Files

	Output the information for each device present to a different JSON file.

	Params:
	flows_dict - an array of dictionaries containing conversation information
	output_dir - the directory to put the output files in
	"""
	def __outputFiles(self, device_conversations, file_name, output_dir):
		# Output dictionary contents to new file as JSON
		output_path = os.path.join(output_dir, file_name + '.json')
		output_file = open(output_path, 'w')
		output_file.write(json.dumps(device_conversations))
