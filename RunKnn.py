#!/bin/python
import sys

# Ignore Future warning error
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

# Check that the python version being used is Python3
major_python_version = sys.version_info[0]
if major_python_version != 3:
	print("ERROR: You need to use Python 3 to run this program")
	exit(1)

import os
from utils.PcapParserHelper import PcapParserHelper
from utils.RNN import RNN
from utils.KNN import KNN
import pcapy as p
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re
import json
import sys
import csv

device_identifiers = []
CONVERSATION_THRESHOLD = 5

def getConversationAttributesForFlow(flow_file_name, device_dir_path):
	# Get the contents of the flow file
	flow_file_path = os.path.join(device_dir_path, flow_file_name)
	flow_file = open(flow_file_path, "r")
	start_reading_packets = False
	packets = []
	flow_src_ip = ""
	flow_file_json = json.loads(flow_file.read())

	
	for packet in flow_file_json['packets']:
		# Sort the packets based on timestamp
		num_packets = len(packets)
		if num_packets > 0:
			for packet_index in range(num_packets):
				current_packet = packets[packet_index]

				if packet == {}:
					print("WARNING: The new packet is empty for some reason")
					continue

				if current_packet == {}:
					print("WARNING: The current packet is empty for some reason")
					continue

				# Determine if the current packet time is greater than the time of the packet being placed
				if spot_found == False and packet["Packet_Timestamp"] < current_packet["Packet_Timestamp"]:
					after_packets = packets[packet_index:num_packets]
					packets[packet_index] = packet
					packets[packet_index + 1: num_packets + 1] = after_packets
					spot_found = True

			# Add the packet to the end
			if spot_found == False:
				packets.append(packet)
		else:
			packets.append(packet)

	# Pull out the conversations from the flow packets
	conversation_attributes = []
	conversations = {
		"TCP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"UDP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"DNS": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"IP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"ICMP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"ARP": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		},
		"Ethernet": {
			"num_packets": 0,
			"num_packets_total": 0,
			"total_packet_length": 0,
			"num_packets_sent": 0,
			"num_packets_received": 0,
			"time_between_conv": 0,
			"num_packets_sent_to_in_network_devices": 0,
			"num_packets_sent_to_out_network_devices": 0,
			"last_packet_timestamp": -1,
		}
	}

	for packet in packets:
		ptype = packet["Packet_Type"]
		ptime = packet["Packet_Timestamp"]
		if float(conversations[ptype]["last_packet_timestamp"]) + float(CONVERSATION_THRESHOLD) >= float(ptime):
			conv = conversations[ptype]
			conv_stats = []
	
			# Add attribute for number of TCP packets
			if "TCP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)
	
			# Add attribute for number of UDP packets
			if "UDP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of DNS packets
			if "DNS" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of IP packets
			if "IP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of ICMP packets
			if "ICMP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of ARP packets
			if "ARP" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add attribute for number of Ethernet packets
			if "Ethernet" == ptype:
				conv_stats.append(conv["num_packets"])
			else:
				conv_stats.append(0)

			# Add the average packet length
			conv_stats.append(float(conv["total_packet_length"]) / float(conv["num_packets_total"]))
			# Add number of packets sent
			conv_stats.append(conv["num_packets_sent"])

			# Add the number of packets received
			conv_stats.append(conv["num_packets_received"])

			# Add the number of packets sent to devices inside the network
			conv_stats.append(conv["num_packets_sent_to_in_network_devices"])

			# Add the number of packets sent to devices outside the network
			conv_stats.append(conv["num_packets_sent_to_out_network_devices"])

			# Add the information from the current conversation to the list of information about the conversations for this flow
			conversation_attributes.append(conv_stats)
			
			# Reset everything
			conv_stats = []

			# Reset the conversation information for the stats of the new packet
			conv["num_packets"] = 1
			conv["total_packet_length"] = packet["Packet_Length"]
			conv["num_packets_total"] = 1
			conv["num_packets_sent"] = 0
			conv["num_packets_received"] = 0
			conv["num_packets_sent_to_in_network_devices"] = 0
			conv["num_packets_sent_to_out_network_devices"] = 0

			# Check if the packet is being sent or received
			if packet["IP_Source_Address"] == flow_src_ip:
				conv["num_packets_sent"] += 1
			else:
				conv["num_packets_received"] += 1
		
			# Check if the packet is being sent to a device inside or outside the network
			network_ip_found = False
			dest_ip = packet["IP_Destination_Address"]
			for label_row in ip_labels:
				if label_row["IP"] == dest_ip:
					network_ip_found = True
					conv["num_packets_sent_to_in_network_devices"] += 1

			if network_ip_found == False:
				conv["num_packets_sent_to_out_network_devices"] += 1
		else:
			conv = conversations[ptype]

			conv["last_packet_timestamp"] = packet["Packet_Timestamp"]
			
			# Update the number of packets
			conv["num_packets"] += 1
			conv["num_packets_total"] += 1

			# Update total packet length
			conv["total_packet_length"] = float(conv["total_packet_length"]) + float(packet["Packet_Length"])

			# Check if the packet is being sent or received
			if packet["IP_Source_Address"] == flow_src_ip:
				conv["num_packets_sent"] += 1
			else:
				conv["num_packets_received"] += 1

			# Check if the packet is being sent to a device inside or outside the network
			network_ip_found = False
			dest_ip = packet["IP_Destination_Address"]
			for label_row in ip_labels:
				if label_row["IP"] == dest_ip:
					network_ip_found = True
					conv["num_packets_sent_to_in_network_devices"] += 1

			if network_ip_found == False:
				conv["num_packets_sent_to_out_network_devices"] += 1

	return conversation_attributes

def main():
	# Check the number of arguments
	if len(sys.argv) != 3:
		print('ERROR: Incorrect number of arguments provided')
		print('python3 DeviceDetector.py <experiment_directory> <display graph>')
		exit(-1)

	# Get the experiment directory
	experiment_dir = sys.argv[1]
	experiment_parent_dir =  ''
	if ((experiment_dir[0] != '/') or (experiment_dir[0] != '~')):
		experiment_parent_dir = os.getcwd()
	else:
		experiment_parent_dir = ''
	experiment_dir = os.path.join(experiment_parent_dir, experiment_dir)

	if not os.path.isdir(experiment_dir):
		print('ERROR: The experiment directory provided does not exist')
		exit(-1)

	displayGraph = False
	if sys.argv[2].lower() == "true" or sys.argv[2].lower == "t":
		displayGraph = True

	devices_identifiers = []
	CONVERSATION_THRESHOLD = 5
	create_flows_state = False

	# Check if the content JSON files have already been created
	flow_json_dir = os.path.join(experiment_dir, 'flow_json')
	if not os.path.isdir(flow_json_dir):
		print('ERROR: You need to process the flow files first')

	training_json_dir = os.path.join(experiment_dir, "training_json")
	eval_json_dir = os.path.join(experiment_dir, "eval_json")
	if not os.path.exists(training_json_dir) or not os.path.exists(eval_json_dir):
		print("ERROR: You need to create training and eval directories and put your flow json files in them before you can continue.")
		sys.exit(-1)

	# Read in the set of labels
	ip_labels = []
	unique_labels = []
	labels_path = os.path.join(experiment_dir, 'device_labels.csv')

	line_count = 0
	labels_file = csv.reader(open(labels_path, newline='\r'), delimiter=',', quotechar='|')
	for row in labels_file:
		if line_count > 0 and len(row) > 0:
			# Add the current entry to the list of IP labels
			ip_labels.append({
				"IP": row[0],
				"Label": row[1],
			})

			# Add the device label to the list of unique labels if it isn't already present
			if row[1] not in unique_labels:
				unique_labels.append(row[1])
		line_count += 1

	print("Processing the training data")

	# Load in all the flow information for the devices in the training set
	training_data = []
	training_labels = []
	for device_dir in os.listdir(training_json_dir):
		print("Processing the " + device_dir + " device in the training data")
		conversation_attributes = []
		conversation_labels = []

		device_dir_path = os.path.join(training_json_dir, device_dir)
		if os.path.isdir(device_dir_path):
			# Get the conversation for the flow
			for flow_file_name in os.listdir(device_dir_path):
				print("Processing the " + flow_file_name + " flow in the training data")
				# Get the label for the device based on the source IP on the file
				src_ip = ""
				flowRe = list(re.finditer(r"(?P<src_ip>\d*.\d*.\d*.\d*)-(?P<dst_ip>\d*.\d*.\d*.\d*).json", flow_file_name))
				if len(flowRe) > 0:
					flowElems = flowRe[0].groupdict()
					src_ip = flowElems["src_ip"]
		
				label = "Unknown"
				for iplabel in ip_labels:
					if iplabel["IP"] == src_ip:
						label = iplabel["Label"] 

				ca = getConversationAttributesForFlow(flow_file_name, device_dir_path)
				num_conv_attributes = len(conversation_attributes)
				num_ca = len(ca)
				conversation_attributes += ca
				conversation_labels += [label] * num_ca
		training_data += conversation_attributes
		training_labels += conversation_labels

	print("Processing the evaluation data")

	# Creates a dictionary of labels containing each label to evaluate the knn algorithms accuracy
	all_labels = {}
	actual_labels = {}

	for label in unique_labels:
		actual_labels[label] = 0
	for label_list in unique_labels:
		all_labels[label_list] = actual_labels.copy()

	# Load in the flow information for the devices in the eval set
	for device_dir in os.listdir(eval_json_dir):
		print("Processing the " + device_dir + " device in the training data")
		conversation_attributes = []
		conversation_labels = []
		label = "Unknown"

		device_dir_path = os.path.join(eval_json_dir, device_dir)
		if os.path.isdir(device_dir_path):
			# Get the conversation for the flow
			for flow_file_name in os.listdir(device_dir_path):
				print("Processing the " + flow_file_name + " flow in the training data")
				# Get the label for the device based on the source IP on the file
				src_ip = ""
				flowRe = list(re.finditer(r"(?P<src_ip>\d*.\d*.\d*.\d*)-(?P<dst_ip>\d*.\d*.\d*.\d*).json", flow_file_name))
				if len(flowRe) > 0:
					flowElems = flowRe[0].groupdict()
					src_ip = flowElems["src_ip"]

				for iplabel in ip_labels:
					if iplabel["IP"] == src_ip:
						label = iplabel["Label"]

				ca = getConversationAttributesForFlow(flow_file_name, device_dir_path)
				#print(ca)
				num_conv_attributes = len(conversation_attributes)
				num_ca = len(ca)
				conversation_attributes += ca
				conversation_labels += [label] * num_ca

		print("Starting to run RNN for device " + device_dir)
		# Run the RNN analysis per evaluation device
		r = RNN()
		canLabel = r.runRNN(training_data, training_labels, conversation_attributes, experiment_dir)
		if not canLabel:
			print("Device " + device_dir + " needs a new label")

		print("Starting to run KNN for device " + device_dir)
		# Run the KNN analysis per evaluation device
		k = KNN()
		knn_label = k.runKNN(training_data, training_labels, conversation_attributes, conversation_labels, unique_labels, experiment_dir, displayGraph)

		# Adds accuracy of device to all_labels dictionary
		all_labels[knn_label][label] += 1

		device_report_dir = os.path.join(experiment_dir, 'device_report')
		if not os.path.exists(device_report_dir):
			os.makedirs(device_report_dir)

		for device in unique_labels:
			TP_numerator = 0
			FN_numerator = 0
			TPandFN_denominator = 0
			FP_numerator = 0
			TN_numerator = 0
			FPandTN_denominator = 0

			for kLabel in all_labels:
				for uLabel in all_labels[kLabel]:
					if uLabel == device and kLabel == device:
						TP_numerator += all_labels[kLabel][uLabel]
						TPandFN_denominator += all_labels[kLabel][uLabel]
					elif uLabel != device and kLabel == device:
						FP_numerator += all_labels[kLabel][uLabel]
						FPandTN_denominator += all_labels[kLabel][uLabel]
					elif uLabel == device and kLabel != device:
						FN_numerator += all_labels[kLabel][uLabel]
						TPandFN_denominator += all_labels[kLabel][uLabel]
					elif uLabel != device and kLabel != device:
						TN_numerator += all_labels[kLabel][uLabel]
						FPandTN_denominator += all_labels[kLabel][uLabel]
			
			device_report = {}
			device_report['True Positive Rate'] = str(TP_numerator) + ' / ' + str(TPandFN_denominator)
			device_report['False Negative Rate'] = str(FN_numerator) + ' / ' + str(TPandFN_denominator)
			device_report['False Positive Rate'] = str(FP_numerator) + ' / ' + str(FPandTN_denominator)
			device_report['True Negative Rate'] = str(TN_numerator) + ' / ' + str(FPandTN_denominator)

			device_path_name = device + '_report.json'
			device_report_path = os.path.join(device_report_dir, device_path_name)
			with open(device_report_path, 'w') as outfile:
				json.dump(device_report, outfile)

	print('Finished processing all files')
			
main()
