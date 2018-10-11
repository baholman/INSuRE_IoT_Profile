import os
import pcapy as p
from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, Raw
import re

"""
WlanPcapFileParser

Convert pcap file to json from WLAN
"""
class WlanPcapFileParser:
	
	"""
	getJson

	Converts directory of PCAP files to dictionary of strings with packet contents.

	Params: 
	pcap_dir - String that is path to PCAP directory

	Return: An array of dictionaries that contain file content
	"""
	def getJson(self, pcap_dir):
		result = []
		
		for file_name in os.listdir(pcap_dir):
			# Initalize file dictionary
			file_dict = {}
			file_dict['file_path'] = file_name
			file_dict['protocol'] = 'WLAN'
			file_dict['identifiers'] = ['source_ip']
			file_dict['packets'] = []

			# Get file contents
			pcap_text = self.__parseBinary(file_name, pcap_dir)
			#print(pcap_text)

			# Get packet info
			for packet in self.__getPackets(pcap_text):
				packet_dict = {}
				#packet_dict['header'] = self.__getHeader(packet)
				#packet_dict['body'] = self.__getBody(packet)
				file_dict['packets'].append(packet_dict)

			result.append(file_dict)

		return result


	"""
	parseBinary

	Parses binary to text.

	Params: 
	input_filename - file name of the input file

	Return: string of the PCAP file
	"""
	def __parseBinary(self, input_filename, pcap_dir):
		pcap_string = ''
		input_filename_base = os.path.splitext(os.path.basename(input_filename))[0]
		print('Input File Name: ' + input_filename_base)

		# Set the parent directory of the PCAP file to the current directory if the full path is not specified
		if ((pcap_dir[0] != '/') or (pcap_dir[0] != '~')):
			pcap_parent_dir = os.getcwd()
		else:
			pcap_parent_dir = ''
		# Set up the input file path
		pcap_path = os.path.join(pcap_parent_dir, pcap_dir, input_filename_base + '.pcap')

		packets = rdpcap(pcap_path)
		#print(packets.summary())
		for packet in packets:
			# Get the ethernet informatin from the packet
			if packet.haslayer(Ether):
				print('Ethernet Source MAC Field: ' + str(packet[Ether].src))
				print('Ethernet Destination MAC Field: ' + str(packet[Ether].dst))
				print('Ethernet X Short Type: ' + str(packet[Ether].type))
			# Get the IP information from the packet
			if packet.haslayer(IP):
				print('IP Source: ' + str(packet[IP].src))
				print('IP Destination: ' + str(packet[IP].dst))
				print('IP Fragment Offset: ' + str(packet[IP].frag))
				print('IP Protocol: ' + str(packet[IP].proto))
				print('IP Type Of Service (aka DSCP): ' + str(packet[IP].tos))
				print('IP Header Checksum: ' + str(packet[IP].chksum))
				print('IP Total Length: ' + str(packet[IP].len))
				print('IP Options: ' + str(packet[IP].options))
				print('IP Version: ' + str(packet[IP].version))
				print('IP Flags: ' + str(packet[IP].flags))
				print('IP Internet Header Length: ' + str(packet[IP].ihl))
				print('IP Time to Live: ' + str(packet[IP].ttl))
				print('IP Identification: ' + str(packet[IP].id))
			# Get the TCP information from the packet
			if packet.haslayer(TCP):
				print('TCP Source Port: ' + str(packet[TCP].sport))
				print('TCP Destination Port: ' + str(packet[TCP].dport))
				print('TCP Sequence Number: ' + str(packet[TCP].seq))
				print('TCP Acknowledge Number: ' + str(packet[TCP].ack))
				print('TCP Data Offset: ' + str(packet[TCP].dataofs))
				print('TCP Reserved Data: ' + str(packet[TCP].reserved))
				print('TCP Control Flags: ' + str(packet[TCP].flags))
				print('TCP Window Size: ' + str(packet[TCP].window))
				print('TCP Checksum: ' + str(packet[TCP].chksum))
				print('TCP Urgent Pointer: ' + str(packet[TCP].urgptr))
				print('TCP Options: ' + str(packet[TCP].options))
			# Get the UDP information from the packet
			if packet.haslayer(UDP):
				print('UDP Source Port: ' + str(packet[UDP].sport))
				print('UDP Destination Port: ' + str(packet[UDP].dport))
				print('UDP Length: ' + str(packet[UDP].len))
				print('UDP Checksum: ' + str(packet[UDP].chksum))
			# Get the IP information from the packet
			if packet.haslayer(ICMP):
				print('ICMP Gate Way: ' + str(packet[ICMP].gw))
				print('ICMP Code: ' + str(packet[ICMP].code))
				print('ICMP Originate Timestamp: ' + str(packet[ICMP].ts_ori))
				print('ICMP Address Mask: ' + str(packet[ICMP].addr_mask))
				print('ICMP Sequence: ' + str(packet[ICMP].seq))
				print('ICMP Pointer: ' + str(packet[ICMP].ptr))
				print('ICMP Unused: ' + str(packet[ICMP].unused))
				print('ICMP Receive Timestamp: ' + str(packet[ICMP].ts_rx))
				print('ICMP Checksum: ' + str(packet[ICMP].chksum))
				print('ICMP Reserved: ' + str(packet[ICMP].reserved))
				print('ICMP Transmit Timestamp: ' + str(packet[ICMP].ts_tx))
				print('ICMP Type: ' + str(packet[ICMP].type))
				print('ICMP Identifier: ' + str(packet[ICMP].id))
			# Get the body from the packet
			if packet.haslayer(Raw):
				print("Raw:")
				print(packet[Raw].load)
		#return ''.join(packets)
		return ''


	"""
	getPackets

	Gets a list of the strings from the various packets in the PCAP file.

	Params: 
	pcap_string - string of the PCAP file
i
	Return: array of the string contents of a packet
	"""
	def __getPackets(self, pcap_string):
		"""result = []
		packets = re.search(r'\(?<= ("packets"): \){(.*?)}}}', pcap_string)
		#for packet in re.findallr'(\?<= (\"packets\"): )\[\{(.*?)\}\}\}', pcap_string):
		#	 result.append(packet)
		return re.findall(r'\{(.*?)\}', packets)"""
		return []


	"""
	getHeader

	Gets a dictionary of strings from the fields in the packet header.

	Params: 
	packet_string - A string of a packets contents

	Return: Dictionary of header fields
	"""
	def __getHeader(self, packet_string):
		result = {}
		"""header_string = re.search(r'(\?<= (\"header\"): )(.*?)\}\])', packet_string)
		for key_value in re.findall(r'(\"(.*?)\":\s\"(.*?)\")', header_string):
			key = re.search(r'(\?<= : ).*', key_value)
			value = re.search(r'.*(\?= : )', key_value)
			result[key] = value"""
		return result
		#return {}


	"""
	getBody

	Gets a dictionary of strings from the content in the packet body.

	Params: 
	packet_string - A string of a packets contents

	Return: Dictionary of body contents
	"""
	def __getBody(self, packet_string):
		result = {}
		"""body_string = re.search(r'(\?<= (\"body\"): )(.*?)\}\])', packet_string)
		for key_value in re.findall(r'(\"(.*?)\":\s\"(.*?)\")', body_string):
			key = re.search(r'(\?<= : ).*', key_value)
			value = re.search(r'.*(\?= : )', key_value)
			result[key] = value"""
		return result
		#return {}
	
