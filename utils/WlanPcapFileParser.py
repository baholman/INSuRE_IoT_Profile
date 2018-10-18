import os
import pcapy as p
from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, DNS, Raw
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
			file_dict['identifiers'] = ['Ethernet_Source_MAC_Field']
			file_dict['packets'] = []

			# Get file contents
			packets = self.__parseBinary(file_name, pcap_dir)

			# Get packet info
			for packet in packets:
				packet_dict = {}
				packet_dict['header'] = self.__getHeader(packet)
				packet_dict['body'] = self.__getBody(packet)
				file_dict['packets'].append(packet_dict)

			result.append(file_dict)

		return result


	"""
	parseBinary

	Parses binary to text.

	Params: 
	input_filename - file name of the input file

	Return: An array of packet objects
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

		return rdpcap(pcap_path)

	"""
	getHeader

	Gets a dictionary of strings from the fields in the packet header.

	Params: 
	packet - A packet object

	Return: Dictionary of header fields
	"""
	def __getHeader(self, packet):
		result = {}
		# Get the ethernet information from the packet
		if packet.haslayer(Ether):
			result['Ethernet_Source_MAC_Field'] = str(packet[Ether].src)
			result['Ethernet_Destination_MAC_Field'] = str(packet[Ether].dst)
			result['Ethernet_Type_Num'] = str(packet[Ether].type)
			result['Ethernet_Type_Protocol'] = self.__getEthernetTypeString(packet[Ether].type)
		# Get the IP information from the packet
		if packet.haslayer(IP):
			result['IP_Source'] = str(packet[IP].src)
			result['IP_Destination'] = str(packet[IP].dst)
			result['IP_Fragment_Offset'] = str(packet[IP].frag)
			result['IP_Protocol'] = str(packet[IP].proto)
			result['IP_Type_Of_Service_(aka_DSCP)'] = str(packet[IP].tos)
			result['IP_Header_Checksum'] = str(packet[IP].chksum)
			result['IP_Total_Length'] = str(packet[IP].len)
			result['IP_Options'] = str(packet[IP].options)
			result['IP_Version'] = str(packet[IP].version)
			result['IP_Flags'] = str(packet[IP].flags)
			result['IP_Internet_Header_Length'] = str(packet[IP].ihl)
			result['IP_Time_to_Live'] = str(packet[IP].ttl)
			result['IP_Identification'] = str(packet[IP].id)
		# Get the TCP information from the packet
		if packet.haslayer(TCP):
			result['TCP_Source_Port'] =  str(packet[TCP].sport)
			result['TCP_Destination_Port'] = str(packet[TCP].dport)
			result['TCP_Sequence_Number'] = str(packet[TCP].seq)
			result['TCP_Acknowledge_Number'] = str(packet[TCP].ack)
			result['TCP_Data_Offset'] = str(packet[TCP].dataofs)
			result['TCP_Reserved_Data'] = str(packet[TCP].reserved)
			result['TCP_Control_Flags'] = str(packet[TCP].flags)
			result['TCP_Window_Size'] = str(packet[TCP].window)
			result['TCP_Checksum'] = str(packet[TCP].chksum)
			result['TCP_Urgent_Pointer'] = str(packet[TCP].urgptr)
			result['TCP_Options'] = str(packet[TCP].options)
		# Get the UDP information from the packet
		if packet.haslayer(UDP):
			result['UDP_Source_Port'] = str(packet[UDP].sport)
			result['UDP_Destination_Port'] = str(packet[UDP].dport)
			result['UDP_Length'] = str(packet[UDP].len)
			result['UDP_Checksum'] = str(packet[UDP].chksum)
		# Get the IP information from the packet
		if packet.haslayer(ICMP):
			result['ICMP_Gate_Way'] = str(packet[ICMP].gw)
			result['ICMP_Code'] = str(packet[ICMP].code)
			result['ICMP_Originate_Timestamp'] = str(packet[ICMP].ts_ori)
			result['ICMP_Address_Mask'] = str(packet[ICMP].addr_mask)
			result['ICMP_Sequence'] = str(packet[ICMP].seq)
			result['ICMP_Pointer'] = str(packet[ICMP].ptr)
			result['ICMP_Unused'] = str(packet[ICMP].unused)
			result['ICMP_Receive_Timestamp'] = str(packet[ICMP].ts_rx)
			result['ICMP_Checksum'] = str(packet[ICMP].chksum)
			result['ICMP_Reserved'] = str(packet[ICMP].reserved)
			result['ICMP_Transmit_Timestamp'] = str(packet[ICMP].ts_tx)
			result['ICMP_Type'] = str(packet[ICMP].type)
			result['ICMP_Identifier'] = str(packet[ICMP].id)
		if packet.haslayer(DNS):
			result['DNS_Identifier'] = str(packet[DNS].id)
			result['DNS_Query_Or_Response'] = str(packet[DNS].qr)
			result['DNS_Op_Code'] = str(packet[DNS].opcode)
			result['DNS_Authoritative_Answer'] = str(packet[DNS].aa)
			result['DNS_TrunCation'] = str(packet[DNS].tc)
			result['DNS_Recursion_Desired'] = str(packet[DNS].rd)
			result['DNS_Recursion_Available'] = str(packet[DNS].ra)
			result['DNS_Z_Reserved'] = str(packet[DNS].z)
			result['DNS_Response_Code'] = str(packet[DNS].rcode)
			result['DNS_Question_Count'] = str(packet[DNS].qdcount) # Number of entries in the question section
			result['DNS_Ancount'] = str(packet[DNS].ancount) # Number of resource records in the answer section
			result['DNS_Nscount'] = str(packet[DNS].nscount) # Number of name service resource records in the authority record section
			result['DNS_Arcount'] = str(packet[DNS].arcount) # Number of resource records in the additional record section 
			result['DNS_Query_Data'] = str(packet[DNS].qd)

		return result

	"""
	getBody

	Gets a dictionary of strings from the content in the packet body.

	Params: 
	packet - A packet object

	Return: Dictionary of body contents
	"""
	def __getBody(self, packet):
		result = {}
		
		if packet.haslayer(Raw):
			result['body'] = str(packet[Raw].load)
		
		return result

	"""
	get Ethernet Type String

	Gets the protocol of the eternet type. It recieves an int baesed on the ethernet type, then it compares it to a hex value. The conversion
	compares a int value to a hex and pulls out the value at the key location in a dictionary. Otherwise, it returns 'Undifined.'
	Note - The comparison between packetNumber and the key values (hex) is a direct comparison with no conversions to the same data type.

	Params:
	packetNumber - the packet[Ether].type which is a number based on the ethernet type. Thi value is an int.
	
	Return: A string of the ethernet type based on its type number
	"""
	def __getEthernetTypeString(self, packetNumber):
		switch = {
			0x0800 : 'Internet Protocol version 4 (IPv4)',
			0x0806 : 'Address Resolution Protocol (ARP)',
			0x0842 : 'Wake-on-LAN[9]',
			0x22F3 : 'IETF TRILL Protocol',
			0x22EA : 'Stream Reservation Protocol',
			0x6003 : 'DECnet Phase IV',
			0x8035 : 'Reverse Address Resolution Protocol',
			0x809B : 'AppleTalk (Ethertalk)',
			0x80F3 : 'AppleTalk Address Resolution Protocol (AARP)',
			0x8100 : 'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]',
			0x8137 : 'IPX',
			0x8204 : 'QNX Qnet',
			0x86DD : 'Internet Protocol Version 6 (IPv6)',
			0x8808 : 'Ethernet flow control',
			0x8809 : 'Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol',
			0x8819 : 'CobraNet',
			0x8847 : 'MPLS unicast',
			0x8848 : 'MPLS multicast',
			0x8863 : 'PPPoE Discovery Stage',
			0x8864 : 'PPPoE Session Stage',
			0x886D : 'Intel Advanced Networking Services [12]',
			0x8870 : 'Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)',
			0x887B : 'HomePlug 1.0 MME',
			0x888E : 'EAP over LAN (IEEE 802.1X)',
			0x8892 : 'PROFINET Protocol',
			0x889A : 'HyperSCSI (SCSI over Ethernet)',
			0x88A2 : 'ATA over Ethernet',
			0x88A4 : 'EtherCAT Protocol',
			0x88A8 : 'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[10]',
			0x88AB : 'Ethernet Powerlink[citation needed]',
			0x88B8 : 'GOOSE (Generic Object Oriented Substation event)',
			0x88B9 : 'GSE (Generic Substation Events) Management Services',
			0x88BA : 'SV (Sampled Value Transmission)',
			0x88CC : 'Link Layer Discovery Protocol (LLDP)',
			0x88CD : 'SERCOS III',
			0x88DC : 'WSMP, WAVE Short Message Protocol',
			0x88E1 : 'HomePlug AV MME[citation needed]',
			0x88E3 : 'Media Redundancy Protocol (IEC62439-2)',
			0x88E5 : 'MAC security (IEEE 802.1AE)',
			0x88E7 : 'Provider Backbone Bridges (PBB) (IEEE 802.1ah)',
			0x88F7 : 'Precision Time Protocol (PTP) over Ethernet (IEEE 1588)',
			0x88F8 : 'NC-SI',
			0x88FB : 'Parallel Redundancy Protocol (PRP)',
			0x8902 : 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
			0x8906 : 'Fibre Channel over Ethernet (FCoE)',
			0x8914 : 'FCoE Initialization Protocol',
			0x8915 : 'RDMA over Converged Ethernet (RoCE)',
			0x891D : 'TTEthernet Protocol Control Frame (TTE)',
			0x892F : 'High-availability Seamless Redundancy (HSR)',
			0x9000 : 'Ethernet Configuration Testing Protocol[13]',
			0x9100 : 'VLAN-tagged (IEEE 802.1Q) frame with double tagging'
		}
		
		if packetNumber not in switch.keys():
			return 'Undefined'
		return switch[packetNumber]

