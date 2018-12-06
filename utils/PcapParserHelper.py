import os
import socket
import pcapy as p
from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import re

class PcapParserHelper:
	
	"""
	getHeader

	Gets a dictionary of strings from the fields in the packet header.

	Params: 
	packet - A packet object

	Return: Dictionary of header fields
	"""
	def getHeader(self, packet, path, verbose):
		device_file = open(path, "a")

		# Get the timestamp that the packet was sent at
		device_file.write("			Packet_Timestamp: '" + str(packet.time) + "',\n")
		
		# Get the type of packet
		#print(self.__getTypeOfPacket(packet))
		protocol = self.__getTypeOfPacket(packet)
		device_file.write("			Packet_Type: '" + str(protocol) + "',\n")

		# Get packet length
		if packet.haslayer(IP):
			device_file.write("			Packet_Length: '" + str(packet[IP].len) + "',\n")
		elif packet.haslayer(ARP):
			device_file.write("			Packet_Length: '28',\n")
		else:
			device_file.write("			Packet_Length: 'Unknown',\n")

		# Get the ethernet information from the packet
		if packet.haslayer(Ether):
			device_file.write("			Ethernet_Source_MAC: '" + str(packet[Ether].src) +  "',\n")
			device_file.write("			Ethernet_Destination_MAC: '" + str(packet[Ether].dst) +  "',\n")

			if verbose:
				device_file.write("			Ethernet_Type_Num: '" + str(packet[Ether].type) +  "',\n")
				device_file.write("			Ethernet_Type_Protocol: '" + self.__getEthernetTypeString(packet[Ether].type) +  "',\n")	
		#Get thr ARP information from the packet
		if packet.haslayer(ARP):
			if verbose:
				device_file.write("			ARP_Hardware_Type: '" + str(packet[ARP].hwtype) + "',\n")
				device_file.write("			ARP_Protocol_Type: '" + str(packet[ARP].ptype) + "',\n")
				device_file.write("			ARP_Hardware_Length: '" + str(packet[ARP].hwlen) + "',\n")
				device_file.write("			ARP_Protocol_Length: '" + str(packet[ARP].plen) + "',\n")
				device_file.write("			ARP_Sender_Hardware_Address: '" + str(packet[ARP].hwsrc) + "',\n")
				device_file.write("			ARP_Sender_Protocol_Address: '" + str(packet[ARP].psrc) + "',\n")
				device_file.write("			ARP_Target_Hardware_Address: '" + str(packet[ARP].hwdst) + "',\n")
				device_file.write("			ARP_Target_Protocol_Address: '" + str(packet[ARP].pdst) + "',\n")
				device_file.write("			ARP_OP_Code: '" + str(packet[ARP].op) + "',\n")
		# Get the IP information from the packet
		if packet.haslayer(IP):
			device_file.write("			IP_Source_Address: '" + str(packet[IP].src) + "',\n")
			device_file.write("			IP_Destination_Address: '" + str(packet[IP].dst) + "',\n")
			device_file.write("			IP_Source_Version: '" + str(packet[IP].version) + "',\n")

			if verbose:
				device_file.write("			IP_Destination_Domain: '" + self.__getDomainName(packet[IP].dst) + "',\n")
				device_file.write("			IP_Fragment_Offset: '" + str(packet[IP].frag) + "',\n")
				device_file.write("			IP_Protocol_Num: '" + str(packet[IP].proto) + "',\n")
				device_file.write("			IP_Protocol_String: '" + self.__getIPProtocolString(packet[IP].proto) + "',\n")
				device_file.write("			IP_Type_Of_Service_(aka_DSCP): '" + str(packet[IP].tos) + "',\n")
				device_file.write("			IP_Header_Checksum: '" + str(packet[IP].chksum) + "',\n")
				device_file.write("			IP_Total_Length: '" + str(packet[IP].len) + "',\n")
				device_file.write("			IP_Source_Options: '" + str(packet[IP].options) + "',\n")
				device_file.write("			IP_Source_Flags: '" + str(packet[IP].flags) + "',\n")
				device_file.write("			IP_Source_Internet_Header_Length: '" + str(packet[IP].ihl) + "',\n")
				device_file.write("			IP_Source_Time_to_Live: '" + str(packet[IP].ttl) + "',\n")
				device_file.write("			IP_Identification: '" + str(packet[IP].id) + "',\n")
		# Get the TCP information from the packet
		if packet.haslayer(TCP):
			device_file.write("			TCP_Source_Port: '" + str(packet[TCP].sport) + "',\n")
			device_file.write("			TCP_Destination_Port: '" + str(packet[TCP].dport) + "',\n")
			device_file.write("			TCP_Sequence_Number: '" + str(packet[TCP].seq) + "',\n")
			device_file.write("			TCP_Acknowledge_Number: '" + str(packet[TCP].ack) + "',\n")

			if verbose:
				device_file.write("			TCP_Data_Offset: '" + str(packet[TCP].dataofs) + "',\n")
				device_file.write("			TCP_Reserved_Data: '" + str(packet[TCP].reserved) + "',\n")
				device_file.write("			TCP_Control_Flags: '" + str(packet[TCP].flags) + "',\n")
				device_file.write("			TCP_Window_Size: '" + str(packet[TCP].window) + "',\n")
				device_file.write("			TCP_Checksum: '" + str(packet[TCP].chksum) + "',\n")
				device_file.write("			TCP_Urgent_Pointer: '" + str(packet[TCP].urgptr) + "',\n")
				device_file.write("			TCP_Options: '" + str(packet[TCP].options) + "',\n")
		# Get the UDP information from the packet
		if packet.haslayer(UDP):
			device_file.write("			UDP_Source_Port: '" + str(packet[UDP].sport) + "',\n")
			device_file.write("			UDP_Destination_Port: '" + str(packet[UDP].dport) + "',\n")

			if verbose:
				device_file.write("			UDP_Length: '" + str(packet[UDP].len) + "',\n")
				device_file.write("			UDP_Checksum: '" + str(packet[UDP].chksum) + "',\n")
		# Get the ICMP information from the packet
		if packet.haslayer(ICMP):
			if verbose:
				device_file.write("			ICMP_Gateway_IP_Address: '" + str(packet[ICMP].gw) + "',\n")
				device_file.write("			ICMP_Gateway_Domain: '" + self.__getDomainName(packet[ICMP].gw) + "',\n")
				device_file.write("			ICMP_Code: '" + str(packet[ICMP].code) + "',\n")
				device_file.write("			ICMP_Originate_Timestamp: '" + str(packet[ICMP].ts_ori) + "',\n")
				device_file.write("			ICMP_Address_Mask: '" + str(packet[ICMP].addr_mask) + "',\n")
				device_file.write("			ICMP_Sequence: '" + str(packet[ICMP].seq) + "',\n")
				device_file.write("			ICMP_Pointer: '" + str(packet[ICMP].ptr) + "',\n")
				device_file.write("			ICMP_Unused: '" + str(packet[ICMP].unused) + "',\n")
				device_file.write("			ICMP_Receive_Timestamp: '" + str(packet[ICMP].ts_rx) + "',\n")
				device_file.write("			ICMP_Checksum: '" + str(packet[ICMP].chksum) + "',\n")
				device_file.write("			ICMP_Reserved: '" + str(packet[ICMP].reserved) + "',\n")
				device_file.write("			ICMP_Transmit_Timestamp: '" + str(packet[ICMP].ts_tx) + "',\n")
				device_file.write("			ICMP_Type: '" + str(packet[ICMP].type) + "',\n")
				device_file.write("			ICMP_Identifier: '" + str(packet[ICMP].id) + "',\n")
		# Get the DNS information from the packet
		if packet.haslayer(DNS):
			device_file.write("			DNS_Identifier: '" + str(packet[DNS].id) + "',\n")
			device_file.write("			DNS_Query_Or_Response: '" + str(packet[DNS].qr) + "',\n")
			device_file.write("			DNS_Response_Code: '" + str(packet[DNS].rcode) + "',\n")

			if verbose:
				device_file.write("			DNS_Op_Code: '" + str(packet[DNS].opcode) + "',\n")
				device_file.write("			DNS_Authoritative_Answer: '" + str(packet[DNS].aa) + "',\n")
				device_file.write("			DNS_TrunCation: '" + str(packet[DNS].tc) + "',\n")
				device_file.write("			DNS_Recursion_Desired: '" + str(packet[DNS].rd) + "',\n")
				device_file.write("			DNS_Recursion_Available: '" + str(packet[DNS].ra) + "',\n")
				device_file.write("			DNS_Z_Reserved: '" + str(packet[DNS].z) + "',\n")
				device_file.write("			DNS_Question_Count: '" + str(packet[DNS].qdcount) + "',\n") # Number of entries in the question section
				device_file.write("			DNS_Ancount: '" + str(packet[DNS].ancount) + "',\n") # Number of resource records in the answer section
				device_file.write("			DNS_Nscount: '" + str(packet[DNS].nscount) + "',\n") # Number of name service resource records in the authority record section
				device_file.write("			DNS_Arcount: '" + str(packet[DNS].arcount) + "',\n") # Number of resource records in the additional record section
				device_file.write("			DNS_Query_Data: '" + str(packet[DNS].qd) + "',\n")

		device_file.close()


	"""
	getTypeOfPacket

	Gets the type of packet.

	Params: 
	packet - A packet object
	result - A dictionary of the current packet info

	Return: Dictionary of Ethernet header fields
	"""
	def __getTypeOfPacket(self, packet):
		ptype = 'Unknown'

		# Update the type if an ethernet header exists (Data-Link layer)
		if packet.haslayer(Ether):
			ptype = 'Ethernet'

		# Update the type if an ARP header exists (Data-Link layer)
		if packet.haslayer(ARP):
			ptype = 'ARP'

		# Update the type if an IP header exists (Network layer)
		if packet.haslayer(IP):
			ptype = 'IP'

		# Update the type if an ICMP header exists (Network layer)
		if packet.haslayer(ICMP):
			ptype = 'ICMP'

		# Update the type if a TCP header exists (Transport layer)
		if packet.haslayer(TCP):
			ptype = 'TCP'

		# Update the type if a UDP header exists (Transport layer)
		if packet.haslayer(UDP):
			ptype = 'UDP'

		# Update the type if an DNS header exists (Transport layer)
		if packet.haslayer(DNS):
			ptype = 'DNS'

		return ptype

	"""
	getDomainName

	Get the domain name for an IP address if it is available using a reverse DNS lookup.

	Params:
	ip - A string containing an IP address

	Returns: A string containing the domain name if there is one. If not, it will be an empty string.
	"""
	def __getDomainName(self, ip):
		domain = ''
		try:
			domain = socket.gethostbyaddr(str(ip))[0]
		except:
			domain = ''
		return domain

	"""
	getBody

	Gets a dictionary of strings from the content in the packet body.

	Params: 
	packet - A packet object

	Return: Dictionary of body contents
	"""
	def getBody(self, packet):
		result = {}
		
		if packet.haslayer(Raw):
			result['body'] = str(packet[Raw])
			body_parts = self.__getBodyText(str(packet[Raw].load))
			body_parts_string = ''.join(body_parts)
			result['body_parts'] = str(body_parts)
			result['body_parts_string'] = body_parts_string
			#result['body_IP'] = self.__getUrlsFromString(body_parts_string == '' ? packet[Raw].load : body_parts_string)
		
		return result
	
	"""
	Get Body Text

	Gets an array of the text from the body that does not contain the bytecodes.

	Params:
	body - the raw text from the body

	Return: An array of strings that make up the body of the packet
	"""
	def __getBodyText(self, body):
		# Handle the body being empty
		if body == '':
			return ''

		# Pull out the non-byte code contents
		result = re.findall(r'\\x\w\w([^\\]*)', body)

		return result

	"""
	Get URLs from String

	Pull out the URLs from the string if they are present.

	Params:
	text - the text to search

	Return: A string containing the URL if one is present, if not it will be an empty string
	"""
	def __getUrlsFromString(self, text):
		# Handle if the string is empty
		if text == '':
			return ''

		# Pull out any URLS present
		result = re.findall(r'([a-zA-Z0-9]*.[a-zA-Z0-9]*.[a-zA-Z0-9]*', text)

		return result

	"""
	get Ethernet Type String

	Gets the protocol of the eternet type. It recieves an int baesed on the ethernet type, then it compares it to a hex value. The conversion
	compares a int value to a hex and pulls out the value at the key location in a dictionary. Otherwise, it returns 'Undifined.'
	Note - The comparison between packetNumber and the key values (hex) is a direct comparison with no conversions to the same data type.

	Params:
	packetNumber - the packet[Ether].type which is a number based on the ethernet type. This value is an int.
	
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


	"""
	get IP Protocol String

	Gets the protocol of IP as a string. Compares against a dictionary to determine protocol

	Params:
	protocol - The protocol of the IP as an integer
	
	Return: A string of the IP Protocol
	"""
	def __getIPProtocolString(self, protocol):
		switch = {
			0 : 'HOPOPT, IPv6 Hop-by-Hop Option.',
			1 : 'ICMP, Internet Control Message Protocol.',
			2 : 'IGAP, Internet Group Management Protocol.',
			3 : 'GGP, Gateway to Gateway Protocol.',
			4 : 'IP in IP encapsulation.',
			5 : 'ST, Internet Stream Protocol.',
			6 : 'TCP, Transmission Control Protocol.',
			7 : 'UCL, CBT.',
			8 : 'EGP, Exterior Gateway Protocol.',
			9 : 'IGRP, Interior Gateway Routing Protocol.',
			10 : 'BBN RCC Monitoring.',
			11 : 'NVP, Network Voice Protocol.',
			12 : 'PUP.',
			13 : 'ARGUS.',	 
			14 : 'EMCON, Emission Control Protocol.',	 
			15 : 'XNET, Cross Net Debugger.',
			16 : 'Chaos.',
			17 : 'UDP, User Datagram Protocol.',
			18 : 'TMux, Transport Multiplexing Protocol.',
			19 : 'DCN Measurement Subsystems.',
			20 : 'HMP, Host Monitoring Protocol.',
			21 : 'Packet Radio Measurement.',
			22 : 'XEROX NS IDP.',
			23 : 'Trunk-1.',
			24 : 'Trunk-2.', 
			25 : 'Leaf-1.',
			26 : 'Leaf-2.',	 
			27 : 'RDP, Reliable Data Protocol.',
			28 : 'IRTP, Internet Reliable Transaction Protocol.',
			29 : 'ISO Transport Protocol Class 4.',
			30 : 'NETBLT, Network Block Transfer.',	 
			31 : 'MFE Network Services Protocol.', 
			32 : 'MERIT Internodal Protocol.',
			33 : 'DCCP, Datagram Congestion Control Protocol.',	 
			34 : 'Third Party Connect Protocol.',
			35 : 'IDPR, Inter-Domain Policy Routing Protocol.',	 
			36 : 'XTP, Xpress Transfer Protocol.',
			37 : 'Datagram Delivery Protocol.',
			38 : 'IDPR, Control Message Transport Protocol.',	 
			39 : 'TP++ Transport Protocol.',
			40 : 'IL Transport Protocol.',
			41 : 'IPv6 over IPv4.',
			42 : 'SDRP, Source Demand Routing Protocol.',	 
			43 : 'IPv6 Routing header.',
			44 : 'IPv6 Fragment header.',	 
			45 : 'IDRP, Inter-Domain Routing Protocol.',	 
			46 : 'RSVP, Reservation Protocol.',
			47 : 'GRE, General Routing Encapsulation.',	 
			48 : 'DSR, Dynamic Source Routing Protocol.',	 
			49 : 'BNA.',
			50 : 'ESP, Encapsulating Security Payload.',	 
			51 : 'AH, Authentication Header.',
			52 : 'I-NLSP, Integrated Net Layer Security TUBA.',	 
			53 : 'SWIPE, IP with Encryption.',
			54 : 'NARP, NBMA Address Resolution Protocol.',	 
			55 : 'Minimal Encapsulation Protocol.',
			56 : 'TLSP, Transport Layer Security Protocol using Kryptonet key management.',	 
			57 : 'SKIP.',
			58 : 'ICMPv6, Internet Control Message Protocol for IPv6.',
			59 : 'IPv6 No Next Header.',
			60 : 'IPv6 Destination Options.',	 
			61 : 'Any host internal protocol.',	 
			62 : 'CFTP.',
			63 : 'Any local network.',	 
			64 : 'SATNET and Backroom EXPAK.',	 
			65 : 'Kryptolan.',
			66 : 'MIT Remote Virtual Disk Protocol.',	 
			67 : 'Internet Pluribus Packet Core.',
			68 : 'Any distributed file system.',
			69 : 'SATNET Monitoring.',
			70 : 'VISA Protocol.',
			71 : 'Internet Packet Core Utility.',	 
			72 : 'Computer Protocol Network Executive.',	 
			73 : 'Computer Protocol Heart Beat.',
			74 : 'Wang Span Network.',
			75 : 'Packet Video Protocol.',	 
			76 : 'Backroom SATNET Monitoring.',	 
			77 : 'SUN ND PROTOCOL-Temporary.', 
			78 : 'WIDEBAND Monitoring.',
			79 : 'WIDEBAND EXPAK.',
			80 : 'ISO-IP.',
			81 : 'VMTP, Versatile Message Transaction Protocol.', 
			82 : 'SECURE-VMTP',
			83 : 'VINES.',
			84 : 'TTP.',
			85 : 'NSFNET-IGP.',	 
			86 : 'Dissimilar Gateway Protocol.',	 
			87 : 'TCF.',
			88 : 'EIGRP.',	 
			89 : 'OSPF, Open Shortest Path First Routing Protocol.', 
			90 : 'Sprite RPC Protocol.',
			91 : 'Locus Address Resolution Protocol.',	 
			92 : 'MTP, Multicast Transport Protocol.',	 
			93 : 'AX.25.',
			94 : 'IP-within-IP Encapsulation Protocol.', 
			95 : 'Mobile Internetworking Control Protocol.',	 
			96 : 'Semaphore Communications Sec. Pro.',
			97 : 'EtherIP.',
			98 : 'Encapsulation Header.',
			99 : 'Any private encryption scheme.',	 
			100 : 'GMTP.',
			101 : 'IFMP, Ipsilon Flow Management Protocol.',	 
			102 : 'PNNI over IP.',
			103 : 'PIM, Protocol Independent Multicast.',	 
			104 : 'ARIS.',
			105 : 'SCPS.',	 
			106 : 'QNX.',
			107 : 'Active Networks.',	 
			108 : 'IPPCP, IP Payload Compression Protocol.',
			109 : 'SNP, Sitara Networks Protocol.',
			110 : 'Compaq Peer Protocol.',
			111 : 'IPX in IP.',
			112 : 'VRRP, Virtual Router Redundancy Protocol.',
			113 : 'PGM, Pragmatic General Multicast.',
			114 : 'any 0-hop protocol.',
			115 : 'L2TP, Level 2 Tunneling Protocol.',
			116 : 'DDX, D-II Data Exchange.',
			117 : 'IATP, Interactive Agent Transfer Protocol.', 
			118 : 'ST, Schedule Transfer.',
			119 : 'SRP, SpectraLink Radio Protocol.',	 
			120 : 'UTI.',
			121 : 'SMP, Simple Message Protocol.',	 
			122 : 'SM.',
			123 : 'PTP, Performance Transparency Protocol.',	 
			124 : 'ISIS over IPv4.',
			125 : 'FIRE.',
			126 : 'CRTP, Combat Radio Transport Protocol.',	 
			127 : 'CRUDP, Combat Radio User Datagram.',
			128 : 'SSCOPMCE.',
			129 : 'IPLT.',
			130 : 'SPS, Secure Packet Shield.',	 
			131 : 'PIPE, Private IP Encapsulation within IP.',	 
			132 : 'SCTP, Stream Control Transmission Protocol.',	 
			133 : 'Fibre Channel.',
			134 : 'RSVP-E2E-IGNORE.',
			135 : 'Mobility Header.',
			136 : 'UDP-Lite, Lightweight User Datagram Protocol.',
			137 : 'MPLS in IP.',
			138 : 'MANET protocols.',
			139 : 'HIP, Host Identity Protocol.',
			140 : 'Shim6, Level 3 Multihoming Shim Protocol for IPv6.',
			141 : 'WESP, Wrapped Encapsulating Security Payload.',
			142 : 'ROHC, RObust Header Compression.',
			253 : 'Experimentation and testing.',
			254 : 'Experimentation and testing.',	 
			255 : 'reserved.'
		}
		if protocol not in switch.keys():
			if(protocol >= 143 and protocol <= 252):
				return 'Unassigned'
			else:
				return 'Undefined'
		return switch[protocol]
