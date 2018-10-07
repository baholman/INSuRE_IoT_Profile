import os
from scapy.all import *
from scapy import pcapy as p
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
            #Initalize file dictionary
            file_dict = {}
            file_dict['file_path'] = file_name
            file_dict['protocol'] = 'WLAN'
            file_dict['identifiers'] = ['source_ip']
            file_dict['packets'] = []

            #get file contents
            input_path = os.path.join(pcap_dir, file_name);
            input_file = open(input_path,'r')
            pcap_text = self.__parseBinary(input_file)

            #get packet info
            for packet in self.__getPackets(pcap_text):
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

    Return: string of the PCAP file
    """
    def __parseBinary(self, input_filename):
        pcap_string = ''
        input_filename_txt = os.path.splitext(input_filename)[0] + '.txt'
        os.system('tshark  -T fields  -e frame.time -e  data.data -w ' + input_filename + ' > ' + input_filename_txt + ' -F pcap -c 1000')
        pcap_string = rdpcap(input_filename)
        return pcap_string


    """
    getPackets

    Gets a list of the strings from the various packets in the PCAP file.

    Params: 
    pcap_string - string of the PCAP file

    Return: array of the string contents of a packet
    """
    def __getPackets(self, pcap_string):
        result = []
        for packet in re.split(r'\s([{\[].*?[}\]])$', pcap_string):
            result.append(packet)
        return result


    """
    getHeader

    Gets a dictionary of strings from the fields in the packet header.

    Params: 
    packet_string - A string of a packets contents

    Return: Dictionary of header fields
    """
    def __getHeader(self, packet_string):
        return {}


    """
    getBody

    Gets a dictionary of strings from the content in the packet body.

    Params: 
    packet_string - A string of a packets contents

    Return: Dictionary of body contents
    """
    def __getBody(self, packet_string):
        return {}
    
