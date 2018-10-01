import os

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
    def getJson(pcap_dir):
        result = []
        
        for file_path in os.listdir(pcap_dir):
            #Initalize file dictionary
            file_dict = {}
            file_dict['file_path'] = file_path
            file_dict['protocol'] = 'WLAN'
            file_dict['identifiers'] = ['source_ip']
            file_dict['packets'] = []

            #get file contents
            input_file = open(file_path,'r')
            pcap_text = __parseBinary(input_file)

            #get packet info
            for packet in getPackets(pcap_text):
                packet_dict = {}
                packet_dict['header'] = getHeader(packet)
                packet_dict['body'] = getBody(packet)
                file_dict['packets'].append(packet_dict)

            result.append(file_dict)

        return result


    """
    parseBinary

    Parses binary to text.

    Params: 
    input_file - input file object

    Return: string of the PCAP file
    """
    def __parseBinary(input_file):
        return ''


    """
    getPackets

    Gets a list of the strings from the various packets in the PCAP file.

    Params: 
    pcap_string - string of the PCAP file

    Return: array of the string contents of a packet
    """
    def __getPackets(pcap_string):
        return []


    """
    getHeader

    Gets a dictionary of strings from the fields in the packet header.

    Params: 
    packet_string - A string of a packets contents

    Return: Dictionary of header fields
    """
    def __getHeader(packet_string):
        return {}


    """
    getBody

    Gets a dictionary of strings from the content in the packet body.

    Params: 
    packet_string - A string of a packets contents

    Return: Dictionary of body contents
    """
    def __getBody(packet_string):
        return {}
    
