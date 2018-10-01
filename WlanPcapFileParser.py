"""
PCAP File Parser

TODOs:
* Take the PCAP binary and convert it to text
* Take the PCAP text and get individual packet text
* Get the header info from the packet text
* Get the body info from the packet text
* Put the file contents into a JSON file

Given: A directory of PCAP files
Returns: A directory of JSON files (one for each PCAP file), device identifier fields (a list of strinngs that identifies the field which differentiates devices)
"""

class WlanPcapFileParser:
    """
    main(string dir):
        result = {}
        for file in dir:
            open file
        string = parseBinary(input)

        file_dict = {}
        file_dict['name'] = file_name
        file_dict['protocol'] = protocol
        file-dict['packets'] = packets
        file_dict['identifiers'] = identifiers

        for packet in getPackets(string):
            packet_json = {}
            packet_json['header'] = getHeader(string)
            packet_json['body'] = getBody(string)
            result.append(packet_json)
        return results
    """

    """
    parseBinary(input_file):
        convert to string
        return pcap_string
    """
    """
    getPackets(pcap_string):
        return listOfStrings_PacketContents
    """
    """
    getHeader(packet_string):
        return dictOfValues
    """
    """
    getBody(packet_string):
        return dictOfValues
    """
    
