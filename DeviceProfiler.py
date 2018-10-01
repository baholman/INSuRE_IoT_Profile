#!/bin/python

print("test");

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

"""
Device File Creator

TODOs:
* Get a list of devices from the packets
* Create different JSON files for each device
* Put all the packets for each device in the devices JSON file

Given: A directory of JSON files (one for each source JSON file), device identifier fields (a list of strings that identifies the field which differentiates devices)
Returns: A directory of JSON files (one for each device)
"""

"""
JSON Visualization Generator (OPTIONAL)
This is an extra step we could take to make the files easier to understand.
There also might be libraries that already do this that we could use.

TODOs:
* Create a tree graph of the JSON file contents for a given JSON file

Given: A device JSON file
Returns: A image of a graph for that file
"""

"""
Device Profiler

TODOs:
* Get machine learning library
* Get device data from JSON
* Format device data for library
* Use library to label devices

Given: A JSON file for a device
Returns: A label for the device
"""
#asdsa