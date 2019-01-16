#!/bin/python

import os
import re
import sys
import json
import subprocess

print('Start processing')

device_identifiers = []

# Check the number of arguments
if len(sys.argv) != 4:
	print("ERROR: Incorrect number of arguments")
	print("    python3 standardizeExperimentFolders2.py <device names filename> <directory prefix> <num of pcap directories>")
	sys.exit(-1)

# Get the arguments from the script
device_names_filename = sys.argv[1]
dir_prefix = sys.argv[2]
total_num_pcap_dirs = int(sys.argv[3])

#print("Devices filename: " + device_names_filename)
#print("Directory prefix: " + dir_prefix)
#print("Total number of pcap directories: " + str(total_num_pcap_dirs))

comb_dir = os.path.join('experiments', dir_prefix + 'combined')

pcap_dirs = []

if os.path.exists(comb_dir) and os.path.isdir(comb_dir):
	# Get the current pcap directory to start processing
	progress_path = os.path.join(os.getcwd(), comb_dir, 'progress.txt')
	progress_file = open(progress_path, 'r')
	progress_contents = progress_file.read()

	progress_dir_num = progress_contents.replace(dir_prefix, '')

	# Get the list of directories to go through
	for i in range(int(progress_dir_num), total_num_pcap_dirs):
		pcap_dirs.append(dir_prefix + str(i))
else:
	# Create combined files directory
	os.mkdir(comb_dir)
	comb_flow_dir = os.path.join(comb_dir, 'flow_json')
	os.mkdir(comb_flow_dir)

	# Get the list of directories to go through
	for i in range(total_num_pcap_dirs):
		pcap_dirs.append(dir_prefix + str(i))

	# Get the device identifiers for each of the known devices
	print('Start creating the device directories')
	device_names_parent = ''
	if ((device_names_filename[0] != '/') or (device_names_filename[0] != '~')):
		device_names_parent = os.getcwd()
	else:
		device_names_parent = ''
	device_names_path = os.path.join(device_names_parent, device_names_filename)

	if not os.path.isfile(device_names_path):
		print('ERROR: The device names file provided does not exist')
		sys.exit(-1)

	device_names_file = open(device_names_path, 'r')
	device_names_json = json.loads(device_names_file.read())

	for device_name in device_names_json:
		device = device_names_json[device_name]
		device_identifiers.append({
			"name": device_name,
			"Ethernet_Source_MAC": device["Source MAC Address"],
			"IP_Source_Address": device["IP Address"]
		})

	# Make the directories for the various devices
	for device in device_identifiers:
		current_device_name = device['name']

		# Make the directory
		os.mkdir(os.path.join(comb_dir, 'flow_json', current_device_name))
	print('End creating the device directories')

# Get the files from everything other file
print('Start processing the experiment directories')
for exp_dir in pcap_dirs:
	print('Start processing the ' + exp_dir + ' directory')

	# Mark the experiment in the progress file
	progress_path = os.path.join(comb_dir, 'progress.txt')
	progress_file = open(progress_path, 'w')
	progress_file.write(exp_dir)
	progress_file.close()

	exp_flow_dir = os.path.join('experiments', exp_dir, 'flow_json')
	# Go through the list of device directories
	for device_dir in os.listdir(exp_flow_dir):
		exp_device_path = os.path.join(exp_flow_dir, device_dir)

		# Go through list of file names for the device
		for filename in os.listdir(exp_device_path):
			# Check if the file already exists
			old_file_path = os.path.join(exp_device_path, filename)
			new_file_path = os.path.join(comb_dir, 'flow_json', device_dir, filename)

			if os.path.exists(new_file_path):
				# Open new and old file
				print('New file path: '  + new_file_path)
				new_file = open(new_file_path, 'r')
				new_file_contents = new_file.read()
				new_file_json = json.loads(new_file_contents)
				new_file.close()

				print('Old file path: ' + old_file_path)
				old_file = open(old_file_path, 'r')
				old_file_contents = old_file.read()
				old_file_json = json.loads(old_file_contents)
				old_file.close()

				new_file = open(new_file_path, 'w')
				# Go through each packet in the old file
				for old_packet in old_file_json['packets']:
					old_packet_found = False
					# Go through each packet in the new file
					for new_packet in new_file_json['packets']:
						if new_packet['Packet_Timestamp'] == old_packet['Packet_Timestamp']:
							old_packet_found = True
							continue
					
					# Add the packet if it isn't already added
					if not old_packet_found:
						new_file_json['packets'].append(old_packet)
				# Save the new file information again
				new_file.write(json.dumps(new_file_json))
				new_file.close()
			else:
				new_file_path = os.path.join(comb_dir, 'flow_json', device_dir)
				cp_cmd = 'cp ' + old_file_path + ' ' + new_file_path
				os.system(cp_cmd)
print('End processing the experiment directories')

print('End processing')
