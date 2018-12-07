#!/bin/python

import sys
import os
import re

experiment_dir = sys.argv[1]
flow_json_dir = os.path.join(experiment_dir, "flow_json")
for device_dir in os.listdir(flow_json_dir):
	print("Looking at the " + device_dir + " device")
	device_dir_path = os.path.join(flow_json_dir, device_dir)
	if os.path.isdir(device_dir_path):
		for filename in os.listdir(device_dir_path):
			file_path = os.path.join(device_dir_path, filename)
			print("Processing the " + filename + " flow file")
			if os.path.isfile(file_path):
				dfile = open(file_path, "r")
				last_line = ""
				lines = dfile.readlines()
				new_lines = lines[:-1]
				last_line = lines[len(lines) - 1]
				dfile.close()

				dfile = open(file_path, "w")
				for line in new_lines:
					dfile.write(line)
					
				doesMatch = re.match("\t\t}", last_line)
				bad2 = re.match("\t}}", last_line)
				if doesMatch != None:
					dfile.write(last_line + "\n")
					dfile.write("\t}\n")
					dfile.write("}\n")
				elif last_line == "}":
					dfile.write(last_line + "\n")
				elif bad2 != None:
					dfile.write("\t}\n")
					dfile.write("}\n")
				else:
					print("ERROR: Malformed flow file")
					print("Last line was: " + str(line))

				dfile.close()
