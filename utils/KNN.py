import os
import sys
import json
from pprint import pprint
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix

"""
K-Nearest Neighbor

Implements K-Nearest Neighbor approach to machine learning
"""
class KNN():
	"""
	isDir

	Checks to see if the string provided is a directory. Otherwise, it throws an error

	Params:
	exp_dir - name of the experimental directory as a string
	"""
	def isDir(self, exp_dir):
		if (not os.path.isdir(exp_dir)):
			print('Error: directory \"' + exp_dir + '\" does not exists')
			return
		self.__parseFeaturesFromJson(exp_dir)


	"""
	parseFeaturesFromJson

	Parses a JSON file which holds the features to implement KNN with

	Params:
	exp_dir - name of the experimental directory as a string
	feature_json - name of json file as string (default is features.json)
	"""
	def __parseFeaturesFromJson(self, exp_dir, feature_json = 'features.json'):
		json_file_path = os.path.join(exp_dir, feature_json)
		if (not os.path.exists(json_file_path)):
			print('Error: JSON file \"' + json_file_path + '\" does not exists')
			return
		
		with open(json_file_path) as json_file:
			json_data = json.load(json_file)
		pprint(json_data)
		self.__getKNNFeatures(exp_dir, json_data)


	def __getKNNFeatures(self, exp_dir, json_data):
		# Get the list of features?
		features = []
		for key in json_data.keys():
			for value in json_data[key]:
				features.append(value)
		
		# Get the directories with the training and evaluation JSON files
		json_training_path = os.path.join(exp_dir, 'training_json')
		json_eval_path = os.path.join(exp_dir, 'eval_json')

		# Get the arrays of attributes for the different types of data
		attributes_training, training_labels = self.__getAttributesFromJsonFiles(json_training_path, features, "training")
		attributes_eval, eval_labels = self.__getAttributesFromJsonFiles(json_eval_path, features, "eval")	

		# Verify that some usable training attributes were found
		if attributes_training == []:
			print('ERROR: No training attributes provided')
			exit(-1)
	
		# Verify that some usable evaluation attributes were found
		if attributes_eval == []:
			print('ERROR: No eval attributes provided')
			exit(-1)
		
		self.__scaleFeatures(attributes_training, attributes_eval)
		eval_pred = self.__trainAndPredict(training_labels, attributes_training, attributes_eval)
		self.__evalKNN(eval_pred, eval_labels)

	"""
	getAttributesFromJsonFiles

	Get the attributes specified in the feature set from the various packets in the JSON files in the specfied directory formatted for KNN calculations.

	Params:
	json_dir_path - A string containing the path to the directory where the JSON files are located
	features - An array of features to look for in the packets
	type_of_attributes - A string that specifies either training or evaluation. This will mainly be used to provide better error messages.

	Returns: A 2D array of attributes formatted for use by KNN algorithm
	"""
	def __getAttributesFromJsonFiles(self, json_dir_path, features, type_of_attributes):
		attributes = []
		device_labels = []

		# Go through each of JSON files
		for file_name in os.listdir(json_dir_path):
			# Load the data into a dictionary
			with open(os.path.join(json_dir_path, file_name)) as device_file:
				device_data = json.load(device_file)

			if 'label' not in device_data.keys():
				print('WARNING: Device label was not provided for ' + file_name  + ' file in ' + type_of_attributes + ' JSON files. This information is required to use the packets from this file.')
				continue
			
			# Get the label for the type of device from the JSON file
			device_label = device_data['label']

			# Go through all the packets in the JSON file
			for packet in device_data['packets']:
				packet_attributes = []
				for feature in features:
					# Verify that the packet data isn't malformed the JSON file
					if 'header' not in packet.keys():
						print('ERROR: Packet in ' + file_name + ' for ' + type_of_attributes + ' data does not contain header section. JSON file is malformed.')
						exit(-1)

					# Get the value of the attribute from the packet
					if feature in packet['header'].keys():
						val = packet['header'][feature]
					else:
						print('WARNING: The ' + feature + ' attribute was expected in packets in the ' + file_name + ' file for the ' + type_of_attributes + ' data but was not found. The default value was used instead.')
						val = 0

					# TODO: Do any data cleaning or manipulation here

					# Add the attribute value to the packet attributes
					packet_attributes.append(val)

				# Add the device label at the end of the packet attributes array
				device_labels.append(device_label)

				# Add the packet attributes to the array of training data
				attributes.append(packet_attributes)

		return attributes, device_labels

	def __scaleFeatures(self, attributes_training, attributes_eval):
		scaler = StandardScaler()  
		scaler.fit(attributes_training)

		attributes_training = scaler.transform(attributes_training)
		attributes_eval = scaler.transform(attributes_eval)


	def __trainAndPredict(self, training_labels, attributes_training, attributes_eval):
		n_neighbors_count = 5
		classifier = KNeighborsClassifier(n_neighbors=n_neighbors_count)
		classifier.fit(attributes_training, training_labels)
		eval_pred = classifier.predict(attributes_eval)
		return eval_pred

	def __evalKNN(self, eval_pred, eval_labels):
		print(confusion_matrix(eval_labels, eval_pred))  
		print(classification_report(eval_labels, eval_pred))  




