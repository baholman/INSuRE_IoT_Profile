import os
import sys
import json
# Used for implementing KNN
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix
# Used for finding K value
import numpy as np
import matplotlib
import matplotlib.pyplot as plt

"""
K-Nearest Neighbor

Implements K-Nearest Neighbor approach to machine learning
"""
class KNN():
	def runKNN(self, attributes_training, training_labels, attributes_eval, eval_labels, all_device_labels):
		# Verify that some usable training attributes were found
		if attributes_training == []:
			print('ERROR: No training attributes provided')
			exit(-1)
	
		# Verify that some usable evaluation attributes were found
		if attributes_eval == []:
			print('ERROR: No eval attributes provided')
			exit(-1)
		
		# Gets number of packets in evaluation set
		packet_count = len(eval_labels)

		self.__scaleFeatures(attributes_training, attributes_eval)
		eval_pred, classifier = self.__trainAndPredict(training_labels, attributes_training, attributes_eval)
		self.__evalKNN(eval_pred, eval_labels, classifier, all_device_labels, packet_count, attributes_eval)
		#Uncomment code to find K value graph
		#self.__findKValue(attributes_training, attributes_eval, training_labels, eval_labels)

	"""
	getAttributesFromJsonFiles

	Get the attributes specified in the feature set from the various packets in the JSON files in the specfied directory formatted for KNN calculations.

	Params:
	json_dir_path - A string containing the path to the directory where the JSON files are located
	features - An array of features to look for in the packets
	type_of_attributes - A string that specifies either training or evaluation. This will mainly be used to provide better error messages.

	Returns: A 2D array of attributes formatted for use by KNN algorithm, a list of device labels to use by KNN algorithm, and a list of all labels of devices
	"""
	def __getAttributesFromJsonFiles(self, json_dir_path, features, type_of_attributes):
		attributes = []
		device_labels = []
		device_all_labels = []

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
			device_all_labels.append(device_label)

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

		return attributes, device_labels, device_all_labels

	"""
	scaleFeatures

	Fits the KNN alogrithm using the training data set

	Params:
	attributes_training - the training set
	attributes_eval - the evaluation set
	"""
	def __scaleFeatures(self, attributes_training, attributes_eval):
		scaler = StandardScaler()  
		scaler.fit(attributes_training)

		attributes_training = scaler.transform(attributes_training)
		attributes_eval = scaler.transform(attributes_eval)

	"""
	trainAndPredict

	Uses a specified amount of K-neighbors to classify/train and predict

	Params:
	training_labels - the labels of devices from the training set
	attributes_training - the training set
	attributes_eval - the evaluation set

	Return - the prediction on the evaluation set, and the classifier fitted for the specific attributes
	"""
	def __trainAndPredict(self, training_labels, attributes_training, attributes_eval):
		n_neighbors_count = 2
		classifier = KNeighborsClassifier(n_neighbors=n_neighbors_count)
		classifier.fit(attributes_training, training_labels)
		eval_pred = classifier.predict(attributes_eval)
		return eval_pred, classifier

	"""
	evalKNN

	Uses information provided to evaluate device(s) using the KNN machine learning algorithm, and gives probability/score of each device.

	Params:
	eval_pred - the prediction on the evaluation set
	eval_labels - the labels of devices in the evaluation set
	classifier - the classifier for these sets
	device_labels - labels of each device with no duplicates
	packet_count - number of packets
	attributes_eval - attributes from evaluation set
	"""
	def __evalKNN(self, eval_pred, eval_labels, classifier, device_labels, packet_count, attributes_eval):
		scores = []
		score_dict = {}

		for label in device_labels:
			label_array = [label]*packet_count
			score_label = classifier.score(attributes_eval, label_array)
			scores.append(label + ' has score = ' + str(score_label))
			score_dict[label] = str(score_label)

		print('\nThe following is the \"Confusion Matrix\"')
		print(confusion_matrix(eval_labels, eval_pred)) 
		#print('\nThe following is the \"Classification Report\"') 
		#print(classification_report(eval_labels, eval_pred))

		print('\nListed below are the \"scores\" for each device in the training set')
		for score in scores:
			print(score)
		
		self.__saveScoreToJson(score_dict)

	"""
	saveScoreToJson

	Saves the scores/accuracy of each label to a json file

	Params:
	score_dict - a dictionary of each label of devices and their scores
	"""
	def __saveScoreToJson(self, score_dict):
		with open('scores.json', 'w') as outfile:
			json.dump(score_dict, outfile)

	"""
	findKValue

	Prints a graph of the error of each k value (1 to 40). It uses matplotlib, feh, and a X server

	**To run this code, the function call in getKNNFeatures must be uncommented**

	Params:
	attributes_training - the training set
	attributes_eval - the eval set
	training labels - the labels of the devices from the training set
	eval_labels - the labels of the devices from the eval set
	"""
	def __findKValue(self, attributes_training, attributes_eval, training_labels, eval_labels):
		error = []
		# Calculating error for K values between 1 and 40
		for i in range(1, 40):  
			knn = KNeighborsClassifier(n_neighbors=i)
			knn.fit(attributes_training, training_labels)
			pred_i = knn.predict(attributes_eval)
			error.append(np.mean(pred_i != eval_labels))
		# Prints Graph of K-Value Error
		# Must install feh and an X server (Xming)
		matplotlib.use('Svg')
		plt.figure(figsize=(12, 6))
		plt.plot(range(1, 40), error, color='red', linestyle='dashed', marker='o', markerfacecolor='blue', markersize=10)
		plt.title('Error Rate K Value')
		plt.xlabel('K Value')
		plt.ylabel('Mean Error')
		plt.savefig('kGraph.png')
		os.system('feh kGraph.png')


