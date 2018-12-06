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
	def runKNN(self, attributes_training, training_labels, attributes_eval, eval_labels, all_device_labels, exp_dir):
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
		highest_score_label = self.__evalKNN(eval_pred, eval_labels, classifier, all_device_labels, packet_count, attributes_eval, exp_dir)
		# Uncomment code to find K value graph
		#self.__findKValue(attributes_training, attributes_eval, training_labels, eval_labels, exp_dir)
		return highest_score_label

	def __breakFlow(self, eval_flow_attributes, trainging_flow_attributes):
		numPackets = len(eval_flow_attributes['packets'])
		training_packets_number = int(numPackets / 80)
		eval_packets_number = int(numPackets / 20)
		training_packets = []
		eval_packets = []
		for packetNum in range(training_packets_number):
			training_packets.append(eval_flow_attributes['packets'][packetNum])
		for packetNum in  range(eval_packets_number):
			eval_packets.append(eval_flow_attributes['packets'][training_packets_number + packetNum])
		trainging_flow_attributes.append(training_packets)
		eval_flow_attributes.clear()
		eval_flow_attributes.append(eval_packets)
		return trainging_flow_attributes, eval_flow_attributes
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
	def __evalKNN(self, eval_pred, eval_labels, classifier, device_labels, packet_count, attributes_eval, exp_dir):
		scores = []
		score_dict = {}
		highest_score_label = 'Unknown'
		highest_score = -1.0

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
		
		for label in score_dict:
			if(float(score_dict[label]) > highest_score):
				highest_score_label = label
				highest_score = float(score_dict[label])

		self.__saveScoreToJson(score_dict, exp_dir)

		return highest_score_label

	"""
	saveScoreToJson

	Saves the scores/accuracy of each label to a json file

	Params:
	score_dict - a dictionary of each label of devices and their scores
	"""
	def __saveScoreToJson(self, score_dict, exp_dir):
		scores_path = os.path.join(exp_dir, 'scores.json')
		with open(scores_path, 'w') as outfile:
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
	def __findKValue(self, attributes_training, attributes_eval, training_labels, eval_labels, exp_dir):
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
		graphPath = os.path.join(exp_dir,'kGraph.png')
		plt.savefig(graphPath)
		os.system('feh ' + graphPath)


