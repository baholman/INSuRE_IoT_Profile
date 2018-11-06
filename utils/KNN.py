import os
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
		attributes = []

		for key in json_data.keys():
			for value in json_data[key]:
				attributes.append(value)
		
		device_labels = []
		eval_labels = []
		attributes_eval = []
		attributes_training = []
		
		json_training_path = os.path.join(exp_dir, 'training_json')
		json_eval_path = os.path.join(exp_dir, 'eval_json')

		for file_name in os.listdir(json_training_path):
			with open(os.path.join(json_training_path, file_name)) as device_file:
				device_data = json.load(device_file)
			attributes_training = [[0]*len(device_data['packets']) for i in range(len(attributes))]

			if 'label' not in device_data.keys():
				print('WARNING: Device label was not provided in ' + file_name  + '. This information is required to use the packets from this file.')
			else:
				device_labels.append([device_data['label']]*len(device_data['packets']))
				for attribute in attributes:
					for index in range(len(attributes)):
						for packet in range(len(device_data['packets'])):
							if attribute in device_data['packets'][packet]['header']:
								attributes_training[index][packet] = device_data['packets'][packet]['header'][attribute]
							else:
								attributes_training[index][packet] = 0
			"""
			attributes_training = [[0]*len(attributes) for i in range(len(device_data['packets']))]
			for packet in range(len(device_data['packets'])):
				index = 0
				for attribute in attributes:
					for index in range(len(attributes))
						if attribute in device_data['packets'][packet]['header']:
							#attributes_training[packet].append(device_data['packets'][packet]['header'][attribute])
							attributes_training[packet][index] =  device_data['packets'][packet]['header'][attribute]
						else:
							#attributes_training[packet].append(0)
							attributes_training[packet][index] = 0
			"""
	
		for file_name in os.listdir(json_eval_path):
			with open(os.path.join(json_eval_path, file_name)) as device_file:
				eval_data = json.load(device_file)
			attributes_eval = [[0]*len(eval_data['packets']) for i in range(len(attributes))]

			if 'label' not in eval_data.keys():
				print('WARNING: Device label was not provided in ' + file_name + '. This information is required to use the packets in this file.')
			else:
				eval_labels.append([eval_data['label']]*len(eval_data['packets']))
				for attribute in attributes:
					for index in range(len(attributes)):
						for packet in range(len(eval_data['packets'])):
							if attribute in eval_data['packets'][packet]['header']:
								attributes_eval[index][packet] = eval_data['packets'][packet]['header'][attribute]
							else:
								attributes_eval[index][packet] = 0

			"""
			attributes_eval = [[0]*len(attributes) for i in range(len(eval_data['packets']))]
			for packet in range(len(eval_data['packets'])):
				for attribute in attributes:
					for index in range(len(attributes))
						if attribute in eval_data['packets'][packet]['header']:
							#attributes_eval[packet].append(eval_data['packets'][packet]['header'][attribute])
							attributes_eval[packet][index] = eval_data['packets'][packet]['header'][attribute]
						else:
							#attributes_eval[packet].append(0)
							attributes_eval[packet][index] = 0
					
			"""
			
			
		self.__scaleFeatures(attributes_training, attributes_eval)
		self.__trainAndPredict(device_labels, attributes_training, attributes_eval)

		
	def __scaleFeatures(self, attributes_training, attributes_eval):
		scaler = StandardScaler()  
		scaler.fit(attributes_training)

		attributes_training = scaler.transform(attributes_training)
		attributes_eval = scaler.transform(attributes_eval)


	def __trainAndPredict(self, device_labels, attributes_training, attributes_eval):
		n_neighbors_count = 5
		classifier = KNeighborsClassifier(n_neighbors=n_neighbors_count)
		classifier.fit(attributes_training, device_labels)
		eval_pred = classifier.predict(attributes_eval)
		self.__evalKNN(eval_pred, device_labels)

	def __evalKNN(self, eval_pred, device_labels):
		print(confusion_matrix(device_labels, eval_pred))  
		print(classification_report(device_labels, eval_pred))  




