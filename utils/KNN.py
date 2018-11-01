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
                
        attributes_eval = []
        attributes_training = []
        json_training_path = os.path.join(exp_dir, 'training_json')
        json_eval_path = os.path.join(exp_dir, 'eval_json')

        for file_name in os.listdir(json_training_path):
            with open(os.path.join(json_training_path, file_name)) as device_file:
                device_data = json.load(device_file)
            attributes_training = [[None]*len(attributes) for i in range(len(device_data['packets']))]
            for packet in range(len(device_data['packets'])):
                for attribute in attributes:
                    if attribute in device_data['packets'][packet]['header']:
                        attributes_training[packet].append(device_data['packets'][packet]['header'][attribute])

        for file_name in os.listdir(json_eval_path):
            with open(os.path.join(json_eval_path, file_name)) as device_file:
                eval_data = json.load(device_file)
            attributes_eval = [[None]*len(attributes) for i in range(len(eval_data['packets']))]
            for packet in range(len(eval_data['packets'])):
                for attribute in attributes:
                    if attribute in eval_data['packets'][packet]['header']:
                        attributes_eval[packet].append(eval_data['packets'][packet]['header'][attribute])

        self.__scaleFeatures(attributes_training, attributes_eval)
        self.__trainAndPredict(attributes, attributes_training, attributes_eval)

        
    def __scaleFeatures(self, attributes_training, attributes_eval):
        scaler = StandardScaler()  
        scaler.fit(attributes_training)

        attributes_training = scaler.transform(attributes_training)
        attributes_eval = scaler.transform(attributes_eval)


    def __trainAndPredict(self, attributes, attributes_training, attributes_eval):
        n_neighbors_count = len(attributes)
        classifier = KNeighborsClassifier(n_neighbors=n_neighbors_count)  
        classifier.fit(attributes_training, attributes)
        eval_pred = classifier.predict(attributes_eval)
        self.__evalKNN(eval_pred, attributes)

    def __evalKNN(self, eval_pred, attributes):
        print(confusion_matrix(attributes, eval_pred))  
        print(classification_report(attributes, eval_pred))  




