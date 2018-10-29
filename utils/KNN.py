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
        file_names_training = []
        file_names_eval = []
        attributes_eval = {}
        attributes_training = {}
        json_training_path = os.path.join(exp_dir, 'training_json')
        json_eval_path = os.path.join(exp_dir, 'eval_json')

        for file_name in os.listdir(json_training_path):
            file_names_training.append(file_name)
            with open(os.path.join(json_training_path, file_name)) as device_file:
                device_data = json.load(device_file)
            for packet in range(0, len(device_data['packets'])):
                for attribute in attributes:
                    if attribute in device_data['packets'][packet]['header']:
                        attributes_training[attribute] = device_data['packets'][packet]['header'][attribute]

        for file_name in os.listdir(json_eval_path):
            file_names_eval.append(file_name)
            with open(os.path.join(json_eval_path, file_name)) as device_file:
                eval_data = json.load(device_file)
            for packet in range(0, len(eval_data['packets'])):
                for attribute in attributes:
                    if attribute in eval_data['packets'][packet]['header']:
                        attributes_eval[attribute] = eval_data['packets'][packet]['header'][attribute]
        self.__scaleFeatures(file_names_training, file_names_eval, attributes_training, attributes_eval)

        
    def __scaleFeatures(self, file_names_training, file_names_eval, attributes_training, attributes_eval):
        scaler = StandardScaler()  
        scaler.fit(file_names_training)

        file_names_training = scaler.transform(file_names_training)
        file_names_eval = scaler.transform(file_names_eval)

        self.__trainAndPredict(file_names_training, file_names_eval, attributes_training, attributes_eval)


    def __trainAndPredict(self, file_names_training, file_names_eval, attributes_training, attributes_eval):
        n_neighbors_count = len(file_names_training)
        classifier = KNeighborsClassifier(n_neighbors=n_neighbors_count)  
        classifier.fit(file_names_training, attributes_training)
        eval_pred = classifier.predict(file_names_eval)
        self.__evalKNN(eval_pred, attributes_eval)

    def __evalKNN(self, eval_pred, attributes_eval):
        print(confusion_matrix(attributes_eval, eval_pred))  
        print(classification_report(attributes_eval, eval_pred))  




