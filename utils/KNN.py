import os
import json
from pprint import pprint

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
        json_file_path = exp_dir + feature_json
        if (not os.path.exists(json_file_path)):
            print('Error: JSON file \"' + json_file_path + '\" does not exists')
            return
        
        with open(json_file_path) as json_file:
            json_data = json.load(json_file)
        pprint(json_data)



