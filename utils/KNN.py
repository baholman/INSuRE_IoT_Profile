import os

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


