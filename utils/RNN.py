from sklearn.neighbors import RadiusNeighborsClassifier
from sklearn.preprocessing import StandardScaler

"""
Radius Nearest Neighbor (rNN)

Implements rNN in order to detemine unlabeled devices
"""
class RNN():
	def runRNN(self, attributes_training, training_labels, attributes_eval, exp_dir, radius = 0.5):
		# Verify that some usable training attributes were found
		if attributes_training == []:
			print('ERROR: No training attributes provided')
			exit(-1)
	
		# Verify that some usable evaluation attributes were found
		if attributes_eval == []:
			print('ERROR: No eval attributes provided')
			exit(-1)
		
		# Determines whether a Label can be predicted
		canLabel = False

		self.__scaleFeatures(attributes_training, attributes_eval)
		canLabel = self.__trainAndPredict(training_labels, attributes_training, attributes_eval, radius)

		return canLabel


	"""
	scaleFeatures

	Fits the RNN alogrithm using the training data set

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

	Uses a specified radius to classify/train and predict

	Params:
	training_labels - the labels of devices from the training set
	attributes_training - the training set
	attributes_eval - the evaluation set

	Return - True if labeled, otherwise False
	"""
	def __trainAndPredict(self, training_labels, attributes_training, attributes_eval, radius):
		try:
			classifier = RadiusNeighborsClassifier(radius=radius)
			classifier.fit(attributes_training, training_labels)
			eval_pred = classifier.predict(attributes_eval)
			return True
		except ValueError:
			return False
