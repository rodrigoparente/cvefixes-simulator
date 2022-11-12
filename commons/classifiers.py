# python imports
import numpy as np

# third-party imports
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split

# patching sklearn lib to run faster
# https://intel.github.io/scikit-learn-intelex/what-is-patching.html
from sklearnex import patch_sklearn
patch_sklearn(verbose=False)

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier

from sklearn.preprocessing import StandardScaler
from sklearn_extra.cluster import KMedoids

from modAL.uncertainty import margin_sampling
from modAL.uncertainty import entropy_sampling
from modAL.uncertainty import uncertainty_sampling


def initial_pool_test_split(X, y, initial_size, test_size):
    # splitting data into pool and test
    X_pool, X_test, y_pool, y_test =\
        train_test_split(X, y, test_size=test_size)

    # calculating clusters centers
    kmedoids = KMedoids(n_clusters=initial_size)
    kmedoids.fit(StandardScaler().fit_transform(X_pool))

    # get the indexes of the medoids centers
    initial_idx = kmedoids.medoid_indices_

    # selecting elements to X_initial
    X_initial, y_initial = X_pool[initial_idx], y_pool[initial_idx]

    # removing selected elements from X_pool
    X_pool = np.delete(X_pool, initial_idx, axis=0)
    y_pool = np.delete(y_pool, initial_idx, axis=0)

    # shuffling data
    X_initial, y_initial = shuffle(X_initial, y_initial)
    X_pool, y_pool = shuffle(X_pool, y_pool)
    X_test, y_test = shuffle(X_test, y_test)

    return X_initial, X_pool, X_test, y_initial, y_pool, y_test


def get_estimator(name):
    if name == 'rf':
        return RandomForestClassifier()
    elif name == 'gb':
        return GradientBoostingClassifier()
    elif name == 'lr':
        return LogisticRegression(penalty='none')
    elif name == 'svc':
        return SVC(probability=True)
    elif name == 'mlp':
        return MLPClassifier()


def get_query_strategy(name):
    if name == 'entropy-sampling':
        return entropy_sampling
    elif name == 'margin-sampling':
        return margin_sampling
    elif name == 'uncertainty-sampling':
        return uncertainty_sampling
