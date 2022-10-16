# python imports
import os
import pickle

# third-party imports
import pandas as pd
import numpy as np

from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier

from sklearn.preprocessing import StandardScaler
from sklearn_extra.cluster import KMedoids

from modAL.models import ActiveLearner
from modAL.uncertainty import margin_sampling
from modAL.uncertainty import entropy_sampling
from modAL.uncertainty import uncertainty_sampling

# local imports
from .constants import CLASSIFY_VULNERABILITY
from .constants import ERROR_STATE
from .constants import RISK_MAP
from .utils import transform_data


def load_data(filepath):
    df = pd.read_csv(filepath)

    # droping unused columns
    df.drop(columns=[
        'cve_id', 'readable_cve_date', 'reference',
        'readable_exploit_date', 'audience_normalized'], inplace=True)

    # encoding dataset
    df = transform_data(df)

    df['label'].replace(RISK_MAP, inplace=True)

    X = df.drop(columns='label').to_numpy()
    y = df['label'].to_numpy()

    return X, y


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


def train_model(env):
    try:
        path = os.path.join(env['root_folder'], 'datasets/vulns-labelled.csv')
        X, y = load_data(path)
    except FileNotFoundError:
        env = {**env, 'errors': ['Lablled dataset not found.']}
        return (ERROR_STATE, env)

    config = env['model_config']

    X_initial, X_pool, X_test, y_initial, y_pool, y_test =\
        initial_pool_test_split(X, y, config['initial_size'], config['test_size'])

    learner = ActiveLearner(estimator=get_estimator(config['estimator']),
                            query_strategy=get_query_strategy(config['query_strategy']),
                            X_training=X_initial, y_training=y_initial)

    for _ in range(config['number_queries']):

        query_idx, query_inst = learner.query(X_pool)

        learner.teach(query_inst.reshape(1, -1), y_pool[query_idx])

        X_pool = np.delete(X_pool, query_idx, axis=0)
        y_pool = np.delete(y_pool, query_idx, axis=0)

    y_pred = learner.predict(X_test)

    # TODO: calibrate the model

    path = os.path.join(env['root_folder'], 'output/', 'model.pickle')
    pickle.dump(learner, open(path, 'wb'), protocol=pickle.HIGHEST_PROTOCOL)

    env = {
        **env,
        'model': {
            'learner': path,
            'score': learner.score(X_test, y_test),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted')
        }
    }

    return (CLASSIFY_VULNERABILITY, env)
