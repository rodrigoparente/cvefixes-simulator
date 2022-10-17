# python imports
import os

# third-party imports
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

from modAL.models import ActiveLearner

# project import
from commons.file import save_model
from commons.data import encode_data
from commons.classifiers import get_estimator
from commons.classifiers import get_query_strategy
from commons.classifiers import initial_pool_test_split

# local imports
from .constants import CLASSIFY_VULNERABILITY
from .constants import ERROR_STATE


def load_data(filepath):
    df = pd.read_csv(filepath)

    # droping unused columns
    df.drop(columns=[
        'cve_id', 'readable_cve_date', 'reference',
        'readable_exploit_date', 'audience_normalized'], inplace=True)

    # encoding dataset
    df = encode_data(df)

    df['label'].replace(
        {'LOW': 0, 'MODERATE': 1, 'IMPORTANT': 2, 'CRITICAL': 3}, inplace=True)

    X = df.drop(columns='label').to_numpy()
    y = df['label'].to_numpy()

    return X, y


def train_model(env):

    try:
        path = os.path.join(env['root_folder'], 'datasets/vulns-labelled.csv')
        X, y = load_data(path)
    except FileNotFoundError:
        env = {**env, 'errors': ['Labelled dataset not found.']}
        return (ERROR_STATE, env)

    config = env['model_config']

    X_initial, X_pool, X_test, y_initial, y_pool, y_test =\
        initial_pool_test_split(X, y, config['initial_size'], config['test_size'])

    if config['encode_data']:
        scaler = StandardScaler().fit(np.r_[X_initial, X_pool])
        X_initial = scaler.transform(X_initial)
        X_pool = scaler.transform(X_pool)
        X_test = scaler.transform(X_test)

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
    save_model(path, learner)

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
