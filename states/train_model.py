# python imports
import os

# third-party imports
import pandas as pd
import numpy as np

from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import KFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

from modAL.models import ActiveLearner

import shap

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
    features = df.drop(columns='label').columns.tolist()

    df['label'].replace(
        {'LOW': 0, 'MODERATE': 1, 'IMPORTANT': 2, 'CRITICAL': 3}, inplace=True)

    X = df.drop(columns='label').to_numpy()
    y = df['label'].to_numpy()

    return X, y, features


def get_feature_importances(learner, X, feature_names):
    feature_importances = pd.Series(dtype='float64')

    occurrences = 0

    for cls in learner.calibrated_classifiers_:

        explainer = shap.Explainer(cls.base_estimator.predict, X, feature_names=feature_names)
        shap_values = pd.DataFrame(explainer(X).values, columns=feature_names)

        feature_values = np.abs(shap_values.values).mean(0)
        importances = pd.Series(feature_values, index=feature_names)

        occurrences += 1

        if not feature_importances.empty:
            feature_importances += importances
        else:
            feature_importances = importances

    feature_importances /= occurrences
    return feature_importances


def train_model(env):

    try:
        path = os.path.join(env['root_folder'], 'datasets/vulns-labelled.csv')
        X, y, feature_names = load_data(path)
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

    X_selected = X_initial.copy()
    y_selected = y_initial.copy()

    base_stimator = get_estimator(config['estimator'])
    query_strategy = get_query_strategy(config['query_strategy'])

    for _ in range(config['number_queries']):
        try:
            calibrated = CalibratedClassifierCV(base_stimator, method='isotonic', cv=5)
            calibrated.fit(X_selected, y_selected)
        except ValueError:
            try:
                kfold = KFold(n_splits=2).split(X_selected)
                calibrated = CalibratedClassifierCV(base_stimator, method='isotonic', cv=kfold)
                calibrated.fit(X_selected, y_selected)
            except ValueError:
                env = {**env, 'errors': ['Not enough samples to perform cross-validation.']}
                return (ERROR_STATE, env)

        learner = ActiveLearner(calibrated, query_strategy)

        query_idx, query_inst = learner.query(X_pool)

        X_selected = np.append(X_selected, query_inst, axis=0)
        y_selected = np.append(y_selected, y_pool[query_idx], axis=0)

        X_pool = np.delete(X_pool, query_idx, axis=0)
        y_pool = np.delete(y_pool, query_idx, axis=0)

    calibrated = CalibratedClassifierCV(base_stimator, method='isotonic', cv=5)
    calibrated.fit(X_selected, y_selected)

    y_pred = calibrated.predict(X_test)

    network_name = env['network_config']['network_name']
    path = os.path.join(env['root_folder'], 'output', network_name, 'model.pickle')
    save_model(path, calibrated)

    feature_importances = get_feature_importances(calibrated, X_selected, feature_names)

    env = {
        **env,
        'feature_importances': feature_importances.to_dict(),
        'model': {
            'learner': path,
            'accuracy': calibrated.score(X_test, y_test),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted')
        }
    }

    return (CLASSIFY_VULNERABILITY, env)
