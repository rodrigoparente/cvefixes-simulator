# python imports
import os
import random

# third-party imports
import pandas as pd
import numpy as np

# local imports
from .constants import TRAIN_MODEL
from .constants import ERROR_STATE


def load_data(path, published_year):
    data = pd.read_csv(path, low_memory=False)

    # converting date columns to datetime object
    data['cve_published_date'] =\
        pd.to_datetime(data['cve_published_date'], format='%Y-%m-%d')

    # filtering vulns based in published_date and cvss_type
    data = data.loc[
        (data['cve_published_date'].dt.year > published_year) & (data['cvss_type'] == 3.0)]

    # converting date to string
    data['cve_published_date'] = data['cve_published_date'].astype(str)

    # rename update_available to security advisory
    data.rename(columns={'update_available': 'security_advisory'}, inplace=True)

    # creating a column called base_severity
    conditions = [
        ((data['base_score'] <= 3.9)),
        ((data['base_score'] >= 4.0) & (data['base_score'] <= 6.9)),
        ((data['base_score'] >= 7.0) & (data['base_score'] <= 8.9)),
        ((data['base_score'] >= 9.0))
    ]

    choices = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    data['base_severity'] = np.select(conditions, choices, default='OTHER')
    data['base_severity'] = pd.Categorical(data.base_severity, categories=choices, ordered=True)

    # filtering columns
    return data[[
        'cve_id', 'part', 'vendor', 'base_score', 'base_severity', 'confidentiality_impact',
        'integrity_impact', 'availability_impact', 'cve_published_date', 'security_advisory',
        'mitre_top_25', 'owasp_top_10', 'exploit_count', 'epss', 'exploit_published_date',
        'attack_type', 'audience'
    ]]


def get_context(context, option):
    context_map = {
        'topology': ('LOCAL', 'DMZ'),
        'asset_type': ('WORKSTATION', 'SERVER'),
        'environment': ('DEVELOPMENT', 'PRODUCTION'),
        'sensitive_data': (0, 1),
        'end_of_life': (0, 1),
        'critical_asset': (0, 1)
    }

    return context_map[context][option]


def add_ctx(assets, asset, vulns, selected_vulns):
    for vuln in selected_vulns:

        # TODO: retrieve google trend values

        vulns.append({
            **vuln,
            'google_trend': np.nan,
            'google_interest': 0.0,
            'asset_id': asset,
            **assets[asset]['context']
        })


def generate_network(env):

    config = env['network_config']

    try:
        path = os.path.join(env['root_folder'], 'datasets/vulns.csv')
        data = load_data(path, config['published_after'])
    except FileNotFoundError:
        env = {**env, 'errors': ['Vulnerability dataset not found.']}
        return (ERROR_STATE, env)

    assets = dict()
    vulns = list()

    for index in range(config['number_assets']):
        assets.setdefault(f'ASSET-{index}', {
            'context': {},
            'vulnerabilities': []
        })

    # assigning context to assets
    for context, value in config['context'].items():
        positive = random.sample(list(assets.keys()), int(config['number_assets'] * value))

        for asset in assets.keys():
            option = 1 if asset in positive else 0
            assets[asset]['context'].setdefault(context, get_context(context, option))

    # assigning vulnerabilities to assets
    for asset in assets.keys():
        amount_of_vulns = random.randrange(
            config['min_vuln_per_asset'], config['max_vuln_per_asset'])

        assets[asset]['amount_of_vulns'] = amount_of_vulns
        vulns_left = amount_of_vulns

        for severity, value in config['severity'].items():

            selected_vulns = data.loc[data['base_severity'] == severity.upper()]\
                .sample(n=int(amount_of_vulns * value)).to_dict(orient='records')

            if len(selected_vulns) > 0:
                vulns_left -= len(selected_vulns)

            add_ctx(assets, asset, vulns, selected_vulns)

        if vulns_left > 0:
            severity = random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
            selected_vulns = data.loc[data['base_severity'] == severity]\
                .sample(n=vulns_left).to_dict(orient='records')

            add_ctx(assets, asset, vulns, selected_vulns)

    env = {
        **env,
        'number_of_vulns': len(vulns),
        'vulnerabilities': vulns
    }

    return (TRAIN_MODEL, env)
