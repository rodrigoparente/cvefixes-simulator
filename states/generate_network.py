# python imports
import os

# third-party imports
import copy
import numpy as np
import pandas as pd

# local imports
from .constants import TRAIN_MODEL
from .constants import ERROR_STATE
from .constants import CONTEXT_MAP


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


def generate_assets(env, number_assets, context_values):

    # loading config values from env

    rng = env['rng']

    # generating assets

    assets = dict()

    for index in range(number_assets):
        assets.setdefault(f'ASSET-{index}', {})

    # assigning context to assets

    for context, value in context_values.items():
        positive = rng.choice(list(assets.keys()), size=round(number_assets * value))

        for asset in assets.keys():
            option = 1 if asset in positive else 0
            assets[asset].setdefault(context, CONTEXT_MAP[context][option])

    return assets


def generate_vulnerabilities(env, assets, n_vulns):

    # loading config values from env

    root_folder = env['root_folder']
    rng = env['rng']

    network_config = env['network_config']
    published_after = network_config['published_after']
    vulns_dist = network_config['severity']

    # loading vulnerabilities dataset

    data = None

    try:
        path = os.path.join(root_folder, 'datasets/vulns.csv')
        data = load_data(path, published_after)
    except FileNotFoundError:
        raise FileNotFoundError('Vulnerability dataset not found.')

    # randomly selecting vulnerabilities

    vulns = list()

    for severity, value in vulns_dist.items():
        filtered_vulns = data.loc[data['base_severity'] == severity.upper()]

        selected_vulns_cves = rng.choice(
            filtered_vulns['cve_id'].tolist(), size=round(n_vulns * value), replace=False)

        selected_vulns = filtered_vulns.loc[
            filtered_vulns['cve_id'].isin(selected_vulns_cves)].to_dict(orient='records')

        vulns.extend(selected_vulns)

    # randomly selecting the assets to assing the new vulnerabilities

    asset_ids = list(rng.choice(list(assets.keys()), size=len(vulns)))

    # assigning vulnerabilities to the selected assets

    vulns_list = list()

    for vuln, asset_id in zip(vulns, asset_ids):
        vulns_list.append({
            **vuln,
            **extra_info(vuln['cve_id']),
            'asset_id': asset_id,
            **assets[asset_id]
        })

    return vulns_list


def extra_info(cve_id):
    # TODO: retrieve google trend and twitter values

    extra = {
        'google_trend': np.nan,
        'google_interest': 0.0,
    }

    return extra


def generate_network(env):

    assets = dict()

    cvss_vulnerabilities = list()
    frape_vulnerabilities = list()

    if env['current_rep'] > 1:

        assets = env['assets']
        cvss_vulnerabilities = env['cvss_vulnerabilities']
        frape_vulnerabilities = env['frape_vulnerabilities']

        if env['new_vulns_per_rep'] > 0:

            # generating assets vulnerabilities

            try:
                n_vulns = env['new_vulns_per_rep']
                vulns = generate_vulnerabilities(env, assets, n_vulns)

                cvss_vulnerabilities.extend(vulns)
                frape_vulnerabilities.extend(vulns)
            except FileNotFoundError:
                env = {**env, 'errors': ['Vulnerability dataset not found.']}
                return (ERROR_STATE, env)
    else:

        network_config = env['network_config']

        # generating network assets

        n_assets = network_config['number_assets']
        ctx_values = network_config['context']

        assets = generate_assets(env, n_assets, ctx_values)

        # generating assets vulnerabilities

        try:
            n_vulns = network_config['number_vulns']
            vulns = generate_vulnerabilities(env, assets, n_vulns)

            cvss_vulnerabilities = copy.deepcopy(vulns)
            frape_vulnerabilities = copy.deepcopy(vulns)
        except FileNotFoundError:
            env = {**env, 'errors': ['Vulnerability dataset not found.']}
            return (ERROR_STATE, env)

    env = {
        **env,
        'assets': assets,
        'cvss_vulnerabilities': cvss_vulnerabilities,
        'frape_vulnerabilities': frape_vulnerabilities
    }

    return (TRAIN_MODEL, env)
