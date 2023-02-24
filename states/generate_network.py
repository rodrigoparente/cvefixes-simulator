# python imports
import os
from collections import Counter

# third-party imports
import copy
import numpy as np
import pandas as pd

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


def generate_assets(number_assets, context_values):

    # generating assets

    assets = dict()

    for index in range(number_assets):
        assets.setdefault(f'ASSET-{index}', {})

    # assigning context to assets

    context_map = {
        'topology': ('LOCAL', 'DMZ'),
        'asset_type': ('WORKSTATION', 'SERVER'),
        'environment': ('DEVELOPMENT', 'PRODUCTION'),
        'sensitive_data': (0, 1),
        'end_of_life': (0, 1),
        'critical_asset': (0, 1)
    }

    for context, value in context_values.items():
        positive = np.random.choice(list(assets.keys()), int(number_assets * value))

        for asset in assets.keys():
            option = 1 if asset in positive else 0
            assets[asset].setdefault(context, context_map[context][option])

    return assets


def assigning_vulnerabilities(assets, vulns_map, vulns, max_vulns_per_asset):

    selected_vulns = copy.deepcopy(vulns)
    len_selected_vulns = len(selected_vulns)

    for asset_id, context in assets:

        counter = Counter(item['asset_id'] for item in vulns_map)
        amount_of_vulns_in_asset = counter[asset_id]

        amount_of_selected_vulns = max_vulns_per_asset - amount_of_vulns_in_asset

        if amount_of_selected_vulns > len_selected_vulns:
            amount_of_selected_vulns = len_selected_vulns

        while amount_of_selected_vulns > 0:
            vuln = selected_vulns.pop()

            vulns_map.append({
                **vuln,
                **extra_info(vuln['cve_id']),
                'asset_id': asset_id,
                **context
            })

            amount_of_selected_vulns -= 1
            len_selected_vulns -= 1

        # when all vulns are
        # attributed break the loop
        if len_selected_vulns == 0:
            break


def extra_info(cve_id):
    # TODO: retrieve google trend and twitter values

    extra = {
        'google_trend': np.nan,
        'google_interest': 0.0,
    }

    return extra


def generate_network(env):

    network_config = env['network_config']

    assets = dict()
    cvss_vulnerabilities = list()
    frape_vulnerabilities = list()

    if env['current_rep'] > 1:
        assets = env['assets']

        new_vulns_per_rep = env['new_vulns_per_rep']
        vulns_per_asset = network_config['vuln_per_asset']

        cvss_vulnerabilities = env['cvss_vulnerabilities']
        frape_vulnerabilities = env['frape_vulnerabilities']

        if new_vulns_per_rep > 0:

            try:
                path = os.path.join(env['root_folder'], 'datasets/vulns.csv')
                data = load_data(path, network_config['published_after'])
            except FileNotFoundError:
                env = {**env, 'errors': ['Vulnerability dataset not found.']}
                return (ERROR_STATE, env)

            # selecting vulnerabilities
            selected_vulns = data.sample(n=new_vulns_per_rep).to_dict(orient='records')

            # shuffling assets to make sure that
            # new vulnerabilities appears at random
            shuffled_assets = list(assets.items())
            np.random.shuffle(shuffled_assets)

            # assigning vulnerabilities to assets
            for vuln_map in [cvss_vulnerabilities, frape_vulnerabilities]:
                assigning_vulnerabilities(
                    shuffled_assets, vuln_map, selected_vulns, vulns_per_asset)
    else:

        try:
            path = os.path.join(env['root_folder'], 'datasets/vulns.csv')
            data = load_data(path, network_config['published_after'])
        except FileNotFoundError:
            env = {**env, 'errors': ['Vulnerability dataset not found.']}
            return (ERROR_STATE, env)

        number_assets = network_config['number_assets']
        context_values = network_config['context']
        vulns_per_asset = network_config['vuln_per_asset']

        selected_vulns = list()

        # generating network assets
        assets = generate_assets(number_assets, context_values)

        # assigning vulnerabilities to assets
        for asset_id, context in assets.items():
            vulns_left = vulns_per_asset

            asset_vulns = list()

            for severity, value in network_config['severity'].items():
                vulns = data.loc[data['base_severity'] == severity.upper()]\
                    .sample(n=int(vulns_per_asset * value)).to_dict(orient='records')

                if len(vulns) > 0:
                    vulns_left -= len(vulns)
                    asset_vulns.extend(vulns)

            severity_index = 0
            severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

            while vulns_left > 0:
                vulns =\
                    data.loc[data['base_severity'] == severities[severity_index]]\
                        .sample(n=1).to_dict(orient='records')

                vulns_left -= 1
                asset_vulns.extend(vulns)

                severity_index = 0 if severity_index == 3 else severity_index + 1

            for vuln in asset_vulns:
                selected_vulns.append({
                    **vuln,
                    **extra_info(vuln['cve_id']),
                    'asset_id': asset_id,
                    **context
                })

        cvss_vulnerabilities = copy.deepcopy(selected_vulns)
        frape_vulnerabilities = copy.deepcopy(selected_vulns)

    env = {
        **env,
        'assets': assets,
        'number_of_cvss_vulns': len(cvss_vulnerabilities),
        'number_of_frape_vulns': len(frape_vulnerabilities),
        'cvss_vulnerabilities': cvss_vulnerabilities,
        'frape_vulnerabilities': frape_vulnerabilities
    }

    return (TRAIN_MODEL, env)
