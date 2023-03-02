# python imports
from ast import literal_eval
import os

# third-party imports
import configparser
import numpy as np

# local imports
from .constants import GENERATE_NETWORK
from .constants import ERROR_STATE


def start_state(env):

    # parsing config file for errors

    config = configparser.ConfigParser(inline_comment_prefixes='#')
    config.read(os.path.join(env['root_folder'], env['config_file']))

    errors = list()

    if 'NETWORK' not in config.sections():
        errors.append('NETWORK settings not available.')

    network = config['NETWORK']

    if not config.has_option('NETWORK', 'NetworkName'):
        errors.append('You must set a value for NetworkName')

    if config.has_option('NETWORK', 'NumberOfAssets'):
        if int(network['NumberOfAssets']) <= 0:
            errors.append('The number of assets must be greater then zero.')
    else:
        errors.append('You must set a value for NumberOfAssets')

    if config.has_option('NETWORK', 'NumberOfVulnerabilities'):
        if int(network['NumberOfVulnerabilities']) <= 0:
            errors.append('The number of vuln. must be greater then zero.')
    else:
        errors.append('You must set a value for NumberOfVulnerabilities')

    if config.has_option('NETWORK', 'VulnerabilitiesPublishedAfter'):
        if int(network['VulnerabilitiesPublishedAfter']) < 2016:
            errors.append('The vulnerabilities published year must be later than 2016.')
    else:
        errors.append('You must set a value for VulnerabilitiesPublishedAfter')

    if config.has_option('NETWORK', 'LowVulnDistribution'):
        if config.has_option('NETWORK', 'MediumVulnDistribution'):
            if config.has_option('NETWORK', 'HighVulnDistribution'):
                if config.has_option('NETWORK', 'CriticalVulnDistribution'):
                    if sum([float(network['LowVulnDistribution']),
                            float(network['MediumVulnDistribution']),
                            float(network['HighVulnDistribution']),
                            float(network['CriticalVulnDistribution'])]) > 1.0:
                        errors.append('Sum of vulnerability distributions must add up to 1.0.')
                else:
                    errors.append('You must set a value for CriticalVulnDistribution')
            else:
                errors.append('You must set a value for HighVulnDistribution')
        else:
            errors.append('You must set a value for MediumVulnDistribution')
    else:
        errors.append('You must set a value for LowVulnDistribution')

    if config.has_option('NETWORK', 'PercentageOfTopology'):
        if float(network['PercentageOfTopology']) > 1.0:
            errors.append('The amount of assets in DMZ must be at most 1.0.')
    else:
        errors.append('You must set a value for PercentageOfTopology')

    if config.has_option('NETWORK', 'PercentageOfType'):
        if float(network['PercentageOfType']) > 1.0:
            errors.append('The amount of assets in Server must be at most 1.0.')
    else:
        errors.append('You must set a value for PercentageOfType')

    if config.has_option('NETWORK', 'PercentageOfEnvironment'):
        if float(network['PercentageOfEnvironment']) > 1.0:
            errors.append('The amount of assets in Production must be at most 1.0.')
    else:
        errors.append('You must set a value for PercentageOfEnvironment')

    if config.has_option('NETWORK', 'PercentageOfSensitive'):
        if float(network['PercentageOfSensitive']) > 1.0:
            errors.append('The amount of assets in Sensitive Data must be at most 1.0.')
    else:
        errors.append('You must set a value for PercentageOfSensitive')

    if config.has_option('NETWORK', 'PercentageOfEndOfLife'):
        if float(network['PercentageOfEndOfLife']) > 1.0:
            errors.append('The amount of assets in End-of-life must be at most 1.0.')
    else:
        errors.append('You must set a value for PercentageOfEndOfLife')

    if config.has_option('NETWORK', 'PercentageOfCriticalAssets'):
        if float(network['PercentageOfCriticalAssets']) > 1.0:
            errors.append('The amount of assets in Critical Assets must be at most 1.0.')
    else:
        errors.append('You must set a value for PercentageOfCriticalAssets')

    if 'MODEL' not in config.sections():
        errors.append('MODEL settings not available.')

    model = config['MODEL']

    if config.has_option('MODEL', 'InitialSize'):
        if int(model['InitialSize']) <= 0:
            errors.append('The initial size must be greater then zero.')
    else:
        errors.append('You must set a value for InitialSize.')

    if config.has_option('MODEL', 'TestSize'):
        if int(model['TestSize']) <= 0:
            errors.append('The test size must be greater then zero.')
    else:
        errors.append('You must set a value for TestSize.')

    if config.has_option('MODEL', 'NumberOfQueries'):
        if int(model['NumberOfQueries']) <= 0:
            errors.append('The number of queries must be greater then zero.')
    else:
        errors.append('You must set a value for NumberOfQueries.')

    if not config.has_option('MODEL', 'ModelEstimator'):
        errors.append('You must set a value for ModelEstimator.')

    if not config.has_option('MODEL', 'EncodeData'):
        errors.append('You must set a value for EncodeData.')

    if not config.has_option('MODEL', 'QueryStrategy'):
        errors.append('You must set a value for QueryStrategy.')

    if not config.has_option('MODEL', 'RetrainModel'):
        errors.append('You must set a value for RetrainModel.')

    if 'GENERAL' not in config.sections():
        errors.append('GENERAL settings not available.')

    general = config['GENERAL']

    if config.has_option('GENERAL', 'NumberOfRepetitions'):
        if int(general['NumberOfRepetitions']) <= 0:
            errors.append('The number of repetitions must be greater then zero.')
    else:
        errors.append('You must set a value for NumberOfRepetitions.')

    if config.has_option('GENERAL', 'NumberOfVulnsFixedInRep'):
        if int(general['NumberOfVulnsFixedInRep']) <= 0:
            errors.append('The number of vulns fixed per iteration must be greater then zero.')
    else:
        errors.append('You must set a value for NumberOfVulnsFixedInRep')

    if config.has_option('GENERAL', 'NumberOfNewVulnsInRep'):
        if int(general['NumberOfNewVulnsInRep']) < 0:
            errors.append('The number of new vuln. per rep must be greater or equal to zero.')
    else:
        errors.append('You must set a value for NumberOfNewVulnsInRep')

    if not config.has_option('GENERAL', 'RandomSeed'):
        errors.append('You must set a random number to be used as seed of the simulation or None')

    if len(errors) > 0:
        env = {**env, 'errors': errors}
        return (ERROR_STATE, env)

    # building env file

    env = {
        **env,
        'rep': int(general['NumberOfRepetitions']),
        'current_rep': 1,
        'fix_vulns_per_rep': int(general['NumberOfVulnsFixedInRep']),
        'new_vulns_per_rep': int(general['NumberOfNewVulnsInRep']),
        'rng': np.random.default_rng(literal_eval(general['RandomSeed'])),
        'network_config': {
            'network_name': network['NetworkName'],
            'number_assets': int(network['NumberOfAssets']),
            'number_vulns': int(network['NumberOfVulnerabilities']),
            'published_after': int(network['VulnerabilitiesPublishedAfter']),
            'severity': {
                'low': float(network['LowVulnDistribution']),
                'medium': float(network['MediumVulnDistribution']),
                'high': float(network['HighVulnDistribution']),
                'critical': float(network['CriticalVulnDistribution']),
            },
            'context': {
                'topology': float(network['PercentageOfTopology']),
                'asset_type': float(network['PercentageOfType']),
                'environment': float(network['PercentageOfEnvironment']),
                'sensitive_data': float(network['PercentageOfSensitive']),
                'end_of_life': float(network['PercentageOfEndOfLife']),
                'critical_asset': float(network['PercentageOfCriticalAssets']),
            }
        },
        'model_config': {
            'initial_size': int(model['InitialSize']),
            'test_size': int(model['TestSize']),
            'number_queries': int(model['NumberOfQueries']),
            'estimator': model['ModelEstimator'],
            'encode_data': literal_eval(model['EncodeData']),
            'query_strategy': model['QueryStrategy'],
            'retrain_model': literal_eval(model['RetrainModel'])
        }
    }

    return (GENERATE_NETWORK, env)
