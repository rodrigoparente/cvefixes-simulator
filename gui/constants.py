ICONS_PATH = 'gui/icons'

DEFAULT_CONFIG = {
    'NetworkName': 'Network1',
    'IndependentRuns': '30',
    'RandomSeed': '42',
    'NumberOfAssets': '300',
    'NumberOfVulnerabilities': '3000',
    'VulnerabilitiesPublishedAfter': '2019',
    'LowVulnDistribution': '0.02',
    'MediumVulnDistribution': '0.41',
    'HighVulnDistribution': '0.42',
    'CriticalVulnDistribution': '0.15',
    'PercentageOfTopology': '0.1',
    'PercentageOfType': '0.35',
    'PercentageOfEnvironment': '0.6',
    'PercentageOfSensitive': '0.3',
    'PercentageOfEndOfLife': '0.15',
    'PercentageOfCriticalAssets': '0.1',
    'InitialSize': '20',
    'TestSize': '40',
    'NumberOfQueries': '100',
    'ModelEstimator': 'gb',
    'QueryStrategy': 'uncertainty-sampling',
    'EncodeData': '0',
    'RetrainModel': '0',
    'NumberOfRepetitions': '99',
    'NumberOfVulnsFixedInRep': '30',
    'NumberOfNewVulnsInRep': '0'
}

CONFIG_FILE_STRUCTURE = {
    'NETWORK': [
        'NetworkName',
        'NumberOfAssets',
        'NumberOfVulnerabilities',
        'VulnerabilitiesPublishedAfter',
        'LowVulnDistribution',
        'MediumVulnDistribution',
        'HighVulnDistribution',
        'CriticalVulnDistribution',
        'PercentageOfTopology',
        'PercentageOfType',
        'PercentageOfEnvironment',
        'PercentageOfSensitive',
        'PercentageOfEndOfLife',
        'PercentageOfCriticalAssets'
    ],
    'MODEL': [
        'InitialSize',
        'TestSize',
        'NumberOfQueries',
        'ModelEstimator',
        'EncodeData',
        'QueryStrategy',
        'RetrainModel'
    ],
    'GENERAL': [
        'NumberOfRepetitions',
        'NumberOfVulnsFixedInRep',
        'NumberOfNewVulnsInRep'
    ]
}
