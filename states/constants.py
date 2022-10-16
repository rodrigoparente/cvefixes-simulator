START_STATE = 'START_STATE'
GENERATE_NETWORK = 'GENERATE_NETWORK'
TRAIN_MODEL = 'TRAIN_MODEL'
CLASSIFY_VULNERABILITY = 'CLASSIFY_VULNERABILITY'
FIX_VULNERABILITY = 'FIX_VULNERABILITY'
END_STATE = 'END_STATE'
ERROR_STATE = 'ERROR_STATE'


CONTEXT_MAP = {
    'topology': ('LOCAL', 'DMZ'),
    'asset_type': ('WORKSTATION', 'SERVER'),
    'environment': ('DEVELOPMENT', 'PRODUCTION'),
    'sensitive_data': (0, 1),
    'end_of_life': (0, 1),
    'critical_asset': (0, 1)
}

RISK_MAP = {'LOW': 0, 'MODERATE': 1, 'IMPORTANT': 2, 'CRITICAL': 3}
RISK_LABELS = ['LOW', 'MODERATE', 'IMPORTANT', 'CRITICAL']
