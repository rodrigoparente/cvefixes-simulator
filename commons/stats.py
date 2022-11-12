# third-party imports
import pandas as pd
import numpy as np


def get_attack_value(df, attack_name):
    value = df.loc[
        ~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: attack_name in x).sum()
    if isinstance(value, np.int64):
        return value.item()
    return value


def get_data_value(df, column):
    dates = (pd.to_datetime('today') - pd.to_datetime(df[column])).dt.days
    if len(dates) > 0:
        return sum(dates) / len(dates)
    return 0


def get_mean_value(df, column):
    if df[column].sum() > 0:
        return df[column].sum() / df.shape[0]
    return 0


def get_stats(df):

    return {
        'base_score': get_mean_value(df, 'base_score'),
        'cve_published_date': get_data_value(df, 'cve_published_date'),
        'exploit_count': df.loc[~df['exploit_count'].isnull(), 'exploit_count'].shape[0],
        'exploit_published_date': get_data_value(df, 'exploit_published_date'),
        'epss': get_mean_value(df, 'epss'),
        'topology': df.loc[df['topology'] == 'DMZ'].shape[0],
        'asset_type': df.loc[df['asset_type'] == 'SERVER'].shape[0],
        'environment': df.loc[df['environment'] == 'PRODUCTION'].shape[0],
        'sensitive_data': df.loc[df['sensitive_data'] == 1].shape[0],
        'end_of_life': df.loc[df['end_of_life'] == 1].shape[0],
        'critical_asset': df.loc[df['critical_asset'] == 1].shape[0],
        'attack_type_arbitrary_code_execution': get_attack_value(df, 'arbitrary code execution'),
        'attack_type_defense_in_depth': get_attack_value(df, 'defense in depth'),
        'attack_type_denial_of_service': get_attack_value(df, 'denial of service'),
        'attack_type_elevation_of_privilege': get_attack_value(df, 'elevation of privilege'),
        'attack_type_information_disclosure': get_attack_value(df, 'information disclosure'),
        'attack_type_memory_leak': get_attack_value(df, 'memory leak'),
        'attack_type_none': get_attack_value(df, 'none'),
        'attack_type_proof_of_concepts': get_attack_value(df, 'proof-of-concepts'),
        'attack_type_remote_code_execution': get_attack_value(df, 'remote code execution'),
        'attack_type_security_feature_bypass': get_attack_value(df, 'security feature bypass'),
        'attack_type_spoofing': get_attack_value(df, 'spoofing'),
        'attack_type_sql_injection': get_attack_value(df, 'sql injection'),
        'attack_type_tampering': get_attack_value(df, 'tampering'),
        'attack_type_xss': get_attack_value(df, 'xss'),
        'attack_type_zero_day': get_attack_value(df, 'zero-day'),
        'availability_impact_high': df.loc[df['availability_impact'] == 'HIGH'].shape[0],
        'availability_impact_low': df.loc[df['availability_impact'] == 'LOW'].shape[0],
        'availability_impact_none': df.loc[df['availability_impact'] == 'NONE'].shape[0],
        'confidentiality_impact_high': df.loc[df['confidentiality_impact'] == 'HIGH'].shape[0],
        'confidentiality_impact_low': df.loc[df['confidentiality_impact'] == 'LOW'].shape[0],
        'confidentiality_impact_none': df.loc[df['confidentiality_impact'] == 'NONE'].shape[0],
        'integrity_impact_high': df.loc[df['integrity_impact'] == 'HIGH'].shape[0],
        'integrity_impact_low': df.loc[df['integrity_impact'] == 'LOW'].shape[0],
        'integrity_impact_none': df.loc[df['integrity_impact'] == 'NONE'].shape[0],
        'part_application': df.loc[df['part'] == 'application'].shape[0],
        'part_hardware': df.loc[df['part'] == 'hardware'].shape[0],
        'part_operating_system': df.loc[df['part'] == 'operating_system'].shape[0],
        'vendor_adobe': df.loc[df['vendor'] == 'adobe'].shape[0],
        'vendor_apple': df.loc[df['vendor'] == 'apple'].shape[0],
        'vendor_cisco': df.loc[df['vendor'] == 'cisco'].shape[0],
        'vendor_debian': df.loc[df['vendor'] == 'debian'].shape[0],
        'vendor_google': df.loc[df['vendor'] == 'google'].shape[0],
        'vendor_ibm': df.loc[df['vendor'] == 'ibm'].shape[0],
        'vendor_linux': df.loc[df['vendor'] == 'linux'].shape[0],
        'vendor_microsoft': df.loc[df['vendor'] == 'microsoft'].shape[0],
        'vendor_oracle': df.loc[df['vendor'] == 'oracle'].shape[0],
        'vendor_other': df.loc[df['vendor'] == 'other'].shape[0],
        'vendor_redhat': df.loc[df['vendor'] == 'redhat'].shape[0],
        'mitre_top_25': df.loc[df['mitre_top_25'] == 1].shape[0],
        'owasp_top_10': df.loc[df['owasp_top_10'] == 1].shape[0],
        'security_advisory': df.loc[df['security_advisory'] == 1].shape[0],
        'audience': get_mean_value(df, 'audience'),
        'google_interest': get_mean_value(df, 'google_interest'),
        'google_trend_decreasing': df.loc[df['google_trend'] == 'decreasing'].shape[0],
        'google_trend_increasing': df.loc[df['google_trend'] == 'increasing'].shape[0],
        'google_trend_none': df.loc[df['google_trend'] == 'none'].shape[0],
        'google_trend_steady': df.loc[df['google_trend'] == 'steady'].shape[0]
    }
