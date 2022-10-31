# python imports
from ast import literal_eval

# third-party imports
import pandas as pd
import numpy as np

from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import MultiLabelBinarizer


def encode_data(data):
    # replacing space with underscore in part column
    data['part'].replace(' ', '_', regex=True, inplace=True)

    # casting dates to days
    columns = ['cve_published_date', 'exploit_published_date']
    for column in columns:
        data[column] =\
            (pd.to_datetime('today') - pd.to_datetime(data[column])).dt.days

        # replacing nan with 0
        data.loc[data[column].isnull(), column] = 0
        data[column] = data[column].astype(int)

    # replacing nan values in exploit
    # and audience columns to 0
    columns = ['exploit_count', 'audience']
    for column in columns:
        data.loc[data[column].isnull(), column] = 0
        data[column] = data[column].astype(int)

    # replacing nan values in epss column
    data.loc[data['epss'].isnull(), 'epss'] = 0.0

    # replacing nan values in google_trend column
    data.loc[data['google_trend'].isnull(), 'google_trend'] = 'none'

    # casting upper values to lower
    columns =\
        ['confidentiality_impact', 'integrity_impact', 'availability_impact',
         'google_trend', 'topology', 'asset_type', 'environment']
    for column in columns:
        data[column] = data[column].str.lower()

    # replacing attack_type space with underscore
    data['attack_type'].replace(', ', ',', regex=True, inplace=True)
    data['attack_type'].replace('-', '_', regex=True, inplace=True)
    data['attack_type'].replace(' ', '_', regex=True, inplace=True)

    # replacing attack_type nan value
    data.loc[data['attack_type'].isnull(), 'attack_type'] = "['none']"

    # casting attack_type string to array
    data['attack_type'] = data['attack_type'].apply(literal_eval)

    # manually encoding columns value
    data['topology'].replace({'local': 0, 'dmz': 1}, inplace=True)
    data['asset_type'].replace({'workstation': 0, 'server': 1}, inplace=True)
    data['environment'].replace({'development': 0, 'production': 1}, inplace=True)

    # one-hot-encoding data
    ohe = OneHotEncoder(sparse=False, dtype=int)

    columns = ['part', 'vendor', 'confidentiality_impact',
               'integrity_impact', 'availability_impact', 'google_trend']

    encoder_vars_array = ohe.fit_transform(data[columns])

    # create object for the feature names using the categorical variables
    encoder_feature_names = ohe.get_feature_names_out(columns)

    # create a dataframe to hold the one hot encoded variables
    encoder_vars_df = pd.DataFrame(encoder_vars_array, columns=encoder_feature_names)

    # adding possible missing features
    ohe_features = [
        'part_application', 'part_hardware', 'part_operating_system',
        'vendor_adobe', 'vendor_apple', 'vendor_cisco', 'vendor_debian',
        'vendor_google', 'vendor_ibm', 'vendor_linux', 'vendor_microsoft',
        'vendor_oracle', 'vendor_other', 'vendor_redhat',
        'confidentiality_impact_high', 'confidentiality_impact_low',
        'confidentiality_impact_none', 'integrity_impact_high',
        'integrity_impact_low', 'integrity_impact_none',
        'availability_impact_high', 'availability_impact_low',
        'availability_impact_none', 'google_trend_decreasing',
        'google_trend_increasing', 'google_trend_none',
        'google_trend_steady']

    missing_ohe_features = list(set(ohe_features).difference(encoder_feature_names))

    n_rows = data.shape[0]
    df_dict = dict()

    for column in missing_ohe_features:
        df_dict.setdefault(column, np.zeros(n_rows, dtype=int))

    # concatenate the new dataframe back to the original input variables dataframe
    data = pd.concat([
        data.reset_index(drop=True),
        encoder_vars_df.reset_index(drop=True),
        pd.DataFrame(df_dict).reset_index(drop=True)], axis=1)

    # drop the original columns
    data.drop(columns, axis=1, inplace=True)

    # multi-hot-encoding
    mlb = MultiLabelBinarizer()
    mlb.fit(data['attack_type'])

    # creating new columns name
    new_col_names = [f'attack_type_{name}' for name in mlb.classes_]

    # create new dataFrame with transformed/one-hot encoded
    attacks = pd.DataFrame(mlb.fit_transform(data['attack_type']), columns=new_col_names)

    # concat encoded data with original dataframe
    data = pd.concat([data.reset_index(drop=True), attacks.reset_index(drop=True)], axis=1)

    # drop the original column
    data.drop('attack_type', axis=1, inplace=True)

    # adding possible missing attack types
    types_of_attack =\
        ['none', 'remote_code_execution', 'arbitrary_code_execution', 'tampering',
         'denial_of_service', 'spoofing', 'defense_in_depth', 'elevation_of_privilege',
         'security_feature_bypass', 'information_disclosure', 'xss', 'memory_leak',
         'sql_injection', 'zero_day', 'proof_of_concepts']

    # creating new columns
    missing_attack_types = list(set(types_of_attack).difference(mlb.classes_))
    missing_columns = [f'attack_type_{name}' for name in missing_attack_types]

    n_rows = data.shape[0]
    df_dict = dict()

    # prep data
    for column in missing_columns:
        df_dict.setdefault(column, np.zeros(n_rows, dtype=int))

    # concatenating to original dataset
    data = pd.concat(
        [data.reset_index(drop=True), pd.DataFrame(df_dict).reset_index(drop=True)], axis=1)

    # sorting columns
    data = data.reindex(sorted(data.columns), axis=1)

    return data


def get_stats(df):

    cve_published_dates =\
        (pd.to_datetime('today') - pd.to_datetime(df['cve_published_date'])).dt.days

    exploitable = df.loc[~df['exploit_published_date'].isnull()]
    exploit_published_dates =\
        (pd.to_datetime('today') - pd.to_datetime(exploitable['exploit_published_date'])).dt.days

    return {
        'base_score': df['base_score'].sum() / df.shape[0],
        'cve_published_date': sum(cve_published_dates) / len(cve_published_dates),
        'exploit_count': df.loc[~df['exploit_count'].isnull(), 'exploit_count'].shape[0],
        'exploit_published_date': sum(exploit_published_dates) / len(exploit_published_dates),
        'epss': df['epss'].max(),
        'topology': df.loc[df['topology'] == 'DMZ'].shape[0],
        'asset_type': df.loc[df['asset_type'] == 'SERVER'].shape[0],
        'environment': df.loc[df['environment'] == 'PRODUCTION'].shape[0],
        'sensitive_data': df.loc[df['sensitive_data'] == 1].shape[0],
        'end_of_life': df.loc[df['end_of_life'] == 1].shape[0],
        'critical_asset': df.loc[df['critical_asset'] == 1].shape[0],
        'attack_type_arbitrary_code_execution': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'arbitrary code execution' in x).sum().item(),  # noqa E501
        'attack_type_defense_in_depth': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'defense in depth' in x).sum().item(),  # noqa E501
        'attack_type_denial_of_service': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'denial of service' in x).sum().item(),  # noqa E501
        'attack_type_elevation_of_privilege': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'elevation of privilege' in x).sum().item(),  # noqa E501
        'attack_type_information_disclosure': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'information disclosure' in x).sum().item(),  # noqa E501
        'attack_type_memory_leak': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'memory leak' in x).sum().item(),  # noqa E501
        'attack_type_none': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'none' in x).sum().item(),  # noqa E501
        'attack_type_proof_of_concepts': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'proof-of-concepts' in x).sum().item(),  # noqa E501
        'attack_type_remote_code_execution': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'remote code execution' in x).sum().item(),  # noqa E501
        'attack_type_security_feature_bypass': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'security feature bypass' in x).sum().item(),  # noqa E501
        'attack_type_spoofing': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'spoofing' in x).sum().item(),  # noqa E501
        'attack_type_sql_injection': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'sql injection' in x).sum().item(),  # noqa E501
        'attack_type_tampering': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'tampering' in x).sum().item(),  # noqa E501
        'attack_type_xss': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'xss' in x).sum().item(),  # noqa E501
        'attack_type_zero_day': df.loc[~df['attack_type'].isnull(), 'attack_type'].apply(lambda x: 'zero-day' in x).sum().item(),  # noqa E501
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
        'audience': df['audience'].sum() / df.shape[0],
        'google_interest': df['google_interest'].sum() / df.shape[0],
        'google_trend_decreasing': df.loc[df['google_trend'] == 'decreasing'].shape[0],
        'google_trend_increasing': df.loc[df['google_trend'] == 'increasing'].shape[0],
        'google_trend_none': df.loc[df['google_trend'] == 'none'].shape[0],
        'google_trend_steady': df.loc[df['google_trend'] == 'steady'].shape[0]
    }
