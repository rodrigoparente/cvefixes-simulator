# python imports
import os

# third-party imports
import configparser

# local imports
from .constants import ICONS_PATH
from .constants import DEFAULT_CONFIG
from .constants import CONFIG_FILE_STRUCTURE


def get_icon_path(icon):
    return os.path.abspath(f'{ICONS_PATH}/{icon}.png')


def create_config(dict_values):
    config = configparser.ConfigParser()
    config.optionxform = lambda option: option  # preserve case for letters

    def filter_keys(pair, keys):
        key, _ = pair
        return True if key in keys else False

    for section, values in CONFIG_FILE_STRUCTURE.items():
        config[section] = dict(filter(lambda pair: filter_keys(pair, values), dict_values.items()))

    filename = f"{dict_values['NetworkName']}.ini"

    with open(filename, 'w') as configfile:
        config.write(configfile)

    return filename


def filling_missing_values(dict_values):
    for key, value in DEFAULT_CONFIG.items():
        if key not in dict_values:
            dict_values.setdefault(key, value)
