# local imports
from .constants import END_STATE


def error_state(env):
    print("# Error(s) ocurred...")

    for error in env['errors']:
        print(f'  - {error}')

    return (END_STATE, env)
