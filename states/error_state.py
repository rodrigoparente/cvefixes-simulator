# local imports
from .constants import END_STATE


def error_state(env):
    print(f"# An error ocurred in {env['path'][-2]}")
    print('# Errors:')

    for error in env['errors']:
        print(f'  - {error}')

    return (END_STATE, env)
