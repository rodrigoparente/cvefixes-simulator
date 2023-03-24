# python imports
import os
from ast import literal_eval

# third-party imports
import argparse
import numpy as np

# project imports
from states import start_state
from states import generate_network
from states import train_model
from states import classify_vulnerability
from states import prioritize_vulnerability
from states import fix_vulnerability
from states import error_state

from states.constants import START_STATE
from states.constants import GENERATE_NETWORK
from states.constants import TRAIN_MODEL
from states.constants import CLASSIFY_VULNERABILITY
from states.constants import PRIORITIZE_VULNERABILITY
from states.constants import FIX_VULNERABILITY
from states.constants import END_STATE
from states.constants import ERROR_STATE

# local imports
from fsm import FSM


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Security-Based Simulator for Vulnerabilities Fix')

    parser.add_argument('-r', '--rep', dest='rep',
                        required=True, action='store', type=int,
                        help='Number of repetitions of the simulation')

    parser.add_argument('-c', '--config', dest='config',
                        required=True, action='store',
                        help='Configuration file path')

    parser.add_argument('-s', '--seed', dest='seed',
                        default=None, action='store',
                        help='Seed used to initialize the rng')

    args = parser.parse_args()

    rng = np.random.default_rng(literal_eval(args.seed))

    for iter in range(1, args.rep + 1):

        print(f'{iter}/{args.rep}')

        fsm = FSM()

        fsm.add_state(START_STATE, start_state, start_state=True)
        fsm.add_state(GENERATE_NETWORK, generate_network)
        fsm.add_state(TRAIN_MODEL, train_model)
        fsm.add_state(CLASSIFY_VULNERABILITY, classify_vulnerability)
        fsm.add_state(PRIORITIZE_VULNERABILITY, prioritize_vulnerability)
        fsm.add_state(FIX_VULNERABILITY, fix_vulnerability)
        fsm.add_state(ERROR_STATE, error_state, error_state=True)
        fsm.add_state(END_STATE, None, end_state=True)

        config_path = os.path.join(os.getcwd(), args.config)

        fsm.run(config_path, rng)

        # cleaning console
        os.system('clear')

    print('Done!')
