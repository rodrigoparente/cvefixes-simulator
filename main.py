# python imports
import os
import sys

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

    if len(sys.argv) < 2:
        exit('the program expects the config file name.')

    fsm = FSM()

    fsm.add_state(START_STATE, start_state, start_state=True)
    fsm.add_state(GENERATE_NETWORK, generate_network)
    fsm.add_state(TRAIN_MODEL, train_model)
    fsm.add_state(CLASSIFY_VULNERABILITY, classify_vulnerability)
    fsm.add_state(PRIORITIZE_VULNERABILITY, prioritize_vulnerability)
    fsm.add_state(FIX_VULNERABILITY, fix_vulnerability)
    fsm.add_state(ERROR_STATE, error_state, error_state=True)
    fsm.add_state(END_STATE, None, end_state=True)

    config_path = os.path.join(os.getcwd(), sys.argv[1])

    fsm.run(config_path)
