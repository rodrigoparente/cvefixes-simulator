# python imports
import os
from datetime import datetime

# project imports
from commons.file import save_json


class FSM:
    def __init__(self):
        self.handlers = dict()
        self.start_state = None
        self.end_states = None
        self.error_state = None

    def add_state(self, name, handler, start_state=False, end_state=False, error_state=False):
        name = name.upper()

        if name in self.handlers.keys():
            return print("State already registered.")
        if start_state and self.start_state is not None:
            return print("You can't have more than one start state.")
        if start_state and end_state:
            return print("An state can't be simultaneously an start and end state.")

        self.handlers.setdefault(name, handler)

        if start_state:
            self.start_state = name
        if end_state:
            self.end_states = name
        if error_state:
            self.error_state = name

    def run(self, config, rng):

        if self.start_state is None:
            return print("You must add an start state.")

        if self.end_states is None:
            return print("You must add an end state.")

        handler = self.handlers[self.start_state]

        head, tail = os.path.split(config)
        env = {
            'root_folder': head,
            'config_file': tail,
            'rng': rng
        }

        while True:
            (new_state, env) = handler(env)

            if new_state in self.end_states:

                # deleting saved model and scaler

                os.remove(env['model']['learner'])
                os.remove(env['model']['scaler'])

                # cleaning unused env fields

                del env['rng']
                del env['current_rep']
                del env['model']['learner']
                del env['model']['scaler']

                # saving env to disk

                network_name = env['network_config']['network_name']
                filename = f"environment-{datetime.now().strftime('%Y-%m-%d--%H-%M-%S')}.json"

                path = os.path.join(env['root_folder'], "output", network_name, filename)
                save_json(path, env)

                break

            handler = self.handlers[new_state]
