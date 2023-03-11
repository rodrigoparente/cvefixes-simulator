# python imports
import os
import json
import pickle


def check_output_path(path):
    # check and create folder it doesn't exists
    dirs = os.path.split(path)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)


def save_json(path, env):
    check_output_path(path)

    with open(path, 'w') as file:
        file.write(json.dumps(env, indent=4))


def save_pickle_obj(path, model):
    check_output_path(path)

    with open(path, 'wb') as file:
        pickle.dump(model, file, protocol=pickle.HIGHEST_PROTOCOL)


def load_pickle_obj(path):
    if not os.path.exists(path):
        return None

    with open(path, 'rb') as file:
        learner = pickle.load(file)

    return learner
