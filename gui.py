# python imports
import os
from ast import literal_eval

# third-party imports
import numpy as np

import tkinter as tk
from tkinter import messagebox

# project imports
from fsm import FSM

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

from gui import BaseWindow

from gui.utils import create_config
from gui.utils import filling_missing_values


class MainWindow(BaseWindow):
    def __init__(self, title, geometry, icon):
        BaseWindow.__init__(self, title, geometry, icon)

    def draw_window(self):
        configFrame = self.draw_frame(self.root, 'Configuration')

        self.draw_input(configFrame, 'NetworkName', 'Simulation Name', 'Network1',
                        description='The name of the network')

        self.draw_input(configFrame, 'IndependentRuns', 'Independent Test Runs', '30',
                        description='Number of independent test runs')

        self.draw_input(configFrame, 'RandomSeed', 'Random Seed', '42',
                        description='A random number to be used as seed of the simulation')

        self.draw_button(configFrame,
                         name='Config',
                         icon='gear',
                         callback=lambda: self.config_window(configFrame),
                         pack=tk.RIGHT)

        self.draw_button(configFrame,
                         name='Save',
                         icon='save',
                         callback=self.update_inputs,
                         pack=tk.RIGHT)

        statusFrame = self.draw_frame(self.root, 'Status')
        pb = self.draw_progressbar(statusFrame)

        controlsFrame = self.draw_frame(self.root)

        self.draw_button(parent=controlsFrame,
                         name='Cancel',
                         icon='close',
                         callback=self.root.destroy,
                         pack=tk.RIGHT)

        self.draw_button(parent=controlsFrame,
                         name='Start',
                         icon='run',
                         callback=lambda: self.run_simulation(pb, configFrame),
                         pack=tk.RIGHT)

    def config_window(self, parent):

        window = tk.Toplevel(parent)
        window.title('Configuration Menu')

        networkFrame = self.draw_frame(window, 'Network')

        firstCol = tk.Frame(networkFrame, padx=5)
        firstCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(firstCol, 'NumberOfAssets', 'Number of Assets', '300',
                        description='Number of assets in the generated network')
        self.draw_input(firstCol, 'NumberOfVulnerabilities', 'Number of Vulns.', '3000',
                        description='The amount of vulnerabilities in the network')
        self.draw_input(firstCol, 'VulnerabilitiesPublishedAfter', 'Vulns. Published After', '2019',
                        description='Select only vulnerabilities published after this date')

        secondCol = tk.Frame(networkFrame, padx=5)
        secondCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(secondCol, 'LowVulnDistribution', 'Low Vuln. Dist.', '0.02',
                        description='Percentage of LOW vulnerabilities.')
        self.draw_input(secondCol, 'MediumVulnDistribution', 'Medium Vuln. Dist.', '0.41',
                        description='Percentage of MEDIUM vulnerabilities.')
        self.draw_input(secondCol, 'HighVulnDistribution', 'High Vuln. Dist.', '0.42',
                        description='Percentage of HIGH vulnerabilities.')
        self.draw_input(secondCol, 'CriticalVulnDistribution', 'Critical Vuln. Dist.', '0.15',
                        description='Percentage of CRITICAL vulnerabilities.')

        thirdCol = tk.Frame(networkFrame, padx=5)
        thirdCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(thirdCol, 'PercentageOfTopology', 'Topology Dist.', '0.1',
                        description='Percentage of Assets in the DMZ')
        self.draw_input(thirdCol, 'PercentageOfType', 'Asset Type Dist.', '0.35',
                        description='Percentage of Assets that are SERVER')
        self.draw_input(thirdCol, 'PercentageOfEnvironment', 'Enviroment Dist.', '0.60',
                        description='Percentage of Assets that are of PRODUCTION')
        self.draw_input(thirdCol, 'PercentageOfSensitive', 'Sensitive Asset Dist.', '0.30',
                        description='Percentage of Assets that\n hold sensitive information')
        self.draw_input(thirdCol, 'PercentageOfEndOfLife', 'End-of-Life Asset Dist.', '0.15',
                        description='Percentage of Assets that no longer receive update')
        self.draw_input(thirdCol, 'PercentageOfCriticalAssets', 'Critical Asset Dist.', '0.1',
                        description='Percentage of Assets consider \n'
                                    'critical (e.g. Active Diretories)')

        modelFrame = self.draw_frame(window, 'Model')

        firstCol = tk.Frame(modelFrame, padx=5)
        firstCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(firstCol, 'InitialSize', 'Initial Size', '20',
                        description='Number of entries in the X_initial array')
        self.draw_input(firstCol, 'TestSize', 'Test Size', '40',
                        description='Number of entries in the X_test array')
        self.draw_input(firstCol, 'NumberOfQueries', 'Number of Queries', '100',
                        description='Number of queries executed by the active learning')

        secondCol = tk.Frame(modelFrame, padx=5)
        secondCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(secondCol, 'ModelEstimator', 'Model Estimator', 'gb',
                        description='Machine learning classifier\n'
                                    'Options: rf | gb | lr | svc | mlp')
        self.draw_input(secondCol, 'QueryStrategy', 'Query Strategy', 'uncertainty-sampling',
                        description='Active learning query strategy\n'
                                    'Options: entropy-sampling | uncertainty-sampling')

        thirdCol = tk.Frame(modelFrame, padx=5)
        thirdCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_radio(thirdCol, 'EncodeData', 'Encode Data', ['False', 'True'],
                        description='True if data should be\n normalized, False otherwise')
        self.draw_radio(thirdCol, 'RetrainModel', 'Retrain Model', ['False', 'True'],
                        description='True if the ML model should be retrain\n in each repetition,'
                                    ' False otherwise')

        generalFrame = self.draw_frame(window, 'General')

        firstCol = tk.Frame(generalFrame, padx=5)
        firstCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(firstCol, 'NumberOfRepetitions', 'Repetitions', '99',
                        description='Number of repetitions run by the simulator')

        secondCol = tk.Frame(generalFrame, padx=5)
        secondCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(secondCol, 'NumberOfVulnsFixedInRep', 'Number of Vulns. Fixed', '30',
                        description='Number of vulnerabilities fixed in each repetition')

        thirdCol = tk.Frame(generalFrame, padx=5)
        thirdCol.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.draw_input(thirdCol, 'NumberOfNewVulnsInRep', 'Number of New Vulns.', '0',
                        description='Number of new vulnerabilities in each repetition')

        self.draw_button(window,
                         name='Close',
                         icon='close',
                         callback=window.destroy,
                         pack=tk.RIGHT)

        self.draw_button(window,
                         name='Save',
                         icon='save',
                         callback=self.update_inputs,
                         pack=tk.RIGHT)

    def run_simulation(self, pb, configFrame):

        filling_missing_values(self.input_values)

        rep = literal_eval(self.input_values['IndependentRuns'])
        rng = np.random.default_rng(literal_eval(self.input_values['RandomSeed']))

        # disabling inputs

        self.change_visibility(configFrame, 'disable')

        for iter in range(1, rep + 1):

            # running simulation

            fsm = FSM()

            fsm.add_state(START_STATE, start_state, start_state=True)
            fsm.add_state(GENERATE_NETWORK, generate_network)
            fsm.add_state(TRAIN_MODEL, train_model)
            fsm.add_state(CLASSIFY_VULNERABILITY, classify_vulnerability)
            fsm.add_state(PRIORITIZE_VULNERABILITY, prioritize_vulnerability)
            fsm.add_state(FIX_VULNERABILITY, fix_vulnerability)
            fsm.add_state(ERROR_STATE, error_state, error_state=True)
            fsm.add_state(END_STATE, None, end_state=True)

            config = create_config(self.input_values)
            config_path = os.path.join(os.getcwd(), config)

            fsm.run(config_path, rng)

            # updating progress bar

            i = int(iter * 100 / rep)

            pb['value'] = i
            self.style.configure('LabeledProgressbar', text=f'{i} %      ')
            self.root.update()

        messagebox.showinfo('CVEFixes Simulator', 'Simulation completed!')

        # reseting progressbar

        pb['value'] = 0
        self.style.configure('LabeledProgressbar', text=f'{0} %     ')
        self.root.update()

        # enabling inputs

        self.change_visibility(configFrame, 'normal')


if __name__ == '__main__':
    main = MainWindow(
        title='CVEFixes Simulator', geometry='265x330', icon='frappe')
