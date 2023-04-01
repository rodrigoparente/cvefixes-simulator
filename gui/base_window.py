# third-party imports
import tkinter as tk
from tkinter import ttk
from tktooltip import ToolTip

# local imports
from .utils import get_icon_path


class BaseWindow():
    def __init__(self, title='', geometry='', icon=''):

        self.entries = dict()
        self.input_values = dict()

        # start tk

        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry(geometry)

        icon_32 = tk.PhotoImage(file=get_icon_path(icon))
        self.root.iconphoto(True, icon_32)

        # add the label to the progressbar style

        self.style = ttk.Style(self.root)
        self.style.layout('LabeledProgressbar', [
            ('LabeledProgressbar.trough', {
                'children': [
                    ('LabeledProgressbar.pbar', {'side': 'left', 'sticky': 'ns'}),
                    ('LabeledProgressbar.label', {'sticky': ''})
                ], 'sticky': 'nswe'
            })
        ])

        self.draw_window()

        self.root.mainloop()

    def change_visibility(self, frame, state='normal'):
        for child in frame.winfo_children():
            if child.widgetName in ['toplevel', 'frame', 'labelframe']:
                self.change_visibility(child, state)
            elif child.widgetName in ['label', 'entry', 'button', 'radiobutton']:
                child.configure(state=state)

    def update_inputs(self):
        for name, entry in self.entries.items():
            if entry.winfo_exists():
                self.input_values[name] = entry.get()

    def draw_window(self):
        pass

    def draw_frame(self, parent, name=None):
        frame = tk.LabelFrame(parent, text=name, font=('Helvetica', '16', 'bold'), padx=5, pady=5)
        frame.pack(fill='x', padx=5, pady=5)
        return frame

    def draw_label(self, parent, text, description=None):
        labelFrame = tk.Frame(parent)
        labelFrame.pack(fill='both')

        label = tk.Label(labelFrame, text=text, anchor=tk.W)
        label.pack(side=tk.LEFT)

        if description:
            icon = tk.PhotoImage(file=get_icon_path('info'))
            labelIcon = tk.Label(labelFrame, image=icon, compound='center')
            labelIcon.pack(side=tk.LEFT)
            labelIcon.image = icon  # keeping reference to avoid a tkinter bug
            ToolTip(labelIcon, msg=description)

    def draw_input(self, parent, name, text, default, description=None):

        value = default
        if name in self.input_values:
            value = self.input_values[name]

        variable = tk.StringVar()
        variable.set(value)

        self.draw_label(parent, text, description)
        entry = tk.Entry(parent, textvariable=variable)
        entry.pack(fill='x')

        self.entries[name] = entry
        self.input_values[name] = variable.get()

    def draw_radio(self, parent, name, text, options, description=None):

        self.draw_label(parent, text, description)

        value = 0
        if name in self.input_values:
            value = self.input_values[name]

        radioFrame = tk.Frame(parent)
        radioFrame.pack(fill='both')

        variable = tk.StringVar()
        variable.set(value)

        def selected():
            self.input_values[name] = variable.get()

        for index, option in enumerate(options):
            radio = tk.Radiobutton(
                radioFrame, text=option, variable=variable,
                value=index, command=selected)
            radio.pack(side=tk.LEFT, anchor=tk.N + tk.W)

        self.input_values.setdefault(name, variable.get())

    def draw_button(self, parent, name, callback, icon=None, pack=tk.BOTTOM):
        btn = tk.Button(parent, text=name, command=callback)
        btn.pack(side=pack, fill='x', expand='true')

        if icon:
            icon = tk.PhotoImage(file=get_icon_path(icon))
            btn.configure(image=icon, compound=tk.LEFT)
            btn.image = icon  # keeping reference to avoid a tkinter bug

    def draw_progressbar(self, parent):
        pb = ttk.Progressbar(
            parent, length=100, orient='horizontal', mode='determinate', style='LabeledProgressbar')
        pb.pack(fill='x')

        # change the text of the progressbar the trailing
        # spaces are here to properly center the text
        self.style.configure('LabeledProgressbar', text='0 %      ')

        return pb
