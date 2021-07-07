import PySimpleGUI as sg
import os.path
from pathlib import Path

def popup_text(filename, text):

    layout = [
        [sg.Multiline(text, size=(80, 25)),],
    ]
    win = sg.Window(filename, layout, modal=True, finalize=True)

file_list_column = [
    [
        sg.Text("IP List"),
        sg.In(size=(25,1), enable_events=True, key="-INPUT-"),
        sg.FileBrowse(file_types=(("TXT Files", "*.txt"), ("ALL Files", "*.*"))),
        sg.Button("Open"),
    ],

    [
    sg.Listbox(
        values= [], enable_events=True, size=(40,20),
        key="-FILE LIST-"
    )
    ],
]
image_viewer_column = [
    [sg.Text("Choose a file from the list on the left:")],
    [sg.Text(size=(40,1), key="-TOUT-")],
    [sg.Image(key="IMAGE")],
]

layout = [
    [
        sg.Column(file_list_column),
        sg.VSeperator(),
        sg.Column(image_viewer_column),
    ]
]

window = sg.Window("IP Checker", layout)

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED:
        break
    elif event == 'Open':
        filename = values['-INPUT-']
        if Path(filename).is_file():
            try:
                with open(filename, encoding='utf-8') as f:
                    text = f.read()
                # popup_text(filename, text)
                window["-FILE LIST-"].update(text)
            except Exception as e:
                print("Error: ", e)

window.close()