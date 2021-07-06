import PySimpleGUI as sg
import csv

# Show CSV data in Table
sg.theme('Dark Red')

def table_example():
    filename = sg.popup_get_file('filename to open', no_window=False, file_types=(("CSV Files","*.csv"),))
    # --- populate table with file contents --- #
    if filename == '':
        return
    data = []
    header_list = []
    button = sg.popup_yes_no('Is this the list of IPs you want to open?')
    if filename is not None:
        with open(filename, "r") as infile:
            reader = csv.reader(infile)
            if button == 'No':
                header_list = next(reader)
            try:
                data = list(reader)  # read everything else into a list of rows
                if button == 'Yes':
                    header_list = ['column' + str(x) for x in range(len(data[0]))]
            except:
                sg.popup_error('Error reading file')
                return
    sg.set_options(element_padding=(0, 0))

    layout = [[sg.Listbox(values=data,
                            s = (50,50),
                            size=(50,50),
                            )]]


    window = sg.Window('Table', layout, grab_anywhere=False)
    event, values = window.read()

    window.close()

table_example()