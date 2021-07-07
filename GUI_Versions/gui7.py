

from tkinter import Event
import PySimpleGUI as sg
import csv
from PySimpleGUI.PySimpleGUI import easy_print
import json
import requests


# function to take a list of IP addresses and run them through virustotal and return all of the information available for each as a seperate dictionary in the format of  {ip address : ip address info}
def VT_ipCheck(ip_addys, VT_key):
    # defining the headers using my personal api key in a separate doc- all we need is the api key
    headers = {"x-apikey" : VT_key}
    # base api URL
    url = "https://www.virustotal.com/api/v3/ip_addresses/"

    # defining a dictionary to hold all of the info for each IP
    VT_dick_list = {}
    for ip in ip_addys:
        # build the request for each IP in the ip_addys list and get the response as json data
        ip_info = requests.get(url + ip, headers=headers).json()
        #format the entries to display as {ip address : ip address info}
        VT_dick_list["{0}".format(ip)] = ip_info

    return VT_dick_list

def Abuse_ipCheck(ip_addys, Abuse_key):
    url = 'https://api.abuseipdb.com/api/v2/check'

    headers = {
    'Accept': 'application/json',
    'Key': Abuse_key
    }
    abuse_dick_list = {}
    for ip in ip_addys:
        querystring = {'ipAddress': ip,
                        'maxAgeInDays': '365',
                        'verbose': "True"}
        
        ip_info = requests.request(method='GET', url=url, headers=headers, params=querystring).json()

        abuse_dick_list["{0}".format(ip)] = ip_info
        
    return abuse_dick_list

def comboCheckParse(ip_addys, vtkey, abusekey):
    vt_info = VT_ipCheck(ip_addys, vtkey)
    abuse_info = Abuse_ipCheck(ip_addys, abusekey)
    for ip in ip_addys:
        
        engine_count = 0
        malicious_count = 0
        undetected_count = 0
        harmless_count = 0 
        engine_list =[]
        for engine in vt_info[ip]["data"]["attributes"]["last_analysis_results"]:
            engine_count += 1
            if vt_info[ip]["data"]["attributes"]["last_analysis_results"][engine]["category"] == "malicious":
                malicious_count += 1
                engine_list.append({"Vendor": vt_info[ip]["data"]["attributes"]["last_analysis_results"][engine]["engine_name"], "Reason":vt_info[ip]["data"]["attributes"]["last_analysis_results"][engine]["result"]})
                
            elif vt_info[ip]["data"]["attributes"]["last_analysis_results"][engine]["category"] == "undetected":
                undetected_count += 1

            elif vt_info[ip]["data"]["attributes"]["last_analysis_results"][engine]["category"] == "harmless":
                harmless_count += 1

        
        print("Virus Total Data")
        print(ip)
        print(f"{malicious_count} Out of {engine_count} Security Vendors Flagged This IP As Malicious")
        print(f"Total Engines searched: {engine_count}")
        print(f"Number Of Security Vendors That Flagged This IP as Malicious: {malicious_count}")
        print(f"Number Of Security Vendors That Flagged This IP as Harmless: {harmless_count}")
        print(f"Security Vendors That Flagged As Malicious: {engine_list}")
        print("-------------------------------")

        print("Abuse IPDB Data")
        print(ip)
        print("Number of Reports = " + str(abuse_info[ip]["data"]['totalReports']))
        print("Abuse Confidence Score = " + str(abuse_info[ip]["data"]["abuseConfidenceScore"]))
        print("Country = " + abuse_info[ip]["data"]['countryName'])
        print("Country Code= " + abuse_info[ip]["data"]['countryCode'])
        print("ISP = " + abuse_info[ip]["data"]['isp'])
        print("Is Public? = " + str(abuse_info[ip]["data"]['isPublic']))
        print("-------------------------------")
        print("-------------------------------")






sg.SetOptions(background_color = 'LightBlue',
              element_background_color = 'LightBlue')
                     
def ipList():

    filename = sg.PopupGetFile('Get required file', no_window = True,file_types=(("CSV Files","*.csv"),("TXT Files", "*.txt")))
    
    #initialise variable
    data = []

    #read file
    if filename.endswith('.csv'): 
        with open(filename, "r") as infile:     
            reader = csv.reader(infile)
            for i in range (1):                 
                #get headings
                header = next(reader)
                #read everything else into a list of rows
                data = list(reader) 
                flat_data = [item for l in data for item in l]    
                # data = reader  
                window["-IP LIST-"].update(flat_data)      
    elif filename.endswith('.txt'):
        with open(filename, "r") as infile:     
            reader = csv.reader(infile)
            data = list(reader)
            flat_data = [item for l in data for item in l]
            # data = reader       
            window["-IP LIST-"].update(flat_data)   

def getKeys():
    filename = sg.PopupGetFile('Get required file', no_window = True, file_types=(("JSON Files", "*.json"),))

    with open(filename) as secret_file:
        secrets = json.load(secret_file)

    VT_key = secrets["VTkey"]
    Abuse_key = secrets["abusekey"]

    window['-VTKEY-'].update(VT_key)
    window['-ABUSEKEY-'].update(Abuse_key)
    


api_key_input = [
    [
    sg.Text("VirusTotal API Key"),
    sg.In(default_text ="", size=(25,1), enable_events=True, key="-VTKEY-"),
    sg.Text("VirusTotal API Key"),
    sg.In(default_text ="", size=(25,1), enable_events=True, key="-ABUSEKEY-"),
    sg.Button("Import Keys")
    ]
]


ip_list_column = [
    [
        sg.ReadButton('Load File', font = ('Arial', 14, 'bold'), size = (15,1)),
        sg.ReadButton('Run Analysis', font = ('Arial', 14, 'bold'), size = (15,1)),
    ],

    [
        sg.Listbox(
            values = '', enable_events=True, size=(40,20),
            key="-IP LIST-"
            )
    ],
]

image_viewer_column = [
    [sg.Text("Your Analysis Will Show Here")],
    
    [sg.Output(key="-analysis-", size=(80,20))],
]

layout = [
    [
        api_key_input,
        sg.Column(ip_list_column),
        sg.VSeperator(),
        sg.Column(image_viewer_column),
        sg.Button("Print")
    ]
]



window = sg.Window('Load File', resizable=False, location = (500,250)).Layout(layout)

while True:
    Event, value = window.Read()
    if Event == sg.WINDOW_CLOSED:
        break
    # if button is not None:
    if Event == 'Load File':
        ipList()
        ips = window["-IP LIST-"].get_list_values()

    if Event == "Import Keys":
        getKeys()
        vtkey = window["-VTKEY-"].get()
        abusekey = window["-ABUSEKEY-"].get()


    if Event == "Run Analysis":
        if window["-IP LIST-"].get_list_values() and window["-VTKEY-"].get() and window["-ABUSEKEY-"].get() is not None:
        
            output = comboCheckParse(ips, vtkey, abusekey)
        
            window["-analysis-"].update(output)
        
        else:
            sg.popup("PLEASE MAKE SURE YOUR KEYS ARE UPLOADED AND A LIST OF IPs HAS BEEN UPLOADED") 

    if Event == "Print":
        easy_print(ips)