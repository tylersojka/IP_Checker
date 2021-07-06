import PySimpleGUI as sg
import os
import time
import random
import json
import requests
import pandas as pd
import time

# Api key is stored in config.json file, as apikey. This simply opens the json file, then sets the key itself to the variable api_key for use later in the api calls

with open("config.json") as secret_file:
    secrets = json.load(secret_file)

VT_key = secrets["VTkey"]
Abuse_key = secrets["abusekey"]

ip_addys =["192.169.69.25","99.174.190.231"]

# function to take a list of IP addresses and run them through virustotal and return all of the information available for each as a seperate dictionary in the format of  {ip address : ip address info}
def VT_ipCheck(ip_addys):
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

def Abuse_ipCheck(ip_addys):
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

def comboCheckParse(ip_addys):

    for ip in ip_addys:
        vt_info = VT_ipCheck(ip_addys)
        abuse_info = Abuse_ipCheck(ip_addys)

        print(ip)
        print("Virus Total Data")
    
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
        
        return (
            f"{ip}\n"
            f"Virus Total Data\n"
            f"{malicious_count} Out of {engine_count} Security Vendors Flagged This IP As Malicious\n"
            f"Total Engines searched: {engine_count}\n"
            f"Number Of Security Vendors That Flagged This IP as Malicious: {malicious_count}\n"
            f"Number Of Security Vendors That Flagged This IP as Harmless: {harmless_count}\n"
            f"Security Vendors That Flagged As Malicious: {engine_list}\n"
            f"-------------------------------\n"

            f"Abuse IPDB Data\n"
            
            f"Number of Reports =  {str(abuse_info[ip]['data']['totalReports'])}\n"
            f"Abuse Confidence Score = {str(abuse_info[ip]['data']['abuseConfidenceScore'])}\n"
            f"Country = {abuse_info[ip]['data']['countryName']}\n"
            f"Country Code = {abuse_info[ip]['data']['countryCode']}\n"
            f"ISP =  + {abuse_info[ip]['data']['isp']}\n"
            f"Is Public? = {str(abuse_info[ip]['data']['isPublic'])}\n"
            f"-------------------------------\n"
            f"-------------------------------\n"
        )

var = (1,2,3,4)

sg.popup('This is a basic popup', 'I can have multiple item arguments', var)

while True:
    text = sg.popup_get_text('Enter IP to analyze!')
    if text is not None:
        output = comboCheckParse([text])
        sg.Print('Analysis:', output)
    elif text == "Exit":
        break

sg.popup_auto_close('Closing the program', background_color='red', text_color='white')
exit()