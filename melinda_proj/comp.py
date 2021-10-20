full_list = [
"84.255.184.75",
"188.247.77.135",
"193.176.86.100",
"46.32.125.15",
"151.236.165.56",
"140.82.181.174",
"188.247.75.174",
"84.255.184.98",
"46.32.122.233",
"84.255.185.189",
"46.185.168.160",
"46.32.122.141",
"84.255.185.148",
"188.247.79.5",
"188.247.78.173",
"46.32.126.97",
"188.70.7.13",
"213.139.53.7",
"102.176.65.37",
"188.70.9.19",
"148.252.133.100",
"37.237.250.18",
"123.231.104.213",
"188.247.73.67",
"46.32.127.238",
"84.255.184.232",
"188.247.76.157",
"188.247.74.22",
"84.255.184.51",
"46.32.127.99",
"188.247.76.181",
"212.34.11.149",
"148.252.132.228",
"213.139.62.223",
"46.185.169.156",
"188.70.42.252",
"188.247.75.207",
"37.237.250.11",
"212.34.19.122",
"149.200.255.116",
"84.255.184.126",
"212.34.30.58",
"213.139.59.205",
"46.32.127.105",
"185.69.144.226",
"212.34.12.150",
"84.255.184.225",
"188.247.77.198",
"102.176.65.85",
"188.247.73.114",
"84.255.184.141",
"84.255.184.28",
"68.60.214.2",
"84.255.185.57",
"84.255.184.37",
"86.108.33.165",
"175.157.47.194",
"151.236.174.234",
"84.255.185.108",
"102.176.65.152",
"188.247.75.244",
"46.32.122.70",
"188.247.78.48",
"188.247.78.168",
"212.34.12.243",
"188.247.74.229",
"149.200.190.242",
"188.247.78.59",
"46.32.123.76",
"67.44.208.95",
"188.247.74.56"]

malware_ips = [
"84.255.184.75",
"193.176.86.100",
"46.32.125.15",
"84.255.184.98",
"46.32.122.233",
"84.255.185.189",
"46.185.168.160",
"84.255.185.148",
"188.247.79.5",
"188.247.78.173",
"102.176.65.37",
"188.70.9.19",
"37.237.250.18",
"84.255.184.232",
"188.247.76.157",
"84.255.184.51",
"46.32.127.99",
"188.247.76.181",
"188.247.75.207",
"37.237.250.11",
"84.255.184.126",
"212.34.30.58",
"213.139.59.205",
"46.32.127.105",
"84.255.184.225",
"188.247.73.114",
"84.255.185.57",
"84.255.185.108",
"102.176.65.152",
"188.247.75.244",
"188.247.78.168",
"188.247.78.59"]

def Diff(li1, li2):
    return list(set(li1) - set(li2)) + list(set(li2) - set(li1))
 
print(Diff(full_list, malware_ips))