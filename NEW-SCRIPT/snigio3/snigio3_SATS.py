# SATS/LT1 Sniffer online and offline
# Version 3.2.3
# DHL Express Italy 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com

import sys
import argparse
from multiprocessing import Process
import os
import sys

# SNIGIO IMPORT

from SNIGIO.ONLINE import *
from SNIGIO.OFFLINE import *
import SNIGIO.my_global as var_g

#############################################################
#                          ARGS                             #
#############################################################
#############################################################


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--SedeDHL", help="The location site name. Default is SNIFF-TEST", default="SNIFF-TEST")
    parser.add_argument("--mode", help="The usage of the sniffer MODE: ON is live capture and OFF is for pcap file", default="ON")
    parser.add_argument("--MQDEBUG", help="enable or disable MQ Debug (print information in a terminal). Default is NO, YES for activate the mode", default="NO")
    parser.add_argument("--cli_debug", help="enable or disable CLI Debug (print information in a terminal). Default is NO, YES for activate the mode", default="NO")
    parser.add_argument("--filter", help="The BPF style filter to sniff with. Example: \"192.168.1.1\". \"host 192.168.1.1 AND port 22\". Please use port to filter SATS/LT1 and NCY network \"port 1415 or port 7007\" ", default="tcp")
    parser.add_argument("--iface", help="Set up the ethernet/wifi sniffing interface. Default is eno1", default="eno1")
    parser.add_argument("--su", help="Add sudo command if needed, defualt no, else type Y", default="NO")
    parser.add_argument("--alive_time", type=int, help="Alive time checks and message. Default is 30 seconds", default=30)
    parser.add_argument("--path_PCAP_R", help="Select folder wher reard pcap file (Offline). Default is /opt/capture-test/", default="/opt/capture-test/")
    parser.add_argument("--Log_PATH", help="Log path for SNIGIO to be read with NXLOG. Default is /var/log/SNIGIO3/snigio3.log", default="/var/log/SNIGIO3/snigio3.log")
    parser.add_argument("--path_PCAP_W", help="PCAP path whre captured packets are stored", default="/home/capture/")
    parser.add_argument("--Type", type=str, help="Sniffer environment type, default SATS, LT1 for Light Tier 1", default="SATS")
    return parser.parse_args()

#############################################################
#                         DECLARATION                       #
#############################################################
#############################################################

# Import configurations arguments and sets builtins variables
args = get_args()

# SedeDHL
var_g.SedeDHL = str(args.SedeDHL)

var_g.ENV_TYPE = args.Type
var_g.MODE = str(args.mode)
var_g.MQDEBUG = str(args.MQDEBUG)
sudo = str(args.su)
# Define variable for SIGTERM
var_g.CLI_DEBUG = str(args.cli_debug)
var_g.PATH_PCAP_R = str(args.path_PCAP_R)
var_g.PATH_PCAP_W = str(args.path_PCAP_W)
var_g.LOG_PATH = str(args.Log_PATH)
# Alive time for checks
var_g.alive_time = args.alive_time
# TSHARK Filter and variables
TFILTER = str(args.filter)
IFACE = str(args.iface)

#############################################################
#                    CHECK CONFIGFURATION                   #
#############################################################
#############################################################

if var_g.ENV_TYPE == 'SATS' or var_g.ENV_TYPE == 'LT1':     #Verificare perchè != non funziona
    print('var_g.ENV_TYPE is good: ' + var_g.ENV_TYPE)
else:
    sys.exit("Please, use SATS or LT1 as Type environment argument, default SATS")

if var_g.MODE == "ON" or var_g.MODE == "OFF":
    print('var_g.MODE is good: ' + var_g.MODE)
else:
    sys.exit("Please, use ON or OFF as MODE environment argument, default ON")

if var_g.MQDEBUG == "NO" or var_g.MQDEBUG == "YES":
    print('MQDEBUG is good: ' + var_g.MQDEBUG)
else:
    sys.exit("Please, use NO or YES as MQDEBUG environment argument, default NO")

if sudo == "Y":
    sudo = 'sudo '
elif sudo == "NO":
    sudo = ""
else:
    sys.exit("Please, use NO or Y as SU environment argument, default NO") 

#############################################################
#                      TSHARK COMMAND                       #
#############################################################
#############################################################

if var_g.MODE == "ON":
    if var_g.ENV_TYPE == 'SATS':
        filt = ' -f ' + "'" + TFILTER + "'" + " -o data.show_as_text:TRUE"
        iface = '-i ' + IFACE
        capture_location = ' -w ' + var_g.PATH_PCAP_W + var_g.SedeDHL + ".pcap"  
        fields = capture_location + ' -b filesize:102400 -b files:250 -B 100 -T fields -e mq.tsh.type -e tcp.flags -e tcp.payload -e ip.src -e data.text -e ip.dst -e frame.time'
    else:
        filt = ' -f ' + "'" + TFILTER + "'"
        iface = '-i ' + IFACE
        capture_location = ' -w ' + var_g.PATH_PCAP_W + var_g.SedeDHL + ".pcap"
        fields = capture_location + ' -b filesize:102400 -b files:250 -B 100 -T fields -e frame.time -e mq -e mq.tsh.type -e ip.src -e ip.dst -e data'
    var_g.command = sudo + 'tshark ' + iface + filt + fields
else:
    fields = '-T fields -e mq.tsh.type -e tcp.flags -e tcp.payload -e ip.src -e data -e ip.dst'
    var_g.command = str(sudo + 'ls ' + var_g.PATH_PCAP_R + ' | grep ' + "'" + '\.pcap$' + "'" + ' | while read f; do (tshark -r ' + var_g.PATH_PCAP_R + '$f -o data.show_as_text:TRUE ' + fields + '); done')

############################################################
#                      START SNIFFER                        #
#############################################################
#############################################################

if __name__ == "__main__":

    if var_g.MODE == "ON":
        SNIGIO.ONLINE.start_LIVE()
    else:
        SNIGIO.OFFLINE.start_READ()