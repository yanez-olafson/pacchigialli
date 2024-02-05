# MESSAGE LOGGER CLASS for SNIGIO3, a SATS/LT1 Sniffer 
# Version 3.0.1
# DHL Express Italy S.r.l. - 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com

import argparse, sys, logging, time, signal, json, re
from datetime import datetime as dt

#############################################################
#############################################################

#Logger init
load = ''
MQTYPE = ''
SedeDHL = ''
logger = ''
 
#############################################################
#                        CLASS FOR                          #
#                       MESSAGE LOG                         #
#############################################################
#############################################################

class messages:
         
    def gray_logger_SATS(load, Frame_Time, MQTYPE, logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug('\"Frame_time:%s\" - \"MQTYPE:%s\" - \"SedeDHL:%s\" - \"Message:%s\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"', Frame_Time, MQTYPE, SedeDHL, load, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
            print('------------------------------------------------------------------------------------')
            print(load)
            print(Frame_Time)
            print(MQTYPE)
    
    def gray_logger_SATS_error(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Error at parsing\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error at parsing')
    
    def gray_logger_SATS_error2(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Error2, packet lost. S--t happens!\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error2, packet lost. S--t happens!')

    def gray_logger_SATS_error3(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Error3 at Debug\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error3 on load')

    def gray_logger_SATS_error4(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Error4 at Debug parsing\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error4 at Debug parsing')

    def gray_logger_SATS_error5(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Error5, No PID Active\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error5, No PID Active')

    def gray_logger_SATS_error6(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Error6 No Process Active\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error6 No Process Active')
    
    def payload_print(load, CLI_DEBUG):
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print(load)
           
    def snigio3_stop(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Sniffer is stopped\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("Sniffer is stopped")
           
    def snigio3_alive(logger, SedeDHL, MQDEBUG, CLI_DEBUG):
        logger.debug("\"SedeDHL:%s\" - \"Message:Sniffer is alive\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
            print('------------------------------------------------------------------------------------')
            print("Sniffer is alive")
           
    def snigio3_start(logger, SedeDHL, MQDEBUG, CLI_DEBUG):

        logger.debug("\"SedeDHL:%s\" - \"Message:Sniffer Started\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("Sniffer Started") 

    def snigio3_pid(logger, SedeDHL, MQDEBUG, CLI_DEBUG):

        logger.debug("\"SedeDHL:%s\" - \"Message:No active PID\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("No active PID")

    def snigio3_process(logger, SedeDHL, MQDEBUG, CLI_DEBUG):

        logger.debug("\"SedeDHL:%s\" - \"Message:No Active Process\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", SedeDHL, MQDEBUG, CLI_DEBUG)
        if CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("No Active Process")