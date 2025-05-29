# MESSAGE LOGGER CLASS for SNIGIO3, a SATS/LT1 Sniffer 
# Version 3.2.3
# DHL Express Italy S.r.l. - 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com

import sys
import logging
from logging.handlers import RotatingFileHandler


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
    
    def gray_logger_SATS(MSG, Frame_Time, MQTYPE):
        import SNIGIO.my_global as var_g
        var_g.logger.debug('\"Frame_time:%s\" - \"MQTYPE:%s\" - \"SedeDHL:%s\" - \"Message:%s\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"', Frame_Time, MQTYPE, var_g.SedeDHL, MSG, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
            print('------------------------------------------------------------------------------------')
            print(MSG)
            print(Frame_Time)
            print(MQTYPE)
    
    def gray_logger_LT1(MSG, Frame_Time, MQTYPE):
        import SNIGIO.my_global as var_g
        var_g.logger.debug('\"Frame_time:%s\" - \"MQTYPE:%s\" - \"SedeDHL:%s\" - \"Message:%s\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"', Frame_Time, MQTYPE, var_g.SedeDHL, MSG, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
            print('------------------------------------------------------------------------------------')
            print(MSG)
            print(Frame_Time)
            print(MQTYPE)
    
    def gray_logger_SATS_NCY(MSG, Frame_Time, MQTYPE):
        import SNIGIO.my_global as var_g
        var_g.logger.debug('\"Frame_time:%s\" - \"MQTYPE:%s\" - \"SedeDHL:%s\" - \"Message:%s\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"', Frame_Time, MQTYPE, var_g.SedeDHL, MSG, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
            print('------------------------------------------------------------------------------------')
            print(MSG)
            print(Frame_Time)
            print(MQTYPE)
    
    def gray_logger_MQDEBUG(MQCODE, MQTYPE):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:DEBUG MQ MESSAGE - MQCODE:%s; and MQTYPE:%s;\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, MQCODE, MQTYPE, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               mq = "MQCODE: " + MQCODE + " MQTYPE: " + MQTYPE
               print(mq)
    
    def gray_logger_SATS_error(load):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Error at parsing\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\" - \"Message:%s\" - \"Load:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.LI_DEBUG, load)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error at parsing')
    
    def gray_logger_SATS_error2(load):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Error2 in Snigio Parsing, packet lost.\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\" - \"Load:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG, load)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error2, packet lost. S--t happens!')
               print(load)

    def gray_logger_SATS_error3(load):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Error3 at Debug\" - \"load:%s\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\" - \"Load:%s\"", var_g.SedeDHL, load, var_g.MQDEBUG, var_g.CLI_DEBUG, load)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error3 on load')

    def gray_logger_SATS_error4(load):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Error4 at Debug parsing\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\" - \"Load:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG, load)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error4 at Debug parsing')

    def gray_logger_SATS_error5(load):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Error5, No PID Active\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error5, No PID Active')

    def gray_logger_SATS_error6(load):
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Error6 No Process Active\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print('Error6 No Process Active')
    
    def payload_print(load):
        import SNIGIO.my_global as var_g
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print(load)
           
    def snigio3_stop():
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Sniffer is stopped\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("Sniffer is stopped")
           
    def snigio3_alive():
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Sniffer is alive\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
            print('------------------------------------------------------------------------------------')
            print("Sniffer is alive")
           
    def snigio3_start():
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:Sniffer Started\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("Sniffer Started") 

    def snigio3_pid():
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:No active PID\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("No active PID")

    def snigio3_process():
        import SNIGIO.my_global as var_g
        var_g.logger.debug("\"SedeDHL:%s\" - \"Message:No Active Process\" - \"MQDEBUG:%s\" - \"CLI_DEBUG:%s\"", var_g.SedeDHL, var_g.MQDEBUG, var_g.CLI_DEBUG)
        if var_g.CLI_DEBUG == 'YES':
               print('------------------------------------------------------------------------------------')
               print("No Active Process")
