#!/usr/bin/env python3

import nxlog
import re
import time
import datetime
from datetime import datetime as dt
from datetime import timedelta

#Header
regexp_HEADER = r"^(\w{4})(\d{2})(\w{6})(\w{6})(.{6})(\d{15})(\d{5}|)(\w{1})(\d{6})"

#MSG
regexp_MSG = r"^(\w{4})(\d{2})(.{6})(\w{6})(.{6})(\d{15})(\d{5})(\w{1})(\d{6})"

#FRAMETIME
regexp_Frametime = r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{3})"

#I_SR RegExp
regex_I_SR = r"(I_SR)(\d{16})(\d{6}|\s{6})(.{10})(\d{15})(Y|N)(D)(Y|N)(S|E)(.*)(\d{5,5})(\d{5,5})(\d{5,5})(\d{5,5})(W)(Y|N)(S|E)(.*)(\d{5,5})(B)(\w{10})(\d{15})(G|B)(.*)"
reg_msg_I_SR = r"(I_SR)"

#I_SI RegExp
regex_I_SI = r"(I_SI)(\d{16})(.{50})(S|N)(\d{2})(.+)"
reg_msg_I_SI = r"(I_SI)"

#I_DR RegExp
regex_I_DR = r"(I_DR)(\d{16})(P|V)(OK\ \ |FAIL|OVER)"
regex_I_DR_OK = r"(I_DR)(\d{16})(P|V)(OK\ \ |FAIL|OVER)(.+)"
reg_msg_I_DR = r"(I_DR)"

#Captured_barcode multivalid
regexp_multivalid = r"(JJD\\d+JJD\\d+)|(0500\\w+0500\\w+)|(0500\\w+0600\\w+)|(0600\\w+0500\\w+)"

#Snigio message
regexp_snigio = r"(Sniffer\ is\ alive)|(Error\, packet lost\. S\-\-t happens\!)|(Sniffer\ is\ stopped)|(Sniffer\ Started)|(No\ Active\ Process)|(No\ active\ PID)"

#FailureCode Parser
FailureCode_source = ["0000", "0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "09"]
FailureName = ["No failure", "Sort Instruction received too late to be executed", "No sort instruction received", "Destination full", "Destination does not exist", "Item not detected on carrier / Piece lost", "Chute disabled", "FLY Chute buffer is full and discharge flap closed", "Sorter speed out of threshold", "Too many simultaneous discharge"]

def data_man_LT1(event):
    Frame_Time = event.get_field('Frame_Time')
    Frame_Time_P = event.get_field('Frame_Time_P')
    
    Frame_Time = str(Frame_Time)
    Frame_Time_P = str(Frame_Time_P)

    #HDEVTM = HDEVTM[:-6]

    #HDEVTM_P = re.sub(r'(\+01\:00)', '', HDEVTM_P)
    #HDEVTM_P = re.sub(r'(\,)', '.', HDEVTM_P)
    #HDEVTM = re.sub(r'(\,)', '.', HDEVTM)
    #HDEVTM_P = re.sub(r'(\,)', '.', HDEVTM_P)
    #Format_HDEVTM = '%Y-%m-%d %H:%M:%S.%f'

    Format_Frame_Time = '%Y-%m-%d %H:%M:%S.%f'
    #Operations
    try:
        if dt.strptime(Frame_Time, Format_Frame_Time) > dt.strptime(Frame_Time_P, Format_Frame_Time):
            Frame_Time_DIFF = dt.strptime(Frame_Time, Format_Frame_Time) - dt.strptime(Frame_Time_P, Format_Frame_Time)
            Frame_Time_DIFF_sec_mill = Frame_Time_DIFF.total_seconds()
            event.set_field('Frame_Time_DIFF', Frame_Time_DIFF)
            event.set_field('Frame_Time_DIFF_sec_mill', Frame_Time_DIFF_sec_mill)
            TOW = round(Frame_Time_DIFF_sec_mill / 2, 4)
            COW = (1 / TOW) * 60
            COW = int(COW)
            event.set_field('TOW', TOW)
            event.set_field('COW', COW)
    except:
        event.set_field('Error', "Error in parsing date")
        event.set_field('NoTOW', "X")

def PID_JJD_LT1(event):
    regexp = r"(21JJD\d{18})"    
    Captured_barcode = ""
    Captured_barcode = event.get_field('Captured_barcode')
    Captured_barcode = str(Captured_barcode)
    try:
        if re.search(regexp, Captured_barcode):
            test = re.search(regexp, Captured_barcode)
            PID_Info = test.group(0)
            PID_Info = PID_Info[3:]
            event.set_field('PID', PID_Info)
        else:
            Captured_barcode = ""
    except:
        Captured_barcode = ""

def parser_LT1(event):
    MSG = "NO"
    Exception_error = str(event.get_field('Exception'))
    FailureCode = str(event.get_field('FailureCode'))
    load = event.get_field('msg_parser')
    load = str(load)
    if re.search(regexp_snigio, load):
        event.set_field('Message_Type', "Snigio")
    else:
        try:
            load_sats_light = re.search(regexp_HEADER, load)
            Message_Version = load_sats_light.group(2)
            Facility_ID = load_sats_light.group(3)
            Source = load_sats_light.group(4)
            Destination = load_sats_light.group(5)
            Frame_Time = load_sats_light.group(6)
            Frame_Time_extract = re.search(regexp_Frametime, Frame_Time)
            Frame_Time = "20" + Frame_Time_extract.group(1) + "-" + Frame_Time_extract.group(2) + "-" + Frame_Time_extract.group(3) + " " + Frame_Time_extract.group(4) + ":" + Frame_Time_extract.group(5) + ":" + Frame_Time_extract.group(6) + "." + Frame_Time_extract.group(7)
            LINE_PROCESS = int(Frame_Time_extract.group(4))
            if LINE_PROCESS > 12:
                LINE_PROCESS = "1"
            else:
                LINE_PROCESS = "2"
            Message_sequence_number = load_sats_light.group(7)
            TYPE = load_sats_light.group(8)
            Message_Body_Length = load_sats_light.group(9)
            MSG = re.sub(regexp_MSG, "", load)
            event.set_field('Message_Version', Message_Version)
            #print(Message_Version)
            event.set_field('TYPE', TYPE)
            #print(TYPE)
            event.set_field('Facility_ID', Facility_ID)
            #print(Facility_ID)
            event.set_field('Source',Source)
            #print(Source)
            event.set_field('Destination', Destination)
            #print(Destination)
            event.set_field('Frame_Time', Frame_Time)
            #print(Frame_Time)
            event.set_field('Message_sequence_number', Message_sequence_number)
            #print(Message_sequence_number)
            event.set_field('Message_Body_Length', Message_Body_Length)
            #print(Message_Body_Length)
            if MSG != "NO":
                event.set_field('MSG', MSG)
                #print(MSG)
            event.set_field('LINE_PROCESS', LINE_PROCESS)
            #print(LINE_PROCESS)
        except:
            Error = "Error in Graylog parsing header"
            event.set_field('Error', Error)
        if MSG != "NO":
            try:
                #I_SR
                if re.search(reg_msg_I_SR, load):
                    #regexp
                    load_sats_light = re.search(regex_I_SR, load)
                    #Assigne variable from regexp
                    Message_Type = load_sats_light.group(1)
                    VID = str(load_sats_light.group(2))
                    Cell_ID = str(load_sats_light.group(3))
                    Induction_name = str(load_sats_light.group(4))
                    Induction_timestamp = load_sats_light.group(5)
                    Technical_Reject = str(load_sats_light.group(6))
                    Data_Section_Identifier = str(load_sats_light.group(7))
                    Dim_Legal_For_Trade = str(load_sats_light.group(8))
                    if Dim_Legal_For_Trade == "N":
                        Exception_error = "NoDim"
                    Dim_Status = str(load_sats_light.group(9))
                    Dim_Alibi_ID = str(load_sats_light.group(10))
                    Volume = load_sats_light.group(11)
                    Length = load_sats_light.group(12)
                    Width = load_sats_light.group(13)
                    Height = load_sats_light.group(14)
                    Weight_ID = str(load_sats_light.group(15))
                    Weight_Legal_for_trade = str(load_sats_light.group(16))
                    if Weight_Legal_for_trade == "N":
                        Exception_error = "NoWeight"
                    Weight_Status = load_sats_light.group(17)
                    Weight_Alibi_ID = load_sats_light.group(18)
                    Weight_in_gram = load_sats_light.group(19)
                    Barcode_Section_Identifier = str(load_sats_light.group(20))
                    Scanner_Identifier = str(load_sats_light.group(21))
                    Scanning_timestamp = load_sats_light.group(22)
                    Frame_Time_extract = re.search(regexp_Frametime, Scanning_timestamp)
                    Scanning_timestamp = "20" + Frame_Time_extract.group(1) + "-" + Frame_Time_extract.group(2) + "-" + Frame_Time_extract.group(3) + " " + Frame_Time_extract.group(4) + ":" + Frame_Time_extract.group(5) + ":" + Frame_Time_extract.group(6) + "." + Frame_Time_extract.group(7)
                    Scanner_Status = str(load_sats_light.group(23))
                    if Scanner_Status == "G":
                        Captured_barcode = str(load_sats_light.group(24))
                        
                    #    if re.search(regexp_multivalid, Captured_barcode):
                    #        Exception = "MultiValid"
                    
                    elif Scanner_Status == "B":
                        Exception_error = "NoRead"
                    #Debug
                    #print(Message_Type)
                    event.set_field('Message_Type', Message_Type)
                    #print(VID)
                    event.set_field('VID', VID)
                    #print(Cell_ID)
                    event.set_field('Cell_ID', Cell_ID)
                    #print(Induction_name)
                    event.set_field('Induction_name', Induction_name)
                    #print(Induction_timestamp)
                    event.set_field('Induction_timestamp', Induction_timestamp)
                    #print(Technical_Reject)
                    event.set_field('Technical_Reject', Technical_Reject)
                    #print(Data_Section_Identifier)
                    event.set_field('Data_Section_Identifier', Data_Section_Identifier)
                    #print(Dim_Legal_For_Trade)
                    event.set_field('Dim_Legal_For_Trade', Dim_Legal_For_Trade)
                    #print(Dim_Status)
                    event.set_field('Dim_Status', Dim_Status)
                    #print(Dim_Alibi_ID)
                    event.set_field('Dim_Alibi_ID', Dim_Alibi_ID)
                    #print(Volume)
                    event.set_field('Volume', Volume)
                    #print(Length)
                    event.set_field('Length', Length)
                    #print(Width)
                    event.set_field('Width', Width)
                    #print(Height)
                    event.set_field('Height',Height)
                    #print(Weight_ID)
                    event.set_field('Weight_ID', Weight_ID)
                    #print(Weight_Legal_for_trade)
                    event.set_field('Weight_Legal_for_trade', Weight_Legal_for_trade)
                    #print(Weight_Status)
                    event.set_field('Weight_Status', Weight_Status)
                    #print(Weight_Alibi_ID)
                    event.set_field('Weight_Alibi_ID', Weight_Alibi_ID)
                    #print(Weight_in_gram)
                    event.set_field('Weight_in_gram', Weight_in_gram)
                    #print(Barcode_Section_Identifier)
                    event.set_field('Barcode_Section_Identifier', Barcode_Section_Identifier)
                    #print(Scanner_Identifier)
                    event.set_field('Scanner_Identifier', Scanner_Identifier)
                    #print(Scanning_timestamp)
                    event.set_field('Scanning_timestamp', Scanning_timestamp)
                    #print(Scanner_Status)
                    event.set_field('Scanner_Status', Scanner_Status)
                    #print(Number_of_barcodes_captured)
                    #event.set_field('Number_of_barcodes_captured', Number_of_barcodes_captured)
                    if Scanner_Status == "G":
                        #print(Captured_barcode)
                        event.set_field('Captured_barcode', Captured_barcode)
                    #print(Exception)
                    event.set_field('Exception', Exception_error)
                #I_SI
                elif re.search(reg_msg_I_SI, load):
                    load_sats_light = re.search(regex_I_SI, load)
                    #Assigne variable from regexp
                    Message_Type = str(load_sats_light.group(1))
                    VID = str(load_sats_light.group(2))
                    Item_Identifier_4_sorting = str(load_sats_light.group(3))
                    Sort_Strategy = str(load_sats_light.group(4))
                    No_of_sort_destination = str(load_sats_light.group(5))
                    Destination_Chute = str(load_sats_light.group(6))
                    if Exception_error == "NoException" and Destination_Chute == "EXC01":
                        Exception_error = "LT1-Fail"
                    elif Exception_error == "NoException" and Destination_Chute == "EXC02":
                        Exception_error = "LT1-Fail"
                    else:
                        Exception_error = "NoException"
                        #Debug
                    #print(Message_Type)
                    event.set_field('Message_Type',Message_Type)
                    #print(VID)
                    event.set_field('VID', VID)
                    #print(Item_Identifier_4_sorting)
                    event.set_field('Item_Identifier_4_sorting', Item_Identifier_4_sorting)
                    #print(Sort_Strategy)
                    event.set_field('Sort_Strategy', Sort_Strategy)
                    #print(No_of_sort_destination)
                    event.set_field('No_of_sort_destination', No_of_sort_destination)
                    #print(Destination_Chute)
                    event.set_field('Destination_Chute', Destination_Chute)
                    #print(Exception_error)
                    event.set_field('Exception', Exception_error)
                #I_DR
                elif re.search(reg_msg_I_DR, load):
                    #regexp
                    load_sats_light = re.search(regex_I_DR, load)
                    #Assigne variable from regex
                    Message_Type = str(load_sats_light.group(1))
                    VID = str(load_sats_light.group(2))
                    Discharge_Type = str(load_sats_light.group(3))
                    Discharge_Result = str(load_sats_light.group(4))
                    if Discharge_Result == "OK  ":
                        load_sats_light = re.search(regex_I_DR_OK, load)
                        Discharge_Chute = str(load_sats_light.group(5))
                    elif Discharge_Result == "FAIL":
                        load_sats_light = re.search(regex_I_DR_OK, load)
                        code = str(load_sats_light.group(5))
                        FailureCodeReg = re.search(r"(\d{4}$)", code)
                        FailureCodeRegExp = FailureCodeReg.group(1)
                        FailureCode = FailureName[FailureCode_source.index(FailureCodeRegExp)]
                        code = str(code)
                        if re.search(r"(LOST)", code):
                            Exception_error = "PieceLost"
                        elif re.search(r"(OVER)", code):
                            Exception_error = "OverFlow"
                    elif Discharge_Result == "OVER":
                        Exception_error = "No sort instruction"
                    #Debug
                    #print(Message_Type)
                    event.set_field('Message_Type', Message_Type)
                    #print(VID)
                    event.set_field('VID', VID)
                    #print(Discharge_Type)
                    event.set_field('Discharge_Type', Discharge_Type)
                    #print(Discharge_Result)
                    event.set_field('Discharge_Result', Discharge_Result)
                    if Discharge_Result == "OK  ":
                        #print(Discharge_Chute)
                        event.set_field('Discharge_Chute', Discharge_Chute)
                    elif Discharge_Result == "FAIL":
                        #print(FailureCode)
                        event.set_field('FailureCode', FailureCode)
                    #print(Exception)
                    event.set_field('Exception', Exception_error)
                elif re.search(r"OPEN", load):
                    Message_Type = "OPEN"
                    event.set_field('Message_Type', Message_Type)
                    #print(VID)
                
            except:
                Error = "Error in Graylog parsing payload"
                event.set_field('Error', Error)

def Read_PID_data(event):

#Import nxlog data

    PID = event.get_field('PID')
    PID = str(PID)
    AWB = ""
    Codice_Account = ""
    
# Connect to MSSQL DB

    cnxn = pyodbc.connect('Driver={ODBC Driver 17 for SQL Server};Server=CZCHOWV918.prg-dc.dhl.com\SQL02;Database=PID_Link;UID=sql_interface;PWD=Sqlinter0+Sqlinter0;')
    cursor = cnxn.cursor()

# Exec Query to DB
    cursor.execute("select AWB, PcID as PID, PyrAcctNum as Codice_Account from SD_pidlink WHERE PcID = ?", PID)
    rows = cursor.fetchone()

# Extract Variable   
    if rows:
        AWB = str(rows[0])
        PID = str(rows[1])
        Codice_Account = str(rows[3])

# Close DB connection    
    cursor.close()

# Pass information to NXLOG

    event.set_field('AWB', AWB)
    event.set_field('PID', PID)
    event.set_field('Codice_Account', Codice_Account)

def data_man_dsnet(event):
    Frame_Time = event.get_field('Timestamp4DSNET')
    Frame_Time_P = event.get_field('time_sender_p')
    #HDEVTM_P = event.get_field('HDEVTM_P')
    #HDEVTM = event.get_field('HDEVTM')
    #frame_t = str(frame_t)
    #frame_t_p = str(frame_t_p)

    Frame_Time = str(Frame_Time)
    Frame_Time_P = str(Frame_Time_P)
    #HDEVTM_P = str(HDEVTM_P)
    #HDEVTM = str(HDEVTM)

    #HDEVTM = HDEVTM[:-6]

    #HDEVTM_P = re.sub(r'(\+01\:00)', '', HDEVTM_P)
    #HDEVTM_P = re.sub(r'(\,)', '.', HDEVTM_P)
    #HDEVTM = re.sub(r'(\,)', '.', HDEVTM)
    #HDEVTM_P = re.sub(r'(\,)', '.', HDEVTM_P)
    #Format_HDEVTM = '%Y-%m-%d %H:%M:%S.%f'

    Format_Frame_Time = '%Y-%m-%d %H:%M:%S,%f'
    #Operations
    # Frame_time 
    try:
        if dt.strptime(Frame_Time, Format_Frame_Time) > dt.strptime(Frame_Time_P, Format_Frame_Time):
            Frame_Time_DIFF = dt.strptime(Frame_Time, Format_Frame_Time) - dt.strptime(Frame_Time_P, Format_Frame_Time)
            Frame_Time_DIFF_sec_mill = Frame_Time_DIFF.total_seconds()
            event.set_field('Frame_Time_DIFF', Frame_Time_DIFF)
            event.set_field('Frame_Time_DIFF_sec_mill', Frame_Time_DIFF_sec_mill)
            Response_time = float(Frame_Time_DIFF_sec_mill)
            event.set_field('Response_time', Response_time)
    except:
        event.set_field('Error', "Error in parsing date")

def data_man_SATS(event):
    #HDSDID = event.get_field('HDSDID')
    Frame_Time = event.get_field('Frame_Time')
    Frame_Time_P = event.get_field('Frame_Time_P')
    #HDEVTM_P = event.get_field('HDEVTM_P')
    #HDEVTM = event.get_field('HDEVTM')
    #frame_t = str(frame_t)
    #frame_t_p = str(frame_t_p)

    Frame_Time = str(Frame_Time)
    Frame_Time_P = str(Frame_Time_P)
    #HDEVTM_P = str(HDEVTM_P)
    #HDEVTM = str(HDEVTM)

    #HDEVTM = HDEVTM[:-6]
    #Frame_Time = Frame_Time[:-6]
    #HDEVTM_P = re.sub(r'(\+01\:00)', '', HDEVTM_P)
    #HDEVTM_P = re.sub(r'(\,)', '.', HDEVTM_P)
    #HDEVTM = re.sub(r'(\,)', '.', HDEVTM)
    #HDEVTM_P = re.sub(r'(\,)', '.', HDEVTM_P)
    #Format_HDEVTM = '%Y-%m-%d %H:%M:%S.%f'

    Format_Frame_Time = '%Y-%m-%d %H:%M:%S,%f'
    #Operations
    # Frame_time 
    try:
        if dt.strptime(Frame_Time, Format_Frame_Time) > dt.strptime(Frame_Time_P, Format_Frame_Time):
            Frame_Time_DIFF = dt.strptime(Frame_Time, Format_Frame_Time) - dt.strptime(Frame_Time_P, Format_Frame_Time)
            Frame_Time_DIFF_sec_mill = Frame_Time_DIFF.total_seconds()
            event.set_field('Frame_Time_DIFF', Frame_Time_DIFF)
            event.set_field('Frame_Time_DIFF_sec_mill', Frame_Time_DIFF_sec_mill)
            TOW = round(Frame_Time_DIFF_sec_mill / 2, 4)
            COW = (1 / TOW) * 60
            COW = int(COW)
            event.set_field('TOW', TOW)
            event.set_field('COW', COW)
    except:
        event.set_field('Error', "Error in parsing date")
        event.set_field('NoTOW', "X")

def reorder_time(event):
    Frame_Time = event.get_field('Frame_Time')
    #prova = str(event.get_field('prova'))
    Frame_Time = str(Frame_Time)
    Frame_Time = Frame_Time[:-6]
    #Frame_Time = re.sub("T", " ", Frame_Time)
    event.set_field('Frame_Time', Frame_Time)
    event.set_field('Reorder_Time', Frame_Time)
    #try:
    #    if re.search(r"\<HDMGTP\>", prova):
    #        HDMGTP = re.findall(r"(?<=\<HDMGTP\>)(.*?)(?=\<\/HDMGTP\>)", prova)
    #        event.set_field('HDMGTP', HDMGTP)
    #    else:
    #        HDMGTP = "bho"
    #        event.set_field('HDMGTP', HDMGTP)
    #        event.set_field('prova', prova)
    #except:
    #    HDMGTP = "bi"
    #    event.set_field('HDMGTP', HDMGTP)
    #    event.set_field('prova', prova)