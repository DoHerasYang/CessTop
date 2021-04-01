#!/usr/bin/python3
#
# CessTop - Cisco Config Files Process Functions
#
#
#
#
#
#

import re
import config
import multiprocessing
import pandas as pd


# define Cisco class
class Cisco_Function(object):

    @classmethod
    def Analyze_CiscoContent(cls, each_content: str) -> dict:

        strip_Content = each_content.strip().split()
        insert_data = dict().fromkeys(config.default_config_dict["default"].df_format, " ")

        # Initialize the Dictionary with
        for key, content in zip(insert_data.keys(), strip_Content[:5]):
            insert_data[key] = content

        # Diff from TopSec, the Packet_Type in icmp
        if strip_Content[4] == "icmp":
            insert_data["Port_Type"] = "PING"

        # Main
        if strip_Content[5] == "host":
            insert_data["Src_Type(host/any/object-group)"] = "host"
            insert_data["Src_Addr"] = strip_Content[6]
            if strip_Content[7] == "host":
                insert_data["Dst_Type(host/any/object-group)"] = strip_Content[7]
                insert_data["Dst_Addr"] = strip_Content[8]
            elif strip_Content[7] == "any":
                insert_data["Dst_Addr"] = "any"
            else:
                insert_data["Dst_Addr"] = strip_Content[7]
                insert_data["Dst_Mask"] = strip_Content[8]
        # Src_Addr = 'any'  Dst_Addr = 'any
        elif strip_Content[5] == "any":
            insert_data["Src_Addr"] = strip_Content[5]
            insert_data["Dst_Addr"] = strip_Content[6]
        # object-group
        elif strip_Content[5] == "object-group":
            insert_data["Src_Type(host/any/object-group)"] = strip_Content[5]
            insert_data["Src_Addr"] = strip_Content[6]
            if strip_Content[7] == "object-group":
                insert_data["Dst_Type(host/any/object-group)"] = strip_Content[7]
                insert_data["Dst_Addr"] = strip_Content[8]
            elif strip_Content[7] == "host":
                insert_data["Dst_Type(host/any/object-group)"] = strip_Content[7]
                insert_data["Dst_Addr"] = strip_Content[8]
            else:
                insert_data["Dst_Addr"] = strip_Content[7]
                insert_data["Dst_Mask"] = strip_Content[8]
        # all Src_Addr = ip / Dst_Addr
        else:
            insert_data["Src_Addr"] = strip_Content[5]
            insert_data["Src_Mask"] = strip_Content[6]
            if strip_Content[7] == "host":
                insert_data["Dst_Type(host/any/object-group)"] = strip_Content[7]
                insert_data["Dst_Addr"] = strip_Content[8]
            elif strip_Content[7] == "any":
                insert_data["Dst_Addr"] = strip_Content[7]
            else:
                insert_data["Dst_Addr"] = strip_Content[7]
                insert_data["Dst_Mask"] = strip_Content[8]

        # At Last Process with the Port_Type
        if 'eq' in strip_Content:
            insert_data["Eq"] = "eq"
            index = strip_Content.index("eq")
            if strip_Content[index + 1] == "www":
                insert_data["Port_Type"] = "HTTP"
            elif strip_Content[index + 1] == "snmptrap":
                insert_data["Port_Type"] = "SNMP-TRAP"
            else:
                insert_data["Port_Type"] = strip_Content[index + 1]
        elif strip_Content[4] == "tcp" and ("eq" not in strip_Content):
            insert_data["Port_Type"] = "TCPALL"

        # Deal With eq = "range"
        if 'range' in strip_Content:
            insert_data["Eq"] = "range"
            index = strip_Content.index("range")
            insert_data["Port_Type"] = strip_Content[index + 1] + "-" + strip_Content[index + 2]

        if 'log' in strip_Content:
            insert_data["Log"] = "log"

        return insert_data

    # Process Function to Format the Cisco Log File
    # In Cisco Log File, Need to Focus on the Line starting with "access-list"
    #
    @classmethod
    def Process_Cisco_LogFile_ToList(cls, filename: str) -> list:

        re_cisco_access_list_header = re.compile(r'access-list')
        access_list = list()
        with open(filename, "r") as ciscoFile:
            log_lineContent = ciscoFile.readline()
            while log_lineContent:
                if re.match(re_cisco_access_list_header, log_lineContent):
                    access_list.append(log_lineContent)
                log_lineContent = ciscoFile.readline()
        return access_list

    @staticmethod
    def LogFileList_toPandasDF(self, Logfile_List: list):
        for item in Logfile_List:
            self.df_cisco = self.df_cisco.append(self.Analyze_CiscoContent(each_content=item), ignore_index=True)

    @staticmethod
    # def Start_Processing(self):
    def Start_Processing(self, queue: multiprocessing.Queue):
        try:
            self.access_list = self.Process_Cisco_LogFile_ToList(filename=self.filename)
            self.LogFileList_toPandasDF(self, Logfile_List=self.access_list)
        except Exception as err:
            raise err
        finally:
            queue.put(self.df_cisco)
            self.df_cisco.to_csv(config.default_config_dict["default"].cisco_csv_Name, sep=',',
                                 header=config.default_config_dict["default"].df_format,
                                 index=True)

    def __init__(self, out_filename: str):
        self.access_list = list()
        self.filename = out_filename
        self.df_cisco = pd.DataFrame(columns=config.default_config_dict["default"].df_format)
