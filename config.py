#
#
#
#  CessTop Config Files - - - - -
#
#
#     This file contains all the configs such as pandas DataFrame Format / Default outputFile name / Version Information
#
#
#
import os
import re
import pandas as pd

class Default_Config:

    # CessTop Version Information
    cesstop_version = "Version 2.1.1 Release - 2021.06.08 Developed By DoHeras"

    # Define default csv columns name
    df_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type",
                 "Src_Type(host/any/object-group)", "Src_Addr", "Src_Mask", "Dst_Type(host/any/object-group)",
                 "Dst_Addr", "Dst_Mask", "Eq", "Port_Type", "Log"]

    # Define default cisco csv file name
    cisco_csv_Name = "./output/cisco_config.csv"

    # Define default topsec csv file name
    topsec_csv_Name = "./output/topsec_config.csv"

    # Define default topsec txt file name
    topsec_strategy_Name = "./output/topsec.txt"

    # Define default output folder
    output_folder_path = "output"

    # Define Result File Name
    result_file_name = "./output/result.csv"

    # Default Cisco File Mark
    re_cisco  = re.compile(r"access-list")

    # Default TopSec File Mark
    re_topsec = re.compile(r"firewall")

    # Create Result Folder to store Result files
    def __init__(self):
        if self.output_folder_path not in os.listdir(os.getcwd()):
            try:
                os.mkdir(self.output_folder_path)
            except OSError:
                os.chmod(os.getcwd(), 777)
                os.mkdir(self.output_folder_path)


# Different Output Color on Console
class Logger(object):

    HELP = '\033[33m'
    INFO = '\033[35m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    COMPLETE = '\033[32m'
    ENDC = '\033[0m'

    @classmethod
    def log_warning(cls, info: str):
        print(cls.WARNING + info + cls.ENDC)

    @classmethod
    def log_fail(cls, info: str):
        print(cls.FAIL + info + cls.ENDC)

    @classmethod
    def log_show(cls, info:str):
        print(cls.INFO + info + cls.ENDC)

    @classmethod
    def info_show(cls, info: str):
        print(cls.HELP + info + cls.ENDC)

    @classmethod
    def complete_show(cls, info:str):
        print(cls.COMPLETE + info + cls.ENDC)


default_config_dict = {
    "default": Default_Config
}
