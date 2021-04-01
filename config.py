#
#
#
#  CessTop Config Files - - - - -
#
#
#     This file contains all the configs such as pandas DataFrame Format and Default outputFile name
#
#
#
import os


class Default_Config:
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

    def __init__(self):
        if self.output_folder_path not in os.listdir(os.getcwd()):
            try:
                os.mkdir(self.output_folder_path)
            except:
                os.chmod(os.getcwd(), 777)
                os.mkdir(self.output_folder_path)


# Different Output Color
class Logger(object):

    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    @classmethod
    def log_warning(cls, info):
        print(Logger.WARNING + info + Logger.ENDC)

    @classmethod
    def log_fail(cls, info):
        print(Logger.FAIL + info + Logger.ENDC)


default_config_dict = {
    "default": Default_Config
}
