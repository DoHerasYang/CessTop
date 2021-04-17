#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
#   CessTop Main Function ---
#
#
#
#
import getopt
import sys
import argparse
import re
import os
from multiprocessing import Process, Pool, Lock, Queue

# Local File Import
import config
import cisco_function
import topsec_function
import compare_function


# Parse Command Line Args
# def Command_SplitFunction(argv: list) -> dict:
#     fileName_dict = {"cisco_filename": "", "topsec_filename": ""}
#     try:
#         opts, args = getopt.getopt(argv, "hs:c:", ["help", "sourcefile=", "comparablefile="])
#         for opt, arg in opts:
#             if opt in ("-h", "--help"):
#                 config.Logger.log_show("Welcome to Use CessTop to Parse Firewall Log Config")
#                 config.Logger.info_show("Usage:")
#                 print(
#                     "  python3 CessTop.py -s <SourceFileName - Cisco File Name> -c <CompareFileName - Topsec File Name>")
#                 sys.exit(0)
#             elif opt in ("-s", "--sourcefile"):
#                 fileName_dict["cisco_filename"] = arg
#             elif opt in ("-c", "--comparablefile"):
#                 fileName_dict["topsec_filename"] = arg
#     except getopt.GetoptError:
#         print("\n")
#         config.Logger.log_warning("Please Check The Input Command Format!")
#         print("\n")
#         config.Logger.info_show("Usage:")
#         print("\n")
#         print("  python3 CessTop.py -s <SourceFileName - Cisco File Name> -c <CompareFileName - Topsec File Name>")
#         sys.exit(2)
#     return fileName_dict


# Rewrite args Process Function and Import argparse package
def Args_Define() -> dict:
    """
    Function:   Process The parameters in Command Line
    :return:    Dictionary with Information
    """
    parser = argparse.ArgumentParser(
        description="CessTop - An Efficient Tool to Parse and Analyse the Firewall Config File...",
        epilog="Developed by DoHeras Yang @2021"
    )

    parser.add_argument('-s', '--source',
                        nargs=1,
                        metavar="[Source File Name]",
                        type=str,
                        help="Input Source File Name (Support Cisco Config File and TopSec)"
                        )

    parser.add_argument("-c", '--compare',
                        nargs=1,
                        type=str,
                        metavar="[Compared Target File Name]",
                        help="Input Comparison File Name (Support Cisco Config File and TopSec)")

    parser.add_argument("-m", "--model",
                        nargs="?",
                        type=str,
                        metavar="[strict/release]",
                        default="release",
                        help="Strict model makes CessTop Do NOT ignore Config Merge. Release model makes CessTop ignore Config Merge.")

    parser.add_argument("-v", "--version",
                        action="store_true",
                        help="Current Tool Version Information ")

    # args
    temp_dict = vars(parser.parse_args())

    # Check Type and Model
    return Process_input(temp_dict)


# Judge the Kind of File Type
def Process_input(args: dict) -> dict:
    """
    :param args: Dictionary From argParse
    :return: New Dictionary with Functional Information
    """
    kernel_dict = dict()
    kernel_dict["order"] = list()
    src_file_type = ""
    cmp_file_type = ""

    try:
        for key, value in args.items():
            if key == "source":
                src_file_type = Judge_File(value[0])
                if src_file_type == "cisco":
                    kernel_dict["cisco_filename"] = value[0]
                    kernel_dict["order"].append("cisco")
                elif src_file_type == "topsec":
                    kernel_dict["topsec_filename"] = value[0]
                    kernel_dict["order"].append("topsec")
            if key == "compare":
                cmp_file_type = Judge_File(value[0])
                if cmp_file_type == "cisco":
                    kernel_dict["cisco_filename"] = value[0]
                    kernel_dict["order"].append("cisco")
                elif cmp_file_type == "topsec":
                    kernel_dict["topsec_filename"] = value[0]
                    kernel_dict["order"].append("topsec")
    except TypeError:
        config.Logger.log_fail("Error: Parameter ERROR!")
        config.Logger.log_show("           CAN NOT FIND YOUR Parameter Input, PLEASE CHECK YOUR Parameter Input File")
        config.Logger.log_warning("Parameter Error:     --" + key + "/-" + key[0] + "\n")
        os.system("python3 CessTop.py -h")
        sys.exit(2)

    if src_file_type == "Not_Recognized":
        config.Logger.log_fail("UnRecognized File Format! Please Check Whether File MEET FIREWALL CONFIGURATION!")
        config.Logger.log_warning("FILENAME:        " + args["source"][0])

    if cmp_file_type == "Not_Recognized":
        config.Logger.log_fail("UnRecognized File Format! Please Check Whether File MEET FIREWALL CONFIGURATION!")
        config.Logger.log_warning("FILENAME:        " + args["compare"][0])

    # Determine the Rule:
    #       - Cisco_cmp_Cisco
    #       - TopSec_cmp_TopSec
    #       - Cisco_cmp_TopSec
    #       - TopSec_cmp_Cisco

    if kernel_dict["order"][0] == "cisco":
        if kernel_dict["order"][0] == kernel_dict["order"][1]:
            kernel_dict["rule"] = "Cisco_cmp_Cisco"
        else:
            kernel_dict["rule"] = "Cisco_cmp_TopSec"
    else:
        if kernel_dict["order"][0] == kernel_dict["order"][1]:
            kernel_dict["rule"] = "TopSec_cmp_TopSec"
        else:
            kernel_dict["rule"] = "TopSec_cmp_Cisco"

    kernel_dict["model"] = args["model"]

    return kernel_dict


def Judge_File(filename: str) -> str:
    """
    : Function: Used to Check File Type and Judge Parameters
    :param filename: Input Filename
    :param par: Parameter
    :return: str
        - "cisco_file"
        - "topsec_file"
        - "Not_Recognized"
    """
    try:

        with open(filename, 'r') as file:
            line = file.readline()
            while line:
                if re.match(config.Default_Config.re_cisco, line):
                    return "cisco"
                elif re.match(config.Default_Config.re_topsec, line):
                    return "topsec"
                else:
                    line = file.readline()

    except FileNotFoundError:
        config.Logger.log_fail("Error: FILE_NOTFOUND_ERROR")
        config.Logger.log_show("           CAN NOT FIND YOUR FILE, PLEASE CHECK YOUR FILE PATH!")
        config.Logger.log_warning("Error File PATH:     " + filename)
        sys.exit(2)

    return "Not_Recognized"


# Main Entrance
if __name__ == "__main__":

    # Check Command Correct And Obtain Config File Name
    # filename_dict = Command_SplitFunction(sys.argv[1:])
    filename_dict = Args_Define()

    print(filename_dict)

    sys.exit(1)

    # Initial Local Config
    local_config = config.default_config_dict["default"]()

    # Class Cisco_Function instance
    cisco_instance = cisco_function.Cisco_Function(filename_dict["cisco_filename"])

    # Class TopSec_Function instance
    topsec_instance = topsec_function.Topsec_Function(filename_dict["topsec_filename"])

    # Class Compare Function instance
    compare_instance = compare_function.Compare_Function()

    # Define the Queue to Transport the Variable
    queue_cisco = Queue(maxsize=1)
    queue_topsec = Queue(maxsize=2)

    # MultiProcessing - Pool
    cisco_process = Process(target=cisco_instance.Start_Processing, args=(cisco_instance, queue_cisco,))
    topsec_process = Process(target=topsec_instance.Start_Processing, args=(topsec_instance, queue_topsec,))
    compare_process = Process(target=compare_instance.Start_Processing,
                              args=(compare_instance, queue_cisco, queue_topsec,))

    cisco_process.start()
    topsec_process.start()
    compare_process.start()

    cisco_process.join()
    topsec_process.join()
    compare_process.join()
