#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import argparse
import os
import sys
import config
import re


# Parse Command Line Args
# Abandon From Version 2.0
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
# Start Used from Version 2.0
def Args_Define() -> dict:
    """
    Function:   Process The parameters in Command Line
    :return:    Dictionary with Information
    """
    parser = argparse.ArgumentParser(
        description="CessTop - An Efficient Tool to Parse and Analyse the Firewall Config File...",
        epilog="Developed by DoHerasYang @ 2021"
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
                        metavar="[Target File Name]",
                        help="Input Comparison File Name (Support Cisco Config File and TopSec)")

    parser.add_argument("-m", "--model",
                        nargs="?",
                        type=str,
                        metavar="[strict/release]",
                        default="release",
                        help="Strict model makes CessTop Do NOT ignore Config Merge. Release model makes CessTop ignore Config Merge.")

    parser.add_argument("-v", "--version",
                        action="version",
                        version=config.Default_Config.cesstop_version,
                        help="Current CessTop Version Information")

    # Check Type and Model
    try:
        args, unparsed = parser.parse_known_args()
        if len(unparsed) != 0:
            raise TypeError
    except TypeError:
        config.Logger.log_fail("\n")
        config.Logger.log_fail("Error: Parameter ERROR!")
        config.Logger.log_show("           CAN NOT FIND YOUR Parameter Input, PLEASE CHECK YOUR Parameter Input File")
        for i in range(int(len(unparsed)/2)):
            config.Logger.log_warning("Parameter Error:   " + unparsed[i*2] + " " + unparsed[i*2+1] + "\n")
        config.Logger.complete_show("####################### Usage ############################\n")
        os.system("python3 CessTop.py -h")
        sys.exit(2)

    return Process_input(vars(args))


# Judge the Kind of File Type
# Cisco or TopSec ?/?
#
#
def Process_input(args: dict, ) -> dict:
    """
    :param args: Dictionary From argParse - vars
    :return: New Dictionary with Functional Information
    """

    kernel_dict = dict()
    kernel_dict["order"] = list()
    src_file_type = ""
    cmp_file_type = ""

    # Extract args - dict
    for key, value in args.items():
        if key == "source":
            src_file_type = Judge_File(filename=value[0])
            if src_file_type == "cisco":
                kernel_dict["cisco_filename"] = value[0]
                kernel_dict["order"].append("cisco")
            elif src_file_type == "topsec":
                kernel_dict["topsec_filename"] = value[0]
                kernel_dict["order"].append("topsec")
        elif key == "compare":
            cmp_file_type = Judge_File(filename=value[0])
            if cmp_file_type == "cisco":
                kernel_dict["cisco_filename"] = value[0]
                kernel_dict["order"].append("cisco")
            elif cmp_file_type == "topsec":
                kernel_dict["topsec_filename"] = value[0]
                kernel_dict["order"].append("topsec")
        elif key == "model":
            pass

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

    # Check Model Config
    kernel_dict["model"] = args["model"] if args["model"] in ["release", "strict"] else Model_Error(args["model"])

    return kernel_dict


def Judge_File(filename: str) -> str:
    """
    : Function: Used to Check File Type and Judge Parameters
    :param filename: Input Filename
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
        config.Logger.log_show("           - CAN NOT FIND YOUR FILE, PLEASE CHECK YOUR FILE PATH!")
        config.Logger.log_warning("Error File PATH:     " + filename)
        sys.exit(2)

    return "Not_Recognized"


def Model_Error(err: str):
    """
        Model Parameter Error (Not Found)
    """
    config.Logger.log_fail("Error: Model Parameter Error!")
    config.Logger.log_show("           Model Parameter Error, PLEASE CHECK YOUR INPUT PARAMETER")
    config.Logger.log_warning("Model Legal Parameters:  [strict/release]   Your Input:  " + err)
    sys.exit(1)
