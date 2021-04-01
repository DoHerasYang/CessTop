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
from multiprocessing import Process, Pool, Lock, Queue

import config
import cisco_function
import topsec_function
import compare_function


def Command_SplitFunction(argv: list) -> dict:
    fileName_dict = {"cisco_filename": "", "topsec_filename": ""}
    try:
        opts, args = getopt.getopt(argv, "hs:c:", ["help", "sourcefile=", "comparablefile="])
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print(
                    "python3 CessTop.py -s <SourceFileName - Cisco File Name> -c <CompareFileName - Topsec File Name>")
                sys.exit(0)
            elif opt in ("-s", "--sourcefile"):
                fileName_dict["cisco_filename"] = arg
            elif opt in ("-c", "--comparablefile"):
                fileName_dict["topsec_filename"] = arg
    except getopt.GetoptError:
        print("Check The Input Command Format!")
        print("python3 CessTop.py -s <SourceFileName - Cisco File Name> -c <CompareFileName - Topsec File Name>")
        sys.exit(2)
    return fileName_dict


if __name__ == "__main__":
    # Initial Local Config
    local_config = config.default_config_dict["default"]()

    # Check Command Correct And Obtain Config File Name
    filename_dict = Command_SplitFunction(sys.argv[1:])

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
    compare_process = Process(target=compare_instance.Start_Processing, args=(compare_instance, queue_cisco, queue_topsec,))

    cisco_process.start()
    topsec_process.start()
    compare_process.start()

    cisco_process.join()
    topsec_process.join()
    compare_process.join()
