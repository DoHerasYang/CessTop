#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
#   CessTop Main Function ---
#
#
#
#
import cProfile as profile
from multiprocessing import Process, Pool, Lock, Queue

# Local File Import
import args
import config
import cisco_function
import topsec_function
import compare_function

# Main Entrance
if __name__ == "__main__":
    # Version 2 Parameter Progress
    # DisCard from Version 2.1
    # filename_dict = Command_SplitFunction(sys.argv[1:])

    filename_dict = args.Args_Define()  # dict_keys(['order', 'cisco_filename', 'topsec_filename', 'rule', 'model'])

    # Initial Local Config
    # Start Initial Function To Make
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
