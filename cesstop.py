#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
#   CessTop Main Function --- Dispatcher Module
#
#
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


# Dispatcher Function
def Dispatcher(dispatcher_dict: dict):
    """
        Dispatcher is used to create the entrance of entire program
    """
    queue_1 = Queue(maxsize=1)
    queue_2 = Queue(maxsize=2)
    instance_seq = list()
    process_seq = list()

    # Cisco File Compare With Cisco File
    if dispatcher_dict["rule"] == "Cisco_cmp_Cisco":
        cisco_src_instance1 = cisco_function.Cisco_Function(out_filename=dispatcher_dict["src_filename"])
        cisco_src_instance2 = cisco_function.Cisco_Function(out_filename=dispatcher_dict["target_filename"])
        instance_seq.append((cisco_src_instance1, queue_1))
        instance_seq.append((cisco_src_instance2, queue_2))
    elif dispatcher_dict["rule"] == "Cisco_cmp_TopSec":
        instance_seq.append((cisco_function.Cisco_Function(out_filename=dispatcher_dict["src_filename"]), queue_1))
        instance_seq.append((topsec_function.Topsec_Function(filename=dispatcher_dict["target_filename"]), queue_2))
    elif dispatcher_dict["rule"] == "TopSec_cmp_Cisco":
        instance_seq.append((topsec_function.Topsec_Function(filename=dispatcher_dict["src_filename"]), queue_1))
        instance_seq.append((cisco_function.Cisco_Function(out_filename=dispatcher_dict["target_filename"]), queue_2))
    elif dispatcher_dict["rule"] == "TopSec_cmp_TopSec":
        instance_seq.append((topsec_function.Topsec_Function(filename=dispatcher_dict["src_filename"]), queue_1))
        instance_seq.append((topsec_function.Topsec_Function(filename=dispatcher_dict["target_filename"]), queue_2))
    else:
        raise ValueError

    cmp_instance = compare_function.Compare_Function(rule=dispatcher_dict["rule"])

    # Initial Process - File Config Process
    #
    process_seq = [Process(target=instance.Start_Processing, args=(instance, queue,)) for instance, queue in instance_seq]
    process_cmp = Process(target=cmp_instance.Start_Processing, args=(cmp_instance, queue_1, queue_2,))
    process_seq.append(process_cmp)

    # Start Process
    for pro in process_seq:
        pro.start()

    for pro in process_seq:
        pro.join()


# Main Entrance
if __name__ == "__main__":
    # Version 2 Parameter Progress
    # DisCard from Version 2.1
    # filename_dict = Command_SplitFunction(sys.argv[1:])

    filename_dict = args.Args_Define()  # dict_keys(['order', 'cisco_filename', 'topsec_filename', 'rule', 'model'])

    # Initial Local Config
    local_config = config.default_config_dict["default"]()  # Start Initial Function To Create Folder and Check Path Information

    # Abandon From Version 2.1
    # Class Cisco_Function instance
    # cisco_instance = cisco_function.Cisco_Function(filename_dict["src_filename"])
    #
    # # Class TopSec_Function instance
    # topsec_instance = topsec_function.Topsec_Function(filename_dict["target_filename"])
    #
    # # Class Compare Function instance
    # compare_instance = compare_function.Compare_Function()
    #
    # # Define the Queue to Transport the Variable
    # queue_cisco = Queue(maxsize=1)
    # queue_topsec = Queue(maxsize=2)
    #
    # # MultiProcessing - Pool
    # cisco_process = Process(target=cisco_instance.Start_Processing, args=(cisco_instance, queue_cisco,))
    # topsec_process = Process(target=topsec_instance.Start_Processing, args=(topsec_instance, queue_topsec,))
    # compare_process = Process(target=compare_instance.Start_Processing,
    #                           args=(compare_instance, queue_cisco, queue_topsec,))
    #
    # cisco_process.start()
    # topsec_process.start()
    # compare_process.start()
    #
    # cisco_process.join()
    # topsec_process.join()
    # compare_process.join()

    Dispatcher(dispatcher_dict=filename_dict)
