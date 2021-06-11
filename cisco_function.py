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
import sys
import asyncio
import time
from typing import Optional, Sequence, Set
import config
from tqdm import tqdm
from rich.console import Console
from rich.progress import Progress
import multiprocessing
import pandas as pd


# define Cisco class
class Cisco_Function(object):
    """
        Class Cisco_Function is designed to Parse and Return the Pandas DataFrame
        Version 2.1
    """

    @classmethod
    async def Analyze_CiscoContent(cls,
                                   queue_pc: asyncio.Queue,
                                   queue_df: asyncio.Queue,
                                   each_content: Optional[str] = None):
        """
        - Version 2.0 define this function is synchronization without async
          each_content is each line of config from the Cisco File

        - Version 2.1 Change this function nto async function:
        - only wait the queue to pass each line content from other coroutine
        - Reserve the

        :param each_content: each line of config file
        :return: Dict variable parameter - used to append the DataFrame from List
        -
        -
        -
        -
        """
        while True:
            each_content = await queue_pc.get()
            queue_pc.task_done()
            if queue_pc.empty() and each_content == "readline_complete" and queue_df.empty():
                await queue_df.put("readline_complete")
                return "Finished! - Analyse Cisco Content"

            strip_Content = each_content.strip().split()
            insert_data = dict().fromkeys(config.default_config_dict["default"].df_format, " ")

            # Initialize the Dictionary
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

            if queue_df.full():
                await queue_df.join()
            await queue_df.put(insert_data)

    @staticmethod
    async def Process_Cisco_LogFile_ToList(self, queue_pc: asyncio.Queue, filename: Optional[str] = None):
        """
        :param filename: Correct File Name (str) or None Which could raise the FileNotFound Error
        :return: Fresh List which stores each line of cisco firewall rules

        function: Process Function to Format the Cisco Log File
                  In Cisco Log File, Need to Focus on the Line starting with "access-list" for now Version 2.x
        """
        re_cisco_access_list_header = re.compile(r'access-list')
        try:
            with open(filename, "r") as ciscoFile:
                log_lineContent = ciscoFile.readline()
                while log_lineContent:
                    if re.match(re_cisco_access_list_header, log_lineContent):
                        if queue_pc.full():
                            await queue_pc.join()
                        await queue_pc.put(log_lineContent)
                        self.total_lineNum += 1
                    log_lineContent = ciscoFile.readline()
                # Put the Last label into asyncio.queue
                if queue_pc.full():
                    await queue_pc.join()
                await queue_pc.put("readline_complete")

        except IOError:
            config.Logger.log_fail("Error! -- Can't Find Your Cisco Config File")
            config.Logger.log_fail("Please Check Your Cisco Config File....")
            sys.exit(1)

    @staticmethod
    async def LogFileDict_toList(self, queue_df: asyncio.Queue, Logfile_List: Optional[list] = None) -> str:
        """
        :param self: Cisco_Function new instance
        :param Logfile_List: List which stores each line of Cisco firewall config
        """
        # Version 2.0 - old Question / Code execution efficiency big problem
        # for item in Logfile_List:
        #     self.df_cisco = self.df_cisco.append(self.Analyze_CiscoContent(each_content=item), ignore_index=True)

        # Create New List to store all generated dict improve from 34062ms to 34ms about 1000x
        # Version 2.1 - New Version / -> Store each config line in dict and Creat New DataFrame
        #
        while True:
            insert_dict = await queue_df.get()
            queue_df.task_done()
            if queue_df.empty() and insert_dict == "readline_complete":
                return "Finished! - LogFileDict_toList"
            self.dict_list.append(insert_dict)
            self.current_sidNum += 1

    @staticmethod
    def Create_DF(self):
        """
        :param self:  Cisco_Function instance
        """
        self.df_cisco = pd.DataFrame(self.dict_list,
                                     columns=config.Default_Config.df_format)

    @staticmethod
    def Display_Bar(self):
        """
        :param self: Cisco_Function Instance
        :type self: Cisco_Function Instance
        """
        # with tqdm(total=10000, leave=True, position=0) as temp:
        #     while True:
        #         if temp.total != self.total_lineNum:
        #             temp.total = self.total_lineNum
        #             temp.refresh()
        #         temp.set_description("Have Processed {} Cisco Configs".format(temp.n))
        #         temp.update(self.current_sidNum - temp.n)
        #         if self.total_lineNum == self.current_sidNum: break
        # return "Succeed"

        # bar_range = tqdm(total=100000, position=0, leave=True)
        # while True:
        #     if bar_range.total != self.total_lineNum:
        #         bar_range.total = self.total_lineNum
        #         bar_range.refresh()
        #     bar_range.set_description("已经处理了{}条配置".format(self.current_sidNum))
        #     bar_range.update(self.current_sidNum - bar_range.n)
        # bar_range.close()

        # Rich Implement
        with Progress(auto_refresh=False) as cisco_pro:
            task1 = cisco_pro.add_task("[green]Cisco Extracting Processing...", total=1000)
            while not cisco_pro.finished:
                cisco_pro.update(task1, advance=0.3)
                time.sleep(0.2)

    @staticmethod
    async def asyncio_start(self):
        """
        :param self: Cisco_Funciton
        """
        tasks = []
        # Make Sure the least queue size to reduce burden of the system
        queue_pc = asyncio.Queue(maxsize=10)
        queue_df = asyncio.Queue(maxsize=10)

        # Create Tasks Queue to Run Handling the Files
        task_processFile = asyncio.create_task(self.Process_Cisco_LogFile_ToList(
            self=self,
            queue_pc=queue_pc,
            filename=self.filename))

        task_analyseFile = asyncio.create_task(self.Analyze_CiscoContent(
            queue_pc=queue_pc,
            queue_df=queue_df))

        task_dict2list = asyncio.create_task(self.LogFileDict_toList(
            self=self,
            queue_df=queue_df))

        # self.Display_Bar(self=self)

        tasks.append(task_processFile)
        tasks.append(task_analyseFile)
        tasks.append(task_dict2list)

        # ERROR Catch
        try:
            # results = await asyncio.gather(*tasks, return_exceptions=True)
            # for task in tasks:
            #     task.cancel()
            bar = tqdm(total=len(tasks), ncols=130, desc="Cisco Process", nrows=3)
            for f in asyncio.as_completed(tasks):
                result = await f
                bar.update()
            bar.close()
        except asyncio.CancelledError:
            print("UnExpected Error! - The Cisco Processing unexpectedly cancel!")
            exit(0)

    @staticmethod
    def Start_Processing(self, queue_multi: multiprocessing.Queue):

        """
        :param self: Cisco_Function new instance
        :param queue: multiprocessing.queue to transform the variables
        """

        try:
            asyncio.run(self.asyncio_start(self=self))
            self.Create_DF(self=self)
        except Exception as err:
            raise err
        finally:
            queue_multi.put(self.df_cisco)
            self.df_cisco.to_csv(config.default_config_dict["default"].cisco_csv_Name,
                                 sep=',',
                                 header=config.default_config_dict["default"].df_format,
                                 index=True)

    def __init__(self, out_filename: str):
        self.access_list = list()
        self.total_lineNum = 0
        self.current_sidNum = 1
        self.filename = out_filename
        self.dict_list = list()
        self.df_cisco = None
