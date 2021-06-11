#!/usr/bin/python3
#
# CessTop - TopSec Config Files Process Functions
#
#
#
#
#
#

import re
import time

import config
import asyncio
from tqdm import tqdm
from typing import Optional
import multiprocessing
import pandas as pd

unrecognized_config = list()

class Topsec_Function(object):

    @staticmethod
    async def Process_GroupAddress_Raw_List(self, queue_groupList: asyncio.Queue):
        """
        :param self:  TopSec_Function Instance
        :param queue_groupList: asyncio Queue to transfer content
        """
        try:
            with open(self.filename, "r") as group_info:
                log_lineContent = group_info.readline()
                while log_lineContent:
                    entire_str = ""
                    if re.match(self.re_topsec_group, log_lineContent):

                        entire_str += log_lineContent.replace('\'', " ").replace("\n", "")
                        log_lineContent = group_info.readline()
                        while (not re.match(self.re_topsec_group_stop, log_lineContent)) and log_lineContent:
                            entire_str += log_lineContent.replace('\'', " ").replace("\n", "")
                            log_lineContent = group_info.readline()
                        entire_str = entire_str.strip() + "\n"
                        if queue_groupList.full():
                            await queue_groupList.join()
                        await queue_groupList.put(entire_str)
                    else:
                        log_lineContent = group_info.readline()
        except Exception as err:
            print(err)
            exit(0)
        finally:
            if queue_groupList.full():
                await queue_groupList.join()
            await queue_groupList.put("complete_process")
            return "Process_GroupAddress_Raw_List - complete"

    @staticmethod
    async def Process_GroupAddress_toDict(self, queue_groupList: asyncio.Queue):
        """
        :param self:
        :param queue_groupList:
        :return:
        """
        item: str
        while True:
            item = await queue_groupList.get()
            queue_groupList.task_done()
            if queue_groupList.empty() and isinstance(item, str):
                return "Process_GroupAddress_toDict - complete"
            group_list = item.split()
            self.group_dict[group_list[4]] = group_list[6:]

    @staticmethod
    def exchange_maskint(mask_int):
        mask_int = int(mask_int)
        bin_arr = ['0' for i in range(32)]
        for i in range(mask_int):
            bin_arr[i] = '1'
        tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
        tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
        return '.'.join(tmpmask)

    @classmethod
    async def Analyze_TopSec(cls, queue_pc: asyncio.Queue, queue_df: asyncio.Queue, each_line: Optional[str] = None):
        while True:
            # Obtain the content from asyncio.queue
            each_line = await queue_pc.get()
            queue_pc.task_done()

            # Check IF Don't Need to Continue this loop
            if queue_pc.empty() and each_line == "complete_process":
                await queue_df.join()
                await queue_df.put("complete_process")
                return "Analyze_TopSec Function - Complete!"

            # Split all the content
            Strip_Content = each_line.replace('\n', ' ').replace('\'', ' ').strip().split()
            default_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type"]

            try:
                # Initial return dict format
                input_data = dict().fromkeys(config.default_config_dict["default"].df_format, " ")

                # Initial Logical Processing
                # Default Processing in TopSec LogFile
                input_data[default_format[0]] = Strip_Content[0]
                input_data[default_format[1]] = ' '.join(Strip_Content[1:6])
                input_data[default_format[3]] = Strip_Content[6]  # accept/deny

                # Process the First Initial
                if Strip_Content[9] == "src":
                    input_data["Src_Type(host/any/object-group)"] = "host"
                    input_data["Src_Addr"] = Strip_Content[10]
                    input_data["Dst_Type(host/any/object-group)"] = "host"
                    input_data["Dst_Addr"] = Strip_Content[12]
                    input_data["Eq"] = "eq"
                    input_data["Port_Type"] = Strip_Content[14]
                    if Strip_Content[-1] == "on": input_data["Log"] = "log"
                elif Strip_Content[9] == "slog":
                    if Strip_Content[11] == "srcarea" and Strip_Content[13] == "dstarea":
                        if "-" in Strip_Content[16]:
                            input_data["Src_Addr"] = Strip_Content[16]
                            if '/' in Strip_Content[18]:
                                input_data["Dst_Addr"] = Strip_Content[18].split('/')[0]
                                input_data["Dst_Mask"] = cls.exchange_maskint(Strip_Content[18].split('/')[1])
                            else:
                                input_data["Dst_Addr"] = Strip_Content[18]
                            if Strip_Content[19] == "service":
                                input_data["Eq"] = "eq"
                                input_data["Port_Type"] = Strip_Content[20]
                            if Strip_Content[-1] == "on": input_data["Log"] = "log"
                        else:
                            if '/' in Strip_Content[16]:
                                input_data["Src_Addr"] = Strip_Content[16].split('/')[0]
                                input_data["Src_Mask"] = cls.exchange_maskint(Strip_Content[16].split('/')[1])
                            else:
                                input_data["Src_Addr"] = Strip_Content[16]

                            if '/' in Strip_Content[18]:
                                input_data["Dst_Addr"] = Strip_Content[18].split('/')[0]
                                input_data["Dst_Mask"] = cls.exchange_maskint(Strip_Content[18].split('/')[1])
                            else:
                                input_data["Dst_Addr"] = Strip_Content[18]
                            if Strip_Content[19] == "service":
                                input_data["Eq"] = "eq"
                                input_data["Port_Type"] = Strip_Content[20]
                            if Strip_Content[-1] == "on": input_data["Log"] = "log"
                    else:
                        if Strip_Content[13] == "src":
                            if '/' in Strip_Content[14]:
                                input_data["Src_Addr"] = Strip_Content[14].split('/')[0]
                                input_data["Src_Mask"] = cls.exchange_maskint(Strip_Content[14].split('/')[1])
                            else:
                                input_data["Src_Addr"] = Strip_Content[14]
                            input_data["Dst_Addr"] = Strip_Content[16]
                            if Strip_Content[-1] == "on": input_data["Log"] = "log"
                        elif Strip_Content[11] == "src":
                            if '/' in Strip_Content[11]:
                                input_data["Src_Addr"] = Strip_Content[11].split('/')[0]
                                input_data["Src_Mask"] = cls.exchange_maskint(Strip_Content[11].split('/')[1])
                            else:
                                input_data["Src_Addr"] = Strip_Content[11]
                            if '/' in Strip_Content[13]:
                                input_data["Dst_Addr"] = Strip_Content[13].split('/')[0]
                                input_data["Dst_Mask"] = cls.exchange_maskint(Strip_Content[13].split('/')[1])
                            else:
                                input_data["Dst_Addr"] = Strip_Content[13]
                        else:
                            print(each_line)
                elif Strip_Content[9] == "srcarea" and Strip_Content[11] == "dstarea":
                    if "-" in Strip_Content[14]:
                        input_data["Src_Addr"] = Strip_Content[14]
                        if '/' in Strip_Content[16]:
                            input_data["Dst_Addr"] = Strip_Content[16].split('/')[0]
                            input_data["Dst_Mask"] = cls.exchange_maskint(Strip_Content[16].split('/')[1])
                        else:
                            input_data["Dst_Addr"] = Strip_Content[16]
                        if Strip_Content[17] == "service":
                            input_data["Eq"] = "eq"
                            input_data["Port_Type"] = Strip_Content[18]
                        if Strip_Content[-1] == "on": input_data["Log"] = "log"
                    else:
                        if '/' in Strip_Content[14]:
                            input_data["Src_Addr"] = Strip_Content[14].split('/')[0]
                            input_data["Src_Mask"] = cls.exchange_maskint(Strip_Content[14].split('/')[1])
                        else:
                            input_data["Src_Addr"] = Strip_Content[14]

                        if '/' in Strip_Content[16]:
                            input_data["Dst_Addr"] = Strip_Content[16].split('/')[0]
                            input_data["Dst_Mask"] = cls.exchange_maskint(Strip_Content[16].split('/')[1])
                        else:
                            input_data["Dst_Addr"] = Strip_Content[16]
                        if Strip_Content[17] == "service":
                            input_data["Eq"] = "eq"
                            input_data["Port_Type"] = Strip_Content[18]
                        if Strip_Content[-1] == "on": input_data["Log"] = "log"

                elif Strip_Content[9] == "srcarea" and Strip_Content[11] == "src":
                    if '/' in Strip_Content[12]:
                        input_data["Src_Addr"] = Strip_Content[12].split('/')[0]
                        input_data["Src_Mask"] = cls.exchange_maskint(Strip_Content[12].split('/')[1])
                    else:
                        input_data["Src_Addr"] = Strip_Content[12]

                    if '/' in Strip_Content[14]:
                        input_data["Dst_Addr"] = Strip_Content[14].split('/')[0]
                        input_data["Dst_Mask"] = cls.exchange_maskint(Strip_Content[14].split('/')[1])
                    else:
                        input_data["Dst_Addr"] = Strip_Content[14]
                else:
                    print(each_line)
            except (NameError, TypeError, RuntimeError, IndexError) as err:
                # print(each_line)
                unrecognized_config.append(each_line)
            finally:
                if queue_df.full():
                    await queue_df.join()
                await queue_df.put(input_data)

    @staticmethod
    async def Obtain_TopSec_Strategy(self, queue_pc: asyncio.Queue):

        # Filename is TopSec Config File Name
        with open(self.filename, "r") as topsecFile:
            # 逐行读取文本内容
            log_lineContent = topsecFile.readline()
            while log_lineContent:
                entire_str = ""
                if re.match(self.re_topsec, log_lineContent):
                    entire_str += log_lineContent.lstrip().replace("\n", "")
                    log_lineContent = topsecFile.readline()
                    while (not re.match(self.re_topsec, log_lineContent)) and log_lineContent and (
                            not re.match(self.re_topsec_content_stop, log_lineContent)):
                        entire_str += log_lineContent.replace("\n", "")
                        log_lineContent = topsecFile.readline()
                    entire_str = entire_str.strip() + "\n"
                    # After Process The Content of CessTop File - entire_str
                    if queue_pc.full():
                        await queue_pc.join()
                    await queue_pc.put(entire_str)
                else:
                    log_lineContent = topsecFile.readline()
            # IF ALL Contents have processed done -> send terminate signal
            if queue_pc.full():
                await queue_pc.join()
            await queue_pc.put("complete_process")
        return "Finished Extract Firewall Policy From Config File"

    @staticmethod
    async def LogFile_toList(self, queue_df: asyncio.Queue):
        """
        :param self:
        :param queue_df:
        """
        # For Version 2.0, The old code block below limits the performance of creating the Pandas DataFrame
        # for item in content_list:
        #     try:
        #         self.df_topsec = self.df_topsec.append(self.Analyze_TopSec(each_line=item), ignore_index=True)
        #     except (NameError, TypeError, RuntimeError, IndexError) as err:
        #         config.Logger.log_warning("Below Config is not Supported by this Program! Please Check")
        #         print(item)

        # New Version 2.1:
        while True:
            process_dict = await queue_df.get()
            queue_df.task_done()
            if queue_df.empty() and process_dict == "complete_process":
                return "LogFile_toList Function - complete"
            self.df_dict_list.append(process_dict)

    @staticmethod
    def Dictlist_toDataFrame(self):
        """
        :param self: TopSec_Function Instance
        """
        self.df_topsec = pd.DataFrame(self.df_dict_list,
                                      columns=config.Default_Config.df_format)

    @staticmethod
    async def asyncio_Start(self):
        """
        :param self: TopSec_Function Instance
        Function: asyncio Start Function
        """
        tasks = []
        queue_pc = asyncio.Queue(maxsize=10)
        queue_df = asyncio.Queue(maxsize=10)
        queue_groupList = asyncio.Queue(maxsize=10)

        # Producer
        task_topsec_rareFileProcess = asyncio.create_task(self.Obtain_TopSec_Strategy(self=self,
                                                                                      queue_pc=queue_pc))
        task_top_analyzeProcess = asyncio.create_task(self.Analyze_TopSec(queue_pc=queue_pc,
                                                                          queue_df=queue_df))
        task_LogFile_toList = asyncio.create_task(self.LogFile_toList(self=self,
                                                                      queue_df=queue_df))

        task_Group_Producer = asyncio.create_task(self.Process_GroupAddress_Raw_List(self=self,
                                                                                     queue_groupList=queue_groupList))

        task_Group_Consumer = asyncio.create_task(self.Process_GroupAddress_toDict(self=self,
                                                                                   queue_groupList=queue_groupList))
        # Append Tasks
        tasks.append(task_topsec_rareFileProcess)
        tasks.append(task_top_analyzeProcess)
        tasks.append(task_LogFile_toList)
        tasks.append(task_Group_Producer)
        tasks.append(task_Group_Consumer)

        # Concurrency Run
        try:
            # results_df = await asyncio.gather(*tasks, return_exceptions=True)
            # for task in tasks:
            #     task.cancel()

            # ProgressBar Show
            bar = tqdm(total=len(tasks), nrows=4, ncols=130, desc="TopSec Process")
            for f in asyncio.as_completed(tasks):
                result = await f
                # bar.set_description("TopSec Process - {}".format(result))
                bar.update()
            bar.close()
        except asyncio.CancelledError:
            print("UnExpected Error! - The TopSec Processing unexpectedly cancel!")
            exit(0)

    @staticmethod
    def Start_Processing(self, queue: multiprocessing.Queue):
        """
        :param self: TopSec
        :param queue: multiprocessing.Queue
        """
        try:
            asyncio.run(self.asyncio_Start(self=self))
            self.Dictlist_toDataFrame(self=self)
        except Exception as err:
            raise err
        finally:
            queue.put(self.df_topsec)
            queue.put(self.group_dict)
            queue.put(unrecognized_config)
            self.df_topsec.to_csv(config.default_config_dict["default"].topsec_csv_Name,
                                  sep=",",
                                  header=config.default_config_dict["default"].df_format,
                                  index=True)

    def __init__(self, filename: str):
        self.filename = filename
        self.df_topsec = None
        self.df_dict_list = list()
        self.group_dict = dict()
        self.unrecognized_config = list()
        self.re_topsec_group = re.compile(r'^define group_address add')
        self.re_topsec_group_stop = re.compile(r'^define')
        self.re_topsec = re.compile(r'firewall policy add name')
        self.re_topsec_content_stop = re.compile(r'firewall policy conflict ')
