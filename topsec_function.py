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
import config
import multiprocessing
import pandas as pd


class Topsec_Function(object):

    @staticmethod
    def Process_GroupAddress_Raw_List(self) -> list:
        result = list()
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
                    result.append(entire_str)
                else:
                    log_lineContent = group_info.readline()
        return result

    @staticmethod
    def Process_GroupAddress_toDict(input_List: list):
        # Traverse All lists
        result_dict = dict()
        for item in input_List:
            addr_list = item.split()
            result_dict[addr_list[4]] = addr_list[6:]
        return result_dict

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
    def Analyze_TopSec(cls, each_line: str):
        # Split all the content
        Strip_Content = each_line.replace('\n', ' ').replace('\'', ' ').strip().split()
        default_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type"]
        # Dictionary
        input_data = dict().fromkeys(config.default_config_dict["default"].df_format, " ")
        # 开始判断逻辑
        # 先编写默认的相关操作
        input_data[default_format[0]] = Strip_Content[0]
        input_data[default_format[1]] = ' '.join(Strip_Content[1:6])
        input_data[default_format[3]] = Strip_Content[6]  # accept/deny
        # 处理 第一个为 src 的情况
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
        return input_data

    @staticmethod
    def Obtain_TopSec_Strategy(self):
        # Topsec Content List
        topsec_list = list()
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
                    topsec_list.append(entire_str)
                else:
                    log_lineContent = topsecFile.readline()
        return topsec_list

    @staticmethod
    def LogFileList_toPandasDF(self, content_list: list):
        for item in content_list:
            try:
                self.df_topsec = self.df_topsec.append(self.Analyze_TopSec(each_line=item), ignore_index=True)
            except (NameError, TypeError, RuntimeError, IndexError) as err:
                config.Logger.log_warning("Below Config is not Supported by this Program! Please Check")
                print(item)

    @staticmethod
    # def Start_Processing(self):
    def Start_Processing(self, queue: multiprocessing.Queue):
        try:
            self.LogFileList_toPandasDF(self, content_list=self.Obtain_TopSec_Strategy(self))
        except Exception as err:
            raise err
        finally:
            self.group_dict = self.Process_GroupAddress_toDict(input_List=self.Process_GroupAddress_Raw_List(self))
            queue.put(self.df_topsec)
            queue.put(self.group_dict)
            self.df_topsec.to_csv(config.default_config_dict["default"].topsec_csv_Name,
                                  sep=",",
                                  header=config.default_config_dict["default"].df_format,
                                  index=True)

    def __init__(self, filename: str):
        self.filename = filename
        self.df_topsec = pd.DataFrame(columns=config.default_config_dict["default"].df_format)
        self.re_topsec_group = re.compile(r'^define group_address add')
        self.re_topsec_group_stop = re.compile(r'^define')
        self.re_topsec = re.compile(r'firewall policy add name')
        self.re_topsec_content_stop = re.compile(r'firewall policy conflict ')
        self.group_dict = dict()
