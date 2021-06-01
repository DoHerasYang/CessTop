#!/usr/bin/python3
#
# CessTop - TopSec Config Files Process Functions
#
#
#
#
#
#
import config
import pandas as pd
import multiprocessing


class Compare_Function(object):

    @staticmethod
    def exchange_mask(mask):
        # 计算二进制字符串中 '1' 的个数
        count_bit = lambda bin_str: len([i for i in bin_str if i == '1'])
        # 分割字符串格式的子网掩码为四段列表
        mask_splited = mask.split('.')
        # 转换各段子网掩码为二进制, 计算十进制
        mask_count = [count_bit(bin(int(i))) for i in mask_splited]
        return str(sum(mask_count))

    @staticmethod
    def Process_DF_withGroupDict(self, input_df: pd.DataFrame, group_dict: dict):

        # 开始遍历整个数组并开始替换工作
        df_compare = input_df.copy()

        for sid, row in df_compare.iterrows():
            compare_str = ""
            # 处理第一个Addr组
            if row["Src_Mask"] != " ":
                compare_str = row["Src_Addr"] + '/' + self.exchange_mask(row["Src_Mask"])
                for item in group_dict:
                    if compare_str in group_dict[item]:
                        row["Src_Addr"] = item
                        row["Src_Mask"] = " "
                        row["Src_Type(host/any/object-group)"] = "object-group"
            else:
                for item in group_dict:
                    if row["Src_Addr"] in group_dict[item]:
                        row["Src_Addr"] = item
                        row["Src_Type(host/any/object-group)"] = "object-group"


            # 处理第二个Addr组
            compare_str = ""
            if row["Dst_Mask"] != " ":
                compare_str = row["Dst_Addr"] + '/' + self.exchange_mask(row["Dst_Mask"])
                for item in group_dict:
                    if compare_str in group_dict[item]:
                        row["Dst_Addr"] = item
                        row["Dst_Mask"] = " "
                        row["Dst_Type(host/any/object-group)"] = "object-group"
            else:
                for item in group_dict:
                    if row["Dst_Addr"] in group_dict[item]:
                        row["Dst_Addr"] = item
                        row["Dst_Type(host/any/object-group)"] = "object-group"
        return df_compare

    # Comparable Algorithm Module
    #
    # In Topsec Config Files, The Original Cisco File includes the Old IP Addresses which have been included in
    # Topsec Config Files
    #
    # Comparable Criteria：Src_Addr /  Src_Mask / Dst_Addr / Dst_Mask / Port_Type

    @staticmethod
    def cisco_compare_topsec(self, df_cisco_transfer: pd.DataFrame, df_cisco: pd.DataFrame, df_topsec: pd.DataFrame,
                             df_topsec_transfer: pd.DataFrame):

        df_diff_temp = pd.DataFrame(columns=config.default_config_dict["default"].df_format)
        df_diff_output = pd.DataFrame(columns=config.default_config_dict["default"].df_format)

        # Cisco DF (Converted) compares with TopSec DF
        # Cisco Df contains two key parameters: sid / df_data(diff_row)
        for sid, diff_row in df_cisco_transfer.iterrows():
            temp_check = None
            temp_check = df_topsec_transfer[(df_topsec_transfer["Src_Addr"] == diff_row["Src_Addr"])]
            temp_check = temp_check[(temp_check["Dst_Addr"] == diff_row["Dst_Addr"])]
            # if IP addr in object-group / We should avoid comparing Mask
            if '-' not in temp_check["Src_Addr"]:
                temp_check = temp_check[(temp_check["Src_Mask"] == diff_row["Src_Mask"])]

            if '-' not in temp_check["Dst_Addr"]:
                temp_check = temp_check[(temp_check["Dst_Mask"] == diff_row["Dst_Mask"])]

            temp_check = temp_check[(temp_check["Port_Type"].str.contains(diff_row["Port_Type"], case=False))]

            print("Before Src")
            print(temp_check["Src_Type(host/any/object-group)"].values)
            print(diff_row["Src_Type(host/any/object-group)"])
            print(temp_check["Dst_Type(host/any/object-group)"].values)
            print(diff_row["Dst_Type(host/any/object-group)"])

            temp_check = temp_check[(
                    temp_check["Src_Type(host/any/object-group)"].str.contains(diff_row["Src_Type(host/any/object-group)"], case=False)
            )]

            if temp_check.empty:
                print(str(sid) +"Src_type")

            print(temp_check["Dst_Type(host/any/object-group)"].values)
            print(diff_row["Dst_Type(host/any/object-group)"])

            temp_check = temp_check[(
                    temp_check["Dst_Type(host/any/object-group)"].str.contains(diff_row["Dst_Type(host/any/object-group)"], case=False)
            )]

            if temp_check.empty:
                print(str(sid) + "Dst_type")

            if temp_check.empty:
                df_diff_temp = df_diff_temp.append(df_cisco.iloc[sid], ignore_index=False)

        # 都不变比较
        for sid, diff_row in df_diff_temp.iterrows():
            temp_check = None
            temp_check = df_topsec[(df_topsec["Src_Addr"] == diff_row["Src_Addr"])]
            temp_check = temp_check[(temp_check["Src_Mask"] == diff_row["Src_Mask"])]
            temp_check = temp_check[(temp_check["Dst_Addr"] == diff_row["Dst_Addr"])]
            temp_check = temp_check[(temp_check["Dst_Mask"] == diff_row["Dst_Mask"])]
            temp_check = temp_check[(temp_check["Port_Type"].str.contains(diff_row["Port_Type"], case=False))]
            # 不符合添加输出
            if temp_check.empty:
                df_diff_output = df_diff_output.append(df_cisco.iloc[sid], ignore_index=False)

        return df_diff_temp

    @staticmethod
    def Start_Processing(self, queue_cisco: multiprocessing.Queue, queue_topsec: multiprocessing.Queue):
        while True:
            if queue_cisco.full() and queue_topsec.full():
                df_cisco = queue_cisco.get()
                df_topsec = queue_topsec.get()
                dict_group = queue_topsec.get()
                try:
                    df_cisco_transfer = self.Process_DF_withGroupDict(self, df_cisco, group_dict=dict_group)
                    df_topsec_transfer = self.Process_DF_withGroupDict(self, df_topsec, group_dict=dict_group)
                    result_df = self.cisco_compare_topsec(self,
                                                          df_cisco_transfer=df_cisco_transfer,
                                                          df_cisco=df_cisco,
                                                          df_topsec_transfer=df_topsec_transfer,
                                                          df_topsec=df_topsec)
                    result_df.to_csv(config.default_config_dict["default"].result_file_name,
                                     sep=',',
                                     header=config.default_config_dict["default"].df_format,
                                     index=True)
                except (TypeError, RuntimeError, NameError) as err:
                    print("error occur:" % err)
                finally:
                    config.Logger.log_fail("Successfully Run Comparison!")
                    config.Logger.log_fail("Please Check ./output/result.csv for details")
                    break

    def __init__(self):
        self.df_compare = None
