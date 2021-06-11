#!/usr/bin/python3
#
# CessTop - TopSec Config Files Process Functions
#
# compare_function
#
#
#
#
import config
import cess_warn
import tqdm
import pandas as pd
import multiprocessing


class Compare_Function(object):
    """
        Function designed to compare with different dataframe
    """

    @staticmethod
    def exchange_mask(mask: str):
        """
        :param mask:
        :type mask:
        :return:
        :rtype:
        """
        # 计算二进制字符串中 '1' 的个数
        count_bit = lambda bin_str: len([i for i in bin_str if i == '1'])
        # 分割字符串格式的子网掩码为四段列表
        mask_splited = mask.split('.')
        # 转换各段子网掩码为二进制, 计算十进制
        mask_count = [count_bit(bin(int(i))) for i in mask_splited]
        return str(sum(mask_count))

    @staticmethod
    def Process_DF_withGroupDict(self, input_df: pd.DataFrame, group_dict: dict, convert_source="all"):
        """
        :param convert_source: determine the convert parameter (src or dst or all)
        :type convert_source: str
        :param self:
        :type self:
        :param input_df:
        :type input_df:
        :param group_dict:
        :type group_dict:
        :return:
        :rtype:
        """
        # 开始遍历整个数组并开始替换工作
        df_compare = input_df.copy()
        for sid, row in df_compare.iterrows():
            if convert_source in ["all", "src"]:
                compare_str = None
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
            if convert_source in ["all", "dst"]:
                compare_str = None
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
    def cisco_compare_topsec(self,
                             df_cisco_transfer: pd.DataFrame,
                             df_cisco: pd.DataFrame,
                             df_topsec: pd.DataFrame,
                             df_topsec_transfer: pd.DataFrame):
        """
        :param self:
        :type self:
        :param df_cisco_transfer:
        :type df_cisco_transfer:
        :param df_cisco:
        :type df_cisco:
        :param df_topsec:
        :type df_topsec:
        :param df_topsec_transfer:
        :type df_topsec_transfer:
        :return:
        :rtype:
        """
        df_list = list()

        # Cisco DF (Converted) compares with TopSec DF
        # Cisco Df contains two key parameters: sid / df_data(diff_row)
        for sid, diff_row in df_cisco.iterrows():
            temp_check = None
            temp_check = df_topsec[(df_topsec["Src_Addr"] == diff_row["Src_Addr"])]
            temp_check = temp_check[(temp_check["Dst_Addr"] == diff_row["Dst_Addr"])]

            # if IP addr in object-group / We should avoid comparing Mask
            if '-' not in temp_check["Src_Addr"] and not temp_check.empty:
                temp_check = temp_check[(temp_check["Src_Mask"] == diff_row["Src_Mask"])]

            if '-' not in temp_check["Dst_Addr"] and not temp_check.empty:
                temp_check = temp_check[(temp_check["Dst_Mask"] == diff_row["Dst_Mask"])]

            temp_check = temp_check[(temp_check["Port_Type"].str.contains(diff_row["Port_Type"], case=False))]

            # temp_check = temp_check[(
            #     temp_check["Src_Type(host/any/object-group)"] == diff_row["Src_Type(host/any/object-group)"])]
            #
            # temp_check = temp_check[(
            #     temp_check["Dst_Type(host/any/object-group)"] == diff_row["Dst_Type(host/any/object-group)"])]

            if temp_check.empty:
                df_list.append(int(sid))

        # Src Convert Compare
        df_diff_out_convertSrc = self.Process_DF_withGroupDict(self,
                                                               input_df=df_cisco.loc[df_list],
                                                               group_dict=self.dict_group,
                                                               convert_source="src")
        for num in df_list.copy():
            temp_check = None
            temp_df = df_diff_out_convertSrc.loc[num]
            temp_check = df_topsec[(df_topsec["Src_Addr"] == temp_df["Src_Addr"])]
            temp_check = temp_check[(temp_check["Src_Mask"] == temp_df["Src_Mask"])]
            temp_check = temp_check[(temp_check["Dst_Addr"] == temp_df["Dst_Addr"])]
            temp_check = temp_check[(temp_check["Dst_Mask"] == temp_df["Dst_Mask"])]
            temp_check = temp_check[(temp_check["Port_Type"].str.contains(temp_df["Port_Type"], case=False))]
            # 不符合记录
            if not temp_check.empty:
                df_list.remove(num)

        # Dst Convert Compare
        df_diff_out_convertDst = self.Process_DF_withGroupDict(self,
                                                               input_df=df_cisco.loc[df_list],
                                                               group_dict=self.dict_group,
                                                               convert_source="dst")
        for sid in df_list.copy():
            temp_check = None
            temp_df = df_diff_out_convertDst.loc[sid]
            temp_check = df_topsec[(df_topsec["Src_Addr"] == temp_df["Src_Addr"])]
            temp_check = temp_check[(temp_check["Src_Mask"] == temp_df["Src_Mask"])]
            temp_check = temp_check[(temp_check["Dst_Addr"] == temp_df["Dst_Addr"])]
            temp_check = temp_check[(temp_check["Dst_Mask"] == temp_df["Dst_Mask"])]
            temp_check = temp_check[(temp_check["Port_Type"].str.contains(temp_df["Port_Type"], case=False))]
            # 不符合添加输出
            if not temp_check.empty:
                df_list.remove(sid)

        # Convert All
        df_diff_out_convertAll = self.Process_DF_withGroupDict(self,
                                                               input_df=df_cisco.loc[df_list],
                                                               group_dict=self.dict_group,
                                                               convert_source="all")
        for sid in df_list.copy():
            temp_check = None
            temp_df = df_diff_out_convertAll.loc[sid]
            temp_check = df_topsec[(df_topsec["Src_Addr"] == temp_df["Src_Addr"])]
            temp_check = temp_check[(temp_check["Src_Mask"] == temp_df["Src_Mask"])]
            temp_check = temp_check[(temp_check["Dst_Addr"] == temp_df["Dst_Addr"])]
            temp_check = temp_check[(temp_check["Dst_Mask"] == temp_df["Dst_Mask"])]
            temp_check = temp_check[(temp_check["Port_Type"].str.contains(temp_df["Port_Type"], case=False))]
            # 不符合添加输出
            if not temp_check.empty:
                df_list.remove(sid)

        # 最后输出
        return df_cisco.loc[df_list]

    @staticmethod
    def Start_Processing(self,
                         queue_cisco: multiprocessing.Queue,
                         queue_topsec: multiprocessing.Queue):
        """
        :param self:
        :type self:
        :param queue_cisco:
        :type queue_cisco:
        :param queue_topsec:
        :type queue_topsec:
        """
        while True:
            if queue_cisco.full() and queue_topsec.full():
                df_cisco = queue_cisco.get()
                df_topsec = queue_topsec.get()
                self.dict_group = queue_topsec.get()
                unrecognized_config = queue_topsec.get()
                try:
                    tq = tqdm.tqdm(total=4, ncols=130, nrows=4, desc="Compare Module Progress")
                    df_cisco_transfer = self.Process_DF_withGroupDict(self, df_cisco, group_dict=self.dict_group)
                    tq.update()
                    df_topsec_transfer = self.Process_DF_withGroupDict(self, df_topsec, group_dict=self.dict_group)
                    tq.update()
                    result_df = self.cisco_compare_topsec(self,
                                                          df_cisco_transfer=df_cisco_transfer,
                                                          df_cisco=df_cisco,
                                                          df_topsec_transfer=df_topsec_transfer,
                                                          df_topsec=df_topsec)
                    tq.update()
                    result_df.to_csv(config.default_config_dict["default"].result_file_name,
                                     sep=',',
                                     header=config.default_config_dict["default"].df_format,
                                     index=True)
                    tq.update()
                    tq.close()
                except (TypeError, RuntimeError, NameError) as err:
                    print("error occur:" % err)
                finally:
                    cess_warn.cesstop_warning.show_warninfo(warn_info=unrecognized_config)
                    config.Logger.complete_show("Successfully Run Comparison!")
                    config.Logger.complete_show("Please Check ./output/result.csv for details")
                    config.Logger.info_show(" ")
                    config.Logger.info_show("##################################################")
                    config.Logger.info_show(
                        "Thanks for your Usage... Any Questions Please Email: doherasyanng@gmail.com")
                    config.Logger.info_show("Developed By DoHeras@June 2021")
                    break

    def __init__(self, rule: str):
        self.df_compare = None
        self.dict_group = None
