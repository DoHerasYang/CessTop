import re
import os
import pandas as pd
import numpy as np
import sys, getopt

re_cisco_header = re.compile(r'access-list')
re_topsec = re.compile(r'firewall')
re_topsec_group = re.compile(r'^define group_address add')
re_topsec_group_stop = re.compile(r'^define')
re_topsec_content_stop = re.compile(r'firewall policy add name ')

df_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type",
             "Src_Type(host/any/object-group)", "Src_Addr", "Src_Mask", "Dst_Type(host/any/object-group)",
             "Dst_Addr", "Dst_Mask", "Eq", "Port_Type", "Log"]


def Analyze_CiscoContent(each_content: str, df_cisco: pd.DataFrame):
    # 将所有的空格取出，并进行判定；
    strip_Content = each_content.strip().split()
    default_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type"]
    # insert_data = {'Command': None, 'Category': None, 'Insert_Word': None, 'Type(permit/deny)': None,
    #                 'Packet_Type': None, 'Src_Type(host/any/object-group)': None, 'Src_Addr': None, 'Src_Mask': None,
    #                 'Dst_Type(host/any/object-group)': None, 'Dst_Addr': None, 'Dst_Mask': None, 'Eq': None,
    #                 'Port_Type': None, 'Log': None}
    sid = 0
    insert_data = dict().fromkeys(df_format, " ")
    for name in default_format:
        insert_data[name] = strip_Content[sid]
        sid += 1

    # 排除报文格式限制 - tcp / icmp
    if strip_Content[4] == "icmp":
        insert_data["Port_Type"] = "PING"

    if strip_Content[sid] == "host":
        insert_data["Src_Type(host/any/object-group)"] = "host"
        insert_data["Src_Addr"] = strip_Content[sid + 1]
        if strip_Content[sid + 2] == "host":
            insert_data["Dst_Type(host/any/object-group)"] = strip_Content[sid + 2]
            insert_data["Dst_Addr"] = strip_Content[sid + 3]
        elif strip_Content[sid + 2] == "any":
            insert_data["Dst_Addr"] = "any"
        else:
            insert_data["Dst_Addr"] = strip_Content[sid + 2]
            insert_data["Dst_Mask"] = strip_Content[sid + 3]
    # 如果是两个any的情况下
    elif strip_Content[sid] == "any":
        insert_data["Src_Addr"] = strip_Content[sid]
        insert_data["Dst_Addr"] = strip_Content[sid + 1]
    # 如果是出现组的情况，在思科下是： object-group
    elif strip_Content[sid] == "object-group":
        insert_data["Src_Type(host/any/object-group)"] = strip_Content[sid]
        insert_data["Src_Addr"] = strip_Content[sid + 1]
        if strip_Content[sid + 2] == "object-group":
            insert_data["Dst_Type(host/any/object-group)"] = strip_Content[sid + 2]
            insert_data["Dst_Addr"] = strip_Content[sid + 3]
        elif strip_Content[sid + 2] == "host":
            insert_data["Dst_Type(host/any/object-group)"] = strip_Content[sid + 2]
            insert_data["Dst_Addr"] = strip_Content[sid + 3]
        else:
            insert_data["Dst_Addr"] = strip_Content[sid + 2]
            insert_data["Dst_Mask"] = strip_Content[sid + 3]
    # 如果是网络地址的话就直接按情况存入
    else:
        insert_data["Src_Addr"] = strip_Content[sid]
        insert_data["Src_Mask"] = strip_Content[sid + 1]
        if strip_Content[sid + 2] == "host":
            insert_data["Dst_Type(host/any/object-group)"] = strip_Content[sid + 2]
            insert_data["Dst_Addr"] = strip_Content[sid + 3]
        elif strip_Content[sid + 2] == "any":
            insert_data["Dst_Addr"] = strip_Content[sid + 2]
        else:
            insert_data["Dst_Addr"] = strip_Content[sid + 2]
            insert_data["Dst_Mask"] = strip_Content[sid + 3]

    # 最后处理端口号
    if 'eq' in strip_Content:
        insert_data["Eq"] = "eq"
        index = strip_Content.index("eq")
        if strip_Content[index + 1] == "www":
            insert_data["Port_Type"] = "HTTP"
        elif strip_Content[index + 1] == "snmptrap":
            insert_data["Port_Type"] = "SNMP-TRAP"
        else:
            insert_data["Port_Type"] = strip_Content[index + 1]
    elif strip_Content[4] == "tcp" and ('eq' not in strip_Content):
        insert_data["Port_Type"] = "TCPALL"

    # 处理 range 字符的问题
    if 'range' in strip_Content:
        insert_data["Eq"] = "range"
        index = strip_Content.index("range")
        insert_data["Port_Type"] = strip_Content[index + 1] + "-" + strip_Content[index + 2]

    if 'log' in strip_Content:
        insert_data["Log"] = "log"

    # 现在已经获取了所有的日志信息 存储信息为字典的模式/因此可以进行匹配
    return insert_data


def Process_GroupAddress_Raw_List():
    result = list()
    with open("./ZH-SRV-2-FW-2_new_20210325_1.log", "r") as group_info:
        log_lineContent = group_info.readline()
        while log_lineContent:
            entire_str = ""
            if re.match(re_topsec_group, log_lineContent):
                entire_str += log_lineContent.replace('\'', " ").replace("\n", "")
                log_lineContent = group_info.readline()
                while ((not re.match(re_topsec_group_stop, log_lineContent)) and log_lineContent):
                    entire_str += log_lineContent.replace('\'', " ").replace("\n", "")
                    log_lineContent = group_info.readline()
                entire_str = entire_str.strip() + "\n"
                result.append(entire_str)
            else:
                log_lineContent = group_info.readline()

    return result


#
def Process_GroupAddress_toDict(input_List: list):
    # 遍历所有的 List 组
    result_dict = dict()
    for item in input_List:
        addr_list = item.split()
        result_dict[addr_list[4]] = addr_list[6:]

    return result_dict


def exchange_maskint(mask_int):
    mask_int = int(mask_int)
    bin_arr = ['0' for i in range(32)]
    for i in range(mask_int):
        bin_arr[i] = '1'
    tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
    tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
    return '.'.join(tmpmask)


def TopSec_ContentStrategy(filename: str):
    f = open("./topsec.txt", 'w+')
    with open(filename, "r") as topsecFile:
        # 逐行读取文本内容
        log_lineContent = topsecFile.readline()
        while log_lineContent:
            entire_str = ""
            if re.match(re_topsec, log_lineContent):
                entire_str += log_lineContent.lstrip().replace("\n", "")
                log_lineContent = topsecFile.readline()
                while log_lineContent and (not re.match(re_topsec_content_stop, log_lineContent)):
                    entire_str += log_lineContent.replace("\n", "")
                    log_lineContent = topsecFile.readline()
                entire_str = entire_str.strip() + "\n"
                f.write(entire_str)
            else:
                log_lineContent = topsecFile.readline()
    f.close()


def Analyze_TopSec(each_line: str):
    # 分开所有空格的内容
    Strip_Content = each_line.replace('\n', ' ').replace('\'', ' ').strip().split()
    default_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type"]
    df_format = ["Command", "Category", "Insert_Word", "Type(permit/deny)", "Packet_Type",
                 "Src_Type(host/any/object-group)", "Src_Addr", "Src_Mask", "Dst_Type(host/any/object-group)",
                 "Dst_Addr", "Dst_Mask", "Eq", "Port_Type", "Log"]
    # 制作字典
    input_data = dict().fromkeys(df_format, " ")

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
        if (Strip_Content[-1] == "on"): input_data["Log"] = "log"
    elif Strip_Content[9] == "slog":
        if Strip_Content[11] == "srcarea" and Strip_Content[13] == "dstarea":
            if "-" in Strip_Content[16]:
                input_data["Src_Addr"] = Strip_Content[16]
                if '/' in Strip_Content[18]:
                    input_data["Dst_Addr"] = Strip_Content[18].split('/')[0]
                    input_data["Dst_Mask"] = exchange_maskint(Strip_Content[18].split('/')[1])
                else:
                    input_data["Dst_Addr"] = Strip_Content[18]
                if Strip_Content[19] == "service":
                    input_data["Eq"] = "eq"
                    input_data["Port_Type"] = Strip_Content[20]
                if (Strip_Content[-1] == "on"): input_data["Log"] = "log"
            else:
                if '/' in Strip_Content[16]:
                    input_data["Src_Addr"] = Strip_Content[16].split('/')[0]
                    input_data["Src_Mask"] = exchange_maskint(Strip_Content[16].split('/')[1])
                else:
                    input_data["Src_Addr"] = Strip_Content[16]

                if '/' in Strip_Content[18]:
                    input_data["Dst_Addr"] = Strip_Content[18].split('/')[0]
                    input_data["Dst_Mask"] = exchange_maskint(Strip_Content[18].split('/')[1])
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
                    input_data["Src_Mask"] = exchange_maskint(Strip_Content[14].split('/')[1])
                else:
                    input_data["Src_Addr"] = Strip_Content[14]
                input_data["Dst_Addr"] = Strip_Content[16]
                if Strip_Content[-1] == "on": input_data["Log"] = "log"
            elif Strip_Content[11] == "src":
                if '/' in Strip_Content[11]:
                    input_data["Src_Addr"] = Strip_Content[11].split('/')[0]
                    input_data["Src_Mask"] = exchange_maskint(Strip_Content[11].split('/')[1])
                else:
                    input_data["Src_Addr"] = Strip_Content[11]
                if '/' in Strip_Content[13]:
                    input_data["Dst_Addr"] = Strip_Content[13].split('/')[0]
                    input_data["Dst_Mask"] = exchange_maskint(Strip_Content[13].split('/')[1])
                else:
                    input_data["Dst_Addr"] = Strip_Content[13]
            else:
                print(each_line)
    elif Strip_Content[9] == "srcarea" and Strip_Content[11] == "dstarea":
        if "-" in Strip_Content[14]:
            input_data["Src_Addr"] = Strip_Content[14]
            if '/' in Strip_Content[16]:
                input_data["Dst_Addr"] = Strip_Content[16].split('/')[0]
                input_data["Dst_Mask"] = exchange_maskint(Strip_Content[16].split('/')[1])
            else:
                input_data["Dst_Addr"] = Strip_Content[16]
            if Strip_Content[17] == "service":
                input_data["Eq"] = "eq"
                input_data["Port_Type"] = Strip_Content[18]
            if (Strip_Content[-1] == "on"): input_data["Log"] = "log"
        else:
            if '/' in Strip_Content[14]:
                input_data["Src_Addr"] = Strip_Content[14].split('/')[0]
                input_data["Src_Mask"] = exchange_maskint(Strip_Content[14].split('/')[1])
            else:
                input_data["Src_Addr"] = Strip_Content[14]

            if '/' in Strip_Content[16]:
                input_data["Dst_Addr"] = Strip_Content[16].split('/')[0]
                input_data["Dst_Mask"] = exchange_maskint(Strip_Content[16].split('/')[1])
            else:
                input_data["Dst_Addr"] = Strip_Content[16]
            if Strip_Content[17] == "service":
                input_data["Eq"] = "eq"
                input_data["Port_Type"] = Strip_Content[18]
            if Strip_Content[-1] == "on": input_data["Log"] = "log"
    elif Strip_Content[9] == "srcarea" and Strip_Content[11] == "src":
        if '/' in Strip_Content[12]:
            input_data["Src_Addr"] = Strip_Content[12].split('/')[0]
            input_data["Src_Mask"] = exchange_maskint(Strip_Content[12].split('/')[1])
        else:
            input_data["Src_Addr"] = Strip_Content[12]

        if '/' in Strip_Content[14]:
            input_data["Dst_Addr"] = Strip_Content[14].split('/')[0]
            input_data["Dst_Mask"] = exchange_maskint(Strip_Content[14].split('/')[1])
        else:
            input_data["Dst_Addr"] = Strip_Content[14]

    elif len(Strip_Content) < 16:
        return input_data

    else:
        print(each_line)
    return input_data


def exchange_mask(mask):
    # 计算二进制字符串中 '1' 的个数
    count_bit = lambda bin_str: len([i for i in bin_str if i == '1'])
    # 分割字符串格式的子网掩码为四段列表
    mask_splited = mask.split('.')
    # 转换各段子网掩码为二进制, 计算十进制
    mask_count = [count_bit(bin(int(i))) for i in mask_splited]
    return str(sum(mask_count))


def Process_ciscoDF(input_df: pd.DataFrame, group_dict: dict):
    # 开始遍历整个数组并开始替换工作
    df_compare = input_df.copy()
    for sid, row in df_compare.iterrows():
        compare_str = ""
        # 处理第一个Addr组
        if row["Src_Mask"] != " ":
            compare_str = row["Src_Addr"] + '/' + exchange_mask(row["Src_Mask"])
            for item in group_dict:
                if compare_str in group_dict[item]:
                    row["Src_Addr"] = item
                    row["Src_Mask"] = " "
        else:
            for item in group_dict:
                if row["Src_Addr"] in group_dict[item]:
                    row["Src_Addr"] = item

        # 处理第二个Addr组
        compare_str = ""
        if row["Dst_Mask"] != " ":
            compare_str = row["Dst_Addr"] + '/' + exchange_mask(row["Dst_Mask"])
            for item in group_dict:
                if compare_str in group_dict[item]:
                    row["Dst_Addr"] = item
                    row["Dst_Mask"] = " "
        else:
            for item in group_dict:
                if row["Dst_Addr"] in group_dict[item]:
                    row["Dst_Addr"] = item

    return df_compare


def cisco_2_topsec_1(df_cisco_transfer: pd.DataFrame, df_cisco: pd.DataFrame, df_topsec: pd.DataFrame,
                     df_topsec_transfer: pd.DataFrame):
    # 使用迭代器 迭代的对象为 cisco ， 即以cisco来找，找到就过，找不到就输出出来
    #
    # 创建一个输出的 df

    df_diff_temp = pd.DataFrame(columns=df_format)
    df_diff_output = pd.DataFrame(columns=df_format)

    #     # cisco 全变比较
    #     for sid, cisco_row in df_transfer.iterrows():
    #         temp_check = None
    #         temp_check = df_topsec[(df_topsec["Src_Addr"] == cisco_row["Src_Addr"])]
    #         temp_check = temp_check[(temp_check["Src_Mask"] == cisco_row["Src_Mask"])]
    #         temp_check = temp_check[(temp_check["Dst_Addr"] == cisco_row["Dst_Addr"])]
    #         temp_check = temp_check[(temp_check["Dst_Mask"] == cisco_row["Dst_Mask"])]
    #         temp_check = temp_check[(temp_check["Port_Type"].str.contains(cisco_row["Port_Type"], case = False))]

    #         # 不符合添加输出
    #         if temp_check.empty:
    #             df_diff_temp = df_diff_temp.append(df_cisco.iloc[sid], ignore_index=False)

    # topsec 全变比较
    for sid, diff_row in df_cisco_transfer.iterrows():
        temp_check = None
        temp_check = df_topsec_transfer[(df_topsec_transfer["Src_Addr"] == diff_row["Src_Addr"])]
        temp_check = temp_check[(temp_check["Src_Mask"] == diff_row["Src_Mask"])]
        temp_check = temp_check[(temp_check["Dst_Addr"] == diff_row["Dst_Addr"])]
        temp_check = temp_check[(temp_check["Dst_Mask"] == diff_row["Dst_Mask"])]
        temp_check = temp_check[(temp_check["Port_Type"].str.contains(diff_row["Port_Type"], case=False))]

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

    df_diff_temp.to_csv("./result.csv", sep=',', header=df_format, index=True)


if __name__ == "__main__":
    cisco_filename = sys.argv[2]
    top_filename = sys.argv[4]
    # 创建一个新的DF结构来接收所有的信息
    df_cisco = pd.DataFrame(columns=df_format)
    # 打开思科的文件并进行预处理
    with open(cisco_filename, "r") as ciscoFile:
        # 逐行读取文本的内容
        log_lineContent = ciscoFile.readline()
        while log_lineContent:
            # 如果是以 "access-list" 字符串开头的字符 那么需要进行处理
            if re.match(re_cisco_header, log_lineContent):
                temp = Analyze_CiscoContent(log_lineContent, df_cisco)
                df_cisco = df_cisco.append(temp, ignore_index=True)
            log_lineContent = ciscoFile.readline()

    df_cisco.to_csv('./cisco_config.csv', sep=',', header=df_format, index=True)

    TopSec_ContentStrategy(top_filename)

    df_topsec = pd.DataFrame(columns=df_format)
    with open("./topsec.txt", 'r') as topsec:
        log_lineContent = topsec.readline()
        while log_lineContent:
            try:
                df_topsec = df_topsec.append(Analyze_TopSec(log_lineContent), ignore_index=True)
                log_lineContent = topsec.readline()
            except:
                print(log_lineContent)
                log_lineContent = topsec.readline()

    df_topsec.to_csv("./topsec_config.csv", sep=",", header=df_format, index=True)
    dict_demo = Process_GroupAddress_toDict(Process_GroupAddress_Raw_List())

    # 运行函数
    df_cisco_transfer = Process_ciscoDF(input_df=df_cisco, group_dict=dict_demo)
    df_topsec_transfer = Process_ciscoDF(input_df=df_topsec, group_dict=dict_demo)
    cisco_2_topsec_1(df_cisco_transfer=df_cisco_transfer, df_cisco=df_cisco, df_topsec=df_topsec,
                     df_topsec_transfer=df_topsec_transfer)