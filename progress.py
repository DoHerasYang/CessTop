#! /usr/bin/python3
#
#  CessTop progress Class
#  -
#  -  Used to Show Iterm 2
#

import tqdm.asyncio


class Progress_Show:
    """
        New Feature From Version 2.2
        Progress_Show Class
        - Designed for Show the Progress of
        - Slightly influence the performance of entire program
    """

    @classmethod
    def Show_DataFrameProgress(cls, bar_range: tqdm.asyncio.tqdm, total_num: int, cur_sid: int, df_category: str):
        """
        :param bar_range:
        :type bar_range:
        :param total_num:
        :type total_num:
        :param cur_sid:
        :type cur_sid:
        :param df_category:
        :type df_category:
        """
        if bar_range.total != total_num:
            bar_range.total = total_num
            bar_range.refresh()
        bar_range.set_description("Have Processed {} Config Items-- From "+df_category.format(cur_sid))
        bar_range.update(cur_sid - bar_range.n)

    def __init__(self):
        pass
