#! /usr/bin/python3
import config


class cesstop_warning:
    """
        Warning Class is Designed to
    """

    def __init__(self):
        pass

    @classmethod
    def show_warninfo(cls, warn_info: list):
        """
            Display Warning Information
        """
        print('\n')
        for info in warn_info:
            config.Logger.log_warning("Below Config is not Supported by this Program! Please Check...")
            print("  --> " + info + '\n')
