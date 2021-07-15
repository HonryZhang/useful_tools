# -*- encoding=utf8 -*-

"""
description: 公共库
author:      baorb
"""

import os
import random
import logging
import mylib.cloghandler


class Common(object):

    @staticmethod
    def get_md5(content):
        import hashlib
        obj_md5 = hashlib.md5()
        obj_md5.update(content)
        return obj_md5.hexdigest()

    @staticmethod
    def generate_a_size(data_size_str):
        """
        返回对象大小，和是否是固定值，可必免反复请求。ifFixed = True
        :param data_size_str:
        :return:
        """
        if str(data_size_str).find('~') != -1 and str(data_size_str).find(',') != -1:
            size_array = data_size_str.split(',')
            size_chosen = size_array[random.randint(0, len(size_array) - 1)]
            start_size = Common.unit_conversion(size_chosen.split('~')[0])
            end_size = Common.unit_conversion(size_chosen.split('~')[1])
            return random.randint(start_size, end_size), False
        elif str(data_size_str).find('~') != -1:
            start_size = Common.unit_conversion(data_size_str.split('~')[0])
            end_size = Common.unit_conversion(data_size_str.split('~')[1])
            return random.randint(start_size, end_size), False
        elif str(data_size_str).find(',') != -1:
            size_array = data_size_str.split(',')
            return Common.unit_conversion(size_array[random.randint(0, len(size_array) - 1)]), False
        else:
            return Common.unit_conversion(data_size_str), True

    @staticmethod
    def unit_conversion(size):
        """
        :author:      baorb
        :date:        2020.09.01
        :description: 转换容量，比如10G -> 10*1024*1024*1024
                      支持无单位、k、K、m、M、g、G、t、T
        :param size:  需要转换的size
        """
        size = str(size)
        if size[-1].isdigit():
            # 最后一个字符是数字
            return int(size)
        num = float(size[:-1])
        unit = size[-1]
        if unit in ['k', 'K']:
            return int(num * 1024)
        elif unit in ['m', 'M']:
            return int(num * 1024 * 1024)
        elif unit in ['g', 'G']:
            return int(num * 1024 * 1024 * 1024)
        else:
            return int(num * 1024 * 1024 * 1024 * 1024)


class Log(object):
    logger = None

    @classmethod
    def set_log(cls, log_path):
        if not os.path.exists(log_path):
            os.mkdir(log_path)
        log_name = os.path.join(log_path, "posbench.log")
        cls.logger = logging.getLogger()
        handler = logging.handlers.ConcurrentRotatingFileHandler(log_name, "a", 100 * 1024 * 1024, 30)
        cls.logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '[%(asctime)s] [%(process)d] [%(levelname)s] [%(filename)s:%(lineno)s] %(message)s')
        handler.setFormatter(formatter)
        cls.logger.addHandler(handler)