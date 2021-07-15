# -*- encoding=utf8 -*-

"""
description: 提供输出字节流
author: baorb
"""


class BaseError(Exception):
    pass


class ConfigError(BaseError):
    def __init__(self, error):
        self._error = error

    def __str__(self):
        return self._error


class DataError(BaseError):
    """数据不一致"""
    def __init__(self):
        pass

    def __str__(self):
        return "data check error"


class ContentLengthError(BaseError):
    """数据长度不正确"""
    def __init__(self, true_length, expect_length):
        self._true_length = true_length
        self._expect_length = expect_length

    def __str__(self):
        return "content length error   content_length: {}   true body length: {}".format(self._expect_length,
                                                                                         self._true_length)