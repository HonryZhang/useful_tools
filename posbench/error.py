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
    def __init__(self, bucket_name, object_key):
        self.bucket_name = bucket_name
        self.object_key = object_key

    def __str__(self):
        return ("bucket: {}   object: {}   data error!!!".format(self.bucket_name, self.object_key))


class ContentLengthError(BaseError):
    """数据长度不正确"""
    def __init__(self, bucket_name, object_key, true_length, expect_length):
        self._bucket_name = bucket_name
        self._object_key = object_key
        self._true_length = true_length
        self._expect_length = expect_length

    def __str__(self):
        return "bucket: {}   object: {}   content_length: {}   true body length: {}".format(self._bucket_name,
                                                                                            self._object_key,
                                                                                            self._expect_length,
                                                                                            self._true_length)