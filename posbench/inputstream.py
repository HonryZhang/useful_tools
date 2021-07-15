# -*- encoding=utf8 -*-

"""
description: 提供输出字节流
author: baorb
"""

import os
import struct
import random

from setting import Config
from lib import Log


class InputStream(object):
    """
    :author:      baorb
    :date:        2020.12.22
    :description: 模拟文件类，用作流式上传
    """

    def __init__(self, size, basedata_offset, obj_md5=None):
        """
        :param size:        文件大小
        :param obj_md5:     md5对象，需要获取拼接内容的md5值时配置(比如多段)
        :param random_seed: 随机值种子，如果种子固定内容即固定
        :param quick_mode:  快速模式，这个模式输出内容不再是随机(为了避免产生随机内容带来的时间消耗)
        """
        self._size = size
        self._eof = False
        self._posstion = 0
        self._basedata_offset = basedata_offset
        self._obj_md5 = obj_md5

    def read(self, length):
        # 提供给obs sdk的read方法，读的内容随机生成
        # if self._eof:
        #     raise IOError("read after end of file")
        if self._posstion >= self._size:
            return self._do_end_of_file()
        else:
            start_posstion = self._posstion
            self._posstion += length
            if self._posstion > self._size:
                length = length - (self._posstion - self._size)
                self._posstion = self._size
            content_byte = self._process_bytes(start_posstion, length)
            if not self._eof and self._obj_md5:
                self._obj_md5.update(content_byte)
            return content_byte

    def tell(self):
        return self._posstion

    def seek(self, offset, whence=0):
        if whence == 0:
            self._posstion = offset
        elif whence == 1:
            self._posstion += offset
        else:
            self._posstion += self._size + offset

    def _process_bytes(self, start_position, length):
        """获取二进制数据"""
        content_byte_lst = []
        start_position = (start_position + self._basedata_offset) % BasicCheckData.BaseDataLength
        while length > 0:
            if start_position + length > BasicCheckData.BaseDataLength:
                content_byte_lst.append(BasicCheckData.BaseData[start_position:])
                length = start_position + length - BasicCheckData.BaseDataLength
                start_position = 0
            else:
                content_byte_lst.append(BasicCheckData.BaseData[start_position:start_position + length])
                length = 0
        return ''.join(content_byte_lst)

    def get_md5(self):
        """获取文件的md5值"""
        if self._obj_md5:
            return self._obj_md5.hexdigest()
        else:
            return None

    def _do_end_of_file(self):
        """读到文件结尾的处理"""
        self._eof = True
        return ''


class BasicCheckData(object):
    """
    原始校验数据
    """
    BaseData = ''                 # 原始校验数据
    BaseDataLength = 256*1024     # 原始数据长度

    def __init__(self, process_id):
        self._process_id = process_id

    @classmethod
    def create_data(cls, seed=None):
        """生成原始数据"""

        obj_random = random.Random()
        if seed is None:
            seed = random.randint(0, 10000000)
            Log.logger.info("Basic Data Seed: {}".format(seed))
        obj_random.seed(seed)
        hex_lst = []
        # 以4字节来创建数据，8位16进制数为4个字节
        for _ in range(cls.BaseDataLength / 4):
            num_str = "".join([obj_random.choice("0123456789abcdef") for _ in range(8)])
            num = int(num_str, 16)
            hex_lst.append(num)
        # 使用struct模块转换成字节流
        format_str = 'I' * (cls.BaseDataLength / 4)
        cls.BaseData = struct.pack(format_str, *hex_lst)

    def get_random_offset(self):
        """获取随机的偏移量，上传对象前使用"""
        return random.randint(0, BasicCheckData.BaseDataLength)

    def get_object_offset(self, bucket_name, object_key, version_id=None):
        """获取对象对应的偏移量，进行检验的时候用"""
        if version_id is None:
            key = bucket_name + object_key
        else:
            key = bucket_name + object_key + str(version_id)
        import shelve
        db = None
        try:
            db = shelve.open(os.path.join(Config.OutputPath, 'data/process-{}.dat'.format(self._process_id)))
            info = db.get(str(key), None)
        finally:
            db.close()
        return info

    def set_object_offset(self, bucket_name, object_key, infos, version_id=None):
        """设置对象的偏移量，上传对象成功后调用"""
        if version_id is None:
            key = bucket_name + object_key
        else:
            key = bucket_name + object_key + str(version_id)
        import shelve
        db = None
        try:
            db = shelve.open(os.path.join(Config.OutputPath, 'data/process-{}.dat'.format(self._process_id)))
            db[str(key)] = infos
            Log.logger.info("bucket/object: {}/{},  version: {},  check_info: {}".format(bucket_name, object_key,
                                                                                         version_id, infos))
        finally:
            db.close()


class CheckSum(object):

    chunk_size = 64 * 1024  # 读的块大小
    block_size = 512        # 每次比较内容的大小
    total_block_num = 16    # 决定打印多少

    def __init__(self, bucket_name, object_name):
        self._bucket_name = bucket_name
        self._object_name = object_name

    def start_check(self, file_object, expect_info, content_range=None):
        true_object_size = 0  # 统计对象真实大小
        start_position = 0
        self._expect_info = expect_info
        self._content_range = content_range
        self._error_msg_lst = []
        self._error_num = 0

        # 根据range获取期望的数据信息
        range_info = self._parse_range(content_range, expect_info)
        expect_object_size = range_info['size']

        expect_body = InputStream(range_info['size'], basedata_offset=range_info['offset'])
        while True:
            expect_content = expect_body.read(self.chunk_size)
            # 如果这一段预期的已经读完，则进行下一段
            if not expect_content:
                break
            true_content = file_object.read(len(expect_content))
            # 如果实际对象读完，则结束
            if not true_content:
                break
            true_object_size += len(true_content)
            # 比较数据一致性，如果不一致的段够了打印数量，则不再比较
            if self._error_num < self.total_block_num:
                self._compare_content(expect_content, true_content, start_position)
            start_position += len(true_content)
        true_object_size += len(file_object.read())

        if self._error_msg_lst:
            Log.logger.error('\n'.join(self._error_msg_lst))

        is_success = self._error_num == 0   # 不一致的段个数为0，暂定为成功
        # 判断实际的对象大小和预期的大小是否相同
        if true_object_size != expect_object_size:
            is_success = False
            Log.logger.warn("expect object bytes {},   actually received object bytes {}".format(expect_object_size,
                                                                                                 true_object_size))
        return is_success, true_object_size

    def _compare_content(self, expect_content, true_content, position):
        """比较内容"""
        # 能进到这个函数，说明不一致的段还没有打印够个数，这个分支说明前边已经不一致，后面的连续数据不再判断一致性，而是都打印出来
        if self._error_num > 0:
            true_content_len = len(true_content)
            expect_content_len = len(expect_content)
            start_position = 0
            while True:
                if start_position >= true_content_len and start_position >= expect_content_len:
                    break
                _expect_content = expect_content[start_position:start_position + self.block_size]
                _true_content = true_content[start_position:start_position + self.block_size]
                self._print_block_content(_expect_content, _true_content)
                start_position += self.block_size
                self._error_num += 1
                if self._error_num >= self.total_block_num:
                    break
        # 此分支说明前面没有发现不一致，需要判断数据是否相等
        elif true_content != expect_content:
            true_content_len = len(true_content)
            expect_content_len = len(expect_content)
            start_position = 0
            while True:
                if start_position >= true_content_len and start_position >= expect_content_len:
                    break
                _expect_content = expect_content[start_position:start_position + self.block_size]
                _true_content = true_content[start_position:start_position + self.block_size]
                if self._error_num > 0:
                    self._print_block_content(_expect_content, _true_content)
                    self._error_num += 1
                    if self._error_num >= self.total_block_num:
                        break
                elif _expect_content != _true_content:
                    self._error_msg_lst.append(
                        "expect_info: {},   range: {}".format(self._expect_info, self._content_range))
                    self._error_msg_lst.append(
                        "bucket: {};   object: {};   bad sector lba: 0x{:08x}".format(self._bucket_name,
                                                                                      self._object_name,
                                                                                      position + start_position))
                    self._error_msg_lst.append("{}{:<35}   {}".format(''.ljust(9), 'expect:', 'true:'))
                    self._print_block_content(_expect_content, _true_content)
                    self._error_num += 1
                    if self._error_num >= self.total_block_num:
                        break
                start_position += self.block_size

    def _print_block_content(self, expect_content, true_content):
        """比较块内容"""
        lba = self._error_num * self.block_size
        while True:
            expect_len = 16 if len(expect_content) >= 16 else len(expect_content)
            true_len = 16 if len(true_content) >= 16 else len(true_content)
            expect_mem = expect_content[:expect_len]
            true_mem = true_content[:true_len]
            expect_content = expect_content[expect_len:]
            true_content = true_content[true_len:]
            # 将内容转换十六进制
            expect_hexs = struct.unpack('I' * (expect_len / 4) + 'B' * (expect_len % 4), expect_mem)
            expect_mem_str = ' '.join('{:08x}'.format(mem) for mem in expect_hexs).ljust(35)
            true_hexs = struct.unpack('I' * (true_len / 4) + 'B' * (true_len % 4), true_mem)
            true_mem_str = ' '.join('{:08x}'.format(mem) for mem in true_hexs).ljust(35)
            self._error_msg_lst.append("0x{:03x}*   {}   {}".format(lba, expect_mem_str, true_mem_str))
            if len(expect_content) == 0 and len(true_content) == 0:
                break
            lba += 16
        self._error_msg_lst.append("")

    def _parse_range(self, content_range, expect_info):
        """
        解析段范围
        :return  {'size': **, 'offset': **}
        """
        if content_range is None:
            return expect_info
        else:
            start = int(content_range.strip('bytes=').split('-')[0])
            end = int(content_range.strip('bytes=').split('-')[-1])
            length = end + 1 - start
            offset = expect_info['offset'] + start
            return {'size': length, 'offset': offset}
