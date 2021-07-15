# -*- encoding=utf8 -*-

"""
description: s3 接口
author: baorb
"""

import time
import urllib
import random
import functools

from boto3.session import Session
from botocore import UNSIGNED
from botocore.client import Config as S3Config
from botocore.exceptions import ClientError, ReadTimeoutError, ConnectTimeoutError, ConnectionClosedError, \
    EndpointConnectionError, IncompleteReadError

from lib import Log, Common
from error import DataError, ContentLengthError
from setting import Config
from inputstream import BasicCheckData, InputStream, CheckSum


class S3TestCase(object):

    def __init__(self, process_id, user, s3_client, result_queue, data_error):
        self._process_id = process_id
        self._user = user
        self._s3_client = s3_client
        self._result_queue = result_queue
        self._basic_check_data = BasicCheckData(process_id=self._process_id)
        self._data_error = data_error
        self._object_index_lst = range(Config.ObjectsPerBucketPerThread)

    def create_bucket(self):
        request_type = 'CreateBucket'
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        i = self._process_id % Config.ThreadsPerUser
        while i < Config.BucketsPerUser:
            if Config.TpsPerThread:  # 限制tps
                # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                dst_time = (i - self._process_id % Config.ThreadsPerUser) / Config.ThreadsPerUser * 1.0 /\
                           Config.TpsPerThread + start_time
                wait_time = dst_time - time.time()
                if wait_time > 0:
                    time.sleep(wait_time)
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            i += Config.ThreadsPerUser
            resp = self._s3_client.create_bucket(bucket_name=bucket_name)
            self._result_queue.put(
                (self._process_id, self._user.username, resp.url, request_type, resp.start_time, resp.end_time,
                 resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))

    def list_objects_in_bucket(self):
        request_type = 'ListObjectsInBucket'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        total_requests = 0
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            marker = None
            while True:
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                    dst_time = total_requests * 1.0 / Config.ThreadsPerUser + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                total_requests += 1
                resp = self._s3_client.list_objects(bucket_name=bucket_name, marker=marker)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time, resp.end_time,
                     resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                if resp.return_data is None or resp.return_data['ResponseMetadata']['HTTPStatusCode'] >= 300 \
                        or resp.return_data['IsTruncated'] is False:
                    break
                else:
                    marker = resp.return_data['Contents'][-1]['Key']

    def delete_bucket(self):
        request_type = 'DeleteBucket'
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        i = self._process_id % Config.ThreadsPerUser
        while i < Config.BucketsPerUser:
            if Config.TpsPerThread:  # 限制tps
                # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                dst_time = (i - self._process_id % Config.ThreadsPerUser) / Config.ThreadsPerUser * 1.0 / \
                           Config.TpsPerThread + start_time
                wait_time = dst_time - time.time()
                if wait_time > 0:
                    time.sleep(wait_time)
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            i += Config.ThreadsPerUser
            resp = self._s3_client.delete_bucket(bucket_name=bucket_name)
            self._result_queue.put(
                (self._process_id, self._user.username, resp.url, request_type, resp.start_time, resp.end_time,
                 resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))

    def put_object(self):
        request_type = 'PutObject'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        buckets_cover = 0  # 已经遍历桶数量
        fixed_size = False
        content_length = 0
        self._object_index_lst = range(Config.ObjectsPerBucketPerThread)    # 初始化对象index列表
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            for j in self._object_index_lst:
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求/限制TPS +　并发开始时间
                    dst_time = (buckets_cover * Config.ObjectsPerBucketPerThread + j) * 1.0 / Config.TpsPerThread \
                               + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                if not fixed_size:
                    # change size every request for the same obj.
                    content_length, fixed_size = Common.generate_a_size(Config.ObjectSize)
                basedata_offset = self._basic_check_data.get_random_offset()
                resp = self._s3_client.put_object(bucket_name=bucket_name, object_key=object_key,
                                                  filesize=content_length, basedata_offset=basedata_offset)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))

                # 上传成功需要更新对象信息
                if resp.return_data and resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                    self._basic_check_data.set_object_offset(bucket_name=bucket_name, object_key=object_key,
                                                             infos={'size': content_length, 'offset': basedata_offset})
            buckets_cover += 1

    def get_object(self):
        request_type = 'GetObject'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        buckets_cover = 0  # 已经遍历桶数量
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            for j in self._object_index_lst:
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求/限制TPS +　并发开始时间
                    dst_time = (buckets_cover * Config.ObjectsPerBucketPerThread + j) * 1.0 / Config.TpsPerThread\
                               + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                # 如果range获取，需要HeadObject，获取对象大小
                content_range = None
                if Config.ObjectGetRange:
                    head_resp = self._s3_client.head_object(bucket_name=bucket_name, object_key=object_key)
                    if head_resp.return_data and head_resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                        content_range = self._get_range(head_resp.return_data['ContentLength'])

                # 获取对象的预期信息
                object_info = self._basic_check_data.get_object_offset(bucket_name=bucket_name, object_key=object_key)
                if not object_info:
                    Log.logger.error("there is no {} {} info".format(bucket_name, object_key))

                resp = self._s3_client.get_object(bucket_name=bucket_name, object_key=object_key,
                                                  except_info=object_info, content_range=content_range)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                # 如果有不一致则测试退出
                if '9901' in resp.status or '9902' in resp.status:
                    self._data_error.value = 1
            buckets_cover += 1

    def head_object(self):
        request_type = 'HeadObject'
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        for i in range(Config.BucketsPerUser):
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            for j in self._object_index_lst:
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求/限制TPS +　并发开始时间
                    dst_time = (i * Config.ObjectsPerBucketPerThread + j) * 1.0 / Config.TpsPerThread + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                resp = self._s3_client.head_object(bucket_name=bucket_name, object_key=object_key)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))

    def delete_object(self):
        request_type = 'DeleteObject'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        buckets_cover = 0  # 已经遍历桶数量
        # 如果是按比例删除，需要重新生成对象index列表
        if Config.ObjectDeleteRatio == 100:
            delete_object_lst = self._object_index_lst
            self._object_index_lst = list()
        else:
            delete_object_num = Config.ObjectsPerBucketPerThread * Config.ObjectDeleteRatio / 100
            delete_object_lst = random.sample(self._object_index_lst, delete_object_num)
            self._object_index_lst = list(set(self._object_index_lst) - set(delete_object_lst))
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            for j in delete_object_lst:
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求/限制TPS +　并发开始时间
                    dst_time = (buckets_cover * Config.ObjectsPerBucketPerThread + j) * 1.0 / Config.TpsPerThread\
                               + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                resp = self._s3_client.delete_object(bucket_name=bucket_name, object_key=object_key)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
            buckets_cover += 1

    def copy_object(self):
        request_type = 'CopyObject'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        total_requests = 0
        dest_bucket = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix,
                                    self._process_id % Config.BucketsPerUser)
        for i in range_arr:
            source_bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            for j in self._object_index_lst:
                source_object_name = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                dest_object_name = '{}-{}.copy'.format(source_object_name, i)
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                    dst_time = total_requests * 1.0 / Config.TpsPerThread + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                resp = self._s3_client.copy_object(dest_bucket=dest_bucket, dest_object=dest_object_name,
                                                   source_bucket=source_bucket_name, source_object=source_object_name)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))

                # 上传成功需要更新对象信息
                if resp.return_data and resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                    info = self._basic_check_data.get_object_offset(bucket_name=source_bucket_name,
                                                                    object_key=source_object_name)
                    self._basic_check_data.set_object_offset(bucket_name=dest_bucket, object_key=dest_object_name,
                                                             infos=info)

    def append_object(self):
        request_type = 'AppendObject'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        total_requests = 0
        fixed_size = False
        content_length = 0
        self._object_index_lst = range(Config.ObjectsPerBucketPerThread)
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            j = 0
            while j < Config.ObjectsPerBucketPerThread:
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                basedata_offset = self._basic_check_data.get_random_offset()    # 获取校验数据的偏移量
                check_info = {'offset': basedata_offset, 'size': 0}    # 记录文件信息，校验时用
                now_position = 0    # 记录当前的position
                for _ in range(Config.AppendNumPerObject):
                    if Config.TpsPerThread:  # 限制tps
                        # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                        dst_time = total_requests * 1.0 / Config.TpsPerThread + start_time
                        wait_time = dst_time - time.time()
                        if wait_time > 0:
                            time.sleep(wait_time)
                    if not fixed_size:
                        content_length, fixed_size = Common.generate_a_size(Config.AppendSize)
                    resp = self._s3_client.append_object(bucket_name=bucket_name, object_key=object_key,
                                                         filesize=content_length, basedata_offset=basedata_offset,
                                                         position=now_position)
                    self._result_queue.put(
                        (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                         resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                    total_requests += 1
                    if resp.return_data and resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                        now_position += content_length
                        check_info['size'] += content_length
                        basedata_offset += content_length
                if check_info['size']:
                    self._basic_check_data.set_object_offset(bucket_name=bucket_name, object_key=object_key,
                                                             infos=check_info)
                j += 1

    def get_copy_object(self):
        request_type = 'GetCopyObject'
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        buckets_cover = 0  # 已经遍历桶数量
        bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix,
                                    self._process_id % Config.BucketsPerUser)
        for i in range(Config.BucketsPerUser):
            for j in self._object_index_lst:
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求/限制TPS +　并发开始时间
                    dst_time = (buckets_cover * Config.ObjectsPerBucketPerThread + j) * 1.0 / Config.TpsPerThread \
                               + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                object_key = '{}-{}-{}-{}.copy'.format(self._process_id, Config.ObjectNamePrefix, j, i)
                # 如果range获取，需要HeadObject，获取对象大小
                content_range = None
                if Config.ObjectGetRange:
                    head_resp = self._s3_client.head_object(bucket_name=bucket_name, object_key=object_key)
                    if head_resp.return_data and head_resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                        content_range = self._get_range(head_resp.return_data['ContentLength'])

                # 获取对象的预期信息
                object_info = self._basic_check_data.get_object_offset(bucket_name=bucket_name, object_key=object_key)
                if not object_info:
                    Log.logger.error("there is no {} {} info".format(bucket_name, object_key))

                resp = self._s3_client.get_object(bucket_name=bucket_name, object_key=object_key,
                                                  except_info=object_info, content_range=content_range)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                # 如果有不一致则测试退出
                if '9901' in resp.status or '9902' in resp.status:
                    self._data_error.value = 1
            buckets_cover += 1

    def multi_parts_upload(self):
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        total_requests = 0
        fixed_size = False
        content_length = 0
        self._object_index_lst = range(Config.ObjectsPerBucketPerThread)
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            j = 0
            while j < Config.ObjectsPerBucketPerThread:
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                # 1> 初始化多段任务
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                    dst_time = total_requests * 1.0 / Config.TpsPerThread + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                resp = self._s3_client.initiate_multipart_upload(bucket_name=bucket_name, object_key=object_key)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, 'InitMultiUpload', resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                total_requests += 1
                upload_id = resp.return_data['UploadId']
                # Log.logger.info("upload id: %s" % upload_id)

                # 2> 串行上传段
                part_number = 1
                part_etags = []
                basedata_offset = self._basic_check_data.get_random_offset()
                check_info = {'offset': basedata_offset, 'size': 0}  # 记录文件信息，校验时用
                while part_number <= Config.PartsForEachUploadID:
                    if Config.TpsPerThread:  # 限制tps
                        # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                        dst_time = total_requests * 1.0 / Config.TpsPerThread + start_time
                        wait_time = dst_time - time.time()
                        if wait_time > 0:
                            time.sleep(wait_time)
                    if not fixed_size:
                        content_length, fixed_size = Common.generate_a_size(Config.PartSize)

                    resp = self._s3_client.upload_part(bucket_name=bucket_name, object_key=object_key,
                                                       part_num=part_number, upload_id=upload_id,
                                                       filesize=content_length, basedata_offset=basedata_offset)
                    self._result_queue.put(
                        (self._process_id, self._user.username, resp.url, 'UploadPart', resp.start_time,
                         resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                    total_requests += 1
                    # 上传成功，才记录ETag和数据校验
                    if resp.return_data and resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                        part_etags.append({'PartNumber': part_number, 'ETag': resp.return_data['ETag'].replace('"', '')})

                        check_info['size'] += content_length
                        basedata_offset += content_length
                    part_number += 1

                # 3> 合并段
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求 / 限制TPS + 并发开始时间
                    dst_time = total_requests * 1.0 / Config.TpsPerThread + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                resp = self._s3_client.complete_multipart_upload(bucket_name=bucket_name, object_key=object_key,
                                                                 upload_id=upload_id, parts=part_etags)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, 'CompleteMultiUpload', resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                if resp.return_data and resp.return_data['ResponseMetadata']['HTTPStatusCode'] < 300:
                    self._basic_check_data.set_object_offset(bucket_name=bucket_name, object_key=object_key,
                                                             infos=check_info)
                total_requests += 1
                j += 1

    TestCase = {101: create_bucket,
                102: list_objects_in_bucket,
                104: delete_bucket,
                201: put_object,
                202: get_object,
                203: head_object,
                204: delete_object,
                206: copy_object,
                208: append_object,
                210: get_copy_object,
                216: multi_parts_upload}

    def _get_range(self, content_length):
        """随机生成range"""
        min_num = random.randint(0, content_length-1)
        max_num = random.randint(0, content_length-1)
        if min_num > max_num:
            min_num, max_num = max_num, min_num
        return 'bytes={}-{}'.format(min_num, max_num)


def get_response(func):

    @functools.wraps(func)
    def _run_func(*args, **kwargs):
        response = DefineResponse()
        response.start_time = time.time()
        try:
            func(response=response, *args, **kwargs)
            response.request_id = response.return_data['ResponseMetadata']['RequestId']
            response.position = response.return_data.get('x-amz-next-append-position', -1)
            response.end_time = time.time()
            if 'Error' in response.return_data:
                response.status = str(response.return_data['ResponseMetadata']['HTTPStatusCode']) + ' ' + \
                                  response.return_data['Error']['Code']
            else:
                response.status = str(response.return_data['ResponseMetadata']['HTTPStatusCode'])
            log_str = 'Request:[%s], URL:[%s], wait_response_time:[%.3f], responseStatus:[%s], %s' % (
                        func.__name__, response.url, response.end_time-response.start_time,
                        response.return_data['ResponseMetadata']['HTTPStatusCode'], response.return_data)
            if response.return_data['ResponseMetadata']['HTTPStatusCode'] < 400:
                Log.logger.debug(log_str)
            elif response.return_data['ResponseMetadata']['HTTPStatusCode'] < 500:
                Log.logger.warn(log_str)
            else:
                Log.logger.error(log_str)
        except KeyboardInterrupt:
            if not response.status:
                response.status = '9991 KeyboardInterrupt'
                Log.logger.warn(response.status)
        except Exception, data:
            Log.logger.error('Caught exception:{}, Request:[{}], URL:[{}], '
                             'responseStatus:[{}], responseBody:[{}]'.format(data, func.__name__, response.url,
                                                                             response.status, response.return_data))
            import traceback
            stack = traceback.format_exc()
            Log.logger.error('print stack: %s' % stack)
            response.status = get_http_status_from_exception_(data)
            Log.logger.warn(response.status)
            # raise
        finally:

            if response.end_time == 0.0:
                response.end_time = time.time()
            return response
    return _run_func


def get_http_status_from_exception_(data):
    error_map = [
        {'error': DataError, 'num': '9901'},                # 数据校验错误
        {'error': ContentLengthError, 'num': '9902'},       # 数据长度和content-length头域值不一致
        {'error': EndpointConnectionError, 'num': '9990'},  # 服务器端域名无法解析
        {'error': ReadTimeoutError, 'num': '9993'},         # 从服务器端读取数据超时
        {'error': ConnectTimeoutError, 'num': '9994'},      # 链接超时
        {'error': IncompleteReadError, 'num': '9995'},      # 客户端读HTTP响应为空，常见于服务器端断开连接
        {'error': ConnectionClosedError, 'num': '9998'},    # 连接类错误：服务器拒绝连接
    ]

    for error_info in error_map:
        if isinstance(data, error_info['error']):
            return '{} {}'.format(error_info['num'], data)
    return '9999 {}'.format(data)


class S3Client(object):

    import urllib3
    urllib3.disable_warnings()

    def __init__(self, server, ak, sk, timeout):
        session = Session(ak, sk)
        self._client = session.client('s3', endpoint_url=server, verify=False,
                                      config=S3Config(retries={'max_attempts': Config.RetriesNum}, read_timeout=timeout))

    @get_response
    def create_bucket(self, response, bucket_name):
        response.bucket_name = bucket_name
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name)
        response.return_data = self._run_amz_sdk(self._client.create_bucket, **params)

    @get_response
    def list_buckets(self, response):
        response.generate_url()
        response.return_data = self._run_amz_sdk(self._client.list_buckets)

    @get_response
    def delete_bucket(self, response, bucket_name):
        response.bucket_name = bucket_name
        response.generate_url()
        response.return_data = self._run_amz_sdk(self._client.delete_bucket, Bucket=bucket_name)

    @get_response
    def list_objects(self, response, bucket_name, prefix=None, marker=None, max_keys=None, delimiter=None):
        response.bucket_name = bucket_name
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name, Prefix=prefix, Marker=marker, MaxKeys=max_keys,
                                        Delimiter=delimiter)
        response.return_data = self._run_amz_sdk(self._client.list_objects, **params)

    @get_response
    def put_object(self, response, bucket_name, object_key, filesize, basedata_offset):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.generate_url()
        body = InputStream(filesize, basedata_offset=basedata_offset)
        content_length = filesize

        params = self._param_conversion(Bucket=bucket_name, Key=object_key, Body=body, ContentLength=content_length)
        response.return_data = self._run_amz_sdk(self._client.put_object, **params)
        response.send_bytes = body.tell()

    @get_response
    def get_object(self, response, bucket_name, object_key, except_info, content_range=None):
        response.bucket_name = bucket_name
        response.object_key = object_key
        if content_range:
            response.queryArgs["bytes"] = content_range.strip('bytes=')
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name, Key=object_key, Range=content_range)
        resp = self._run_amz_sdk(self._client.get_object, **params)
        response.return_data = resp

        if resp['ResponseMetadata']['HTTPStatusCode'] < 300:
            if except_info:
                check_object = CheckSum(bucket_name=bucket_name, object_name=object_key)
                data_ok, obj_size = check_object.start_check(resp['Body'], except_info, content_range=content_range)
                resp['Body'].close()
                response.recv_bytes = obj_size
                if obj_size != resp['ContentLength']:
                    Log.logger.error('bucket: {}   object: {} content length is error, '
                                     'content_length: {}   true body length: {}'.format(bucket_name, object_key,
                                                                                        resp['ContentLength'],
                                                                                        obj_size))
                    raise ContentLengthError(obj_size, resp['ContentLength'])
                if data_ok is False:
                    raise DataError()
            else:
                chunk_size = 64*1024
                obj_size = 0
                while True:
                    content = resp['Body'].read(chunk_size)
                    if not content:
                        break
                    obj_size += len(content)
                resp['Body'].close()
                response.recv_bytes = obj_size
                if obj_size != resp['ContentLength']:
                    Log.logger.error('bucket: {}   object: {} content length is error, '
                                     'content_length: {}   true body length: {}'.format(bucket_name, object_key,
                                                                                        resp['ContentLength'],
                                                                                        obj_size))
                    raise ContentLengthError(obj_size, resp['ContentLength'])

    @get_response
    def head_object(self, response, bucket_name, object_key):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name, Key=object_key)
        response.return_data = self._run_amz_sdk(self._client.head_object, **params)

    @get_response
    def delete_object(self, response, bucket_name, object_key, version_id=None):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name, Key=object_key, VersionId=version_id)
        response.return_data = self._run_amz_sdk(self._client.delete_object, **params)

    @get_response
    def copy_object(self, response, dest_bucket, dest_object, source_bucket, source_object):
        response.bucket_name = dest_bucket
        response.object_key = dest_object
        response.queryArgs["copySrc"] = '{}/{}'.format(source_bucket, source_object)
        response.generate_url()
        copy_source = {'Bucket': source_bucket, 'Key': source_object}
        response.return_data = self._run_amz_sdk(self._client.copy_object, Bucket=dest_bucket, Key=dest_object,
                                                 CopySource=copy_source)

    @get_response
    def append_object(self, response, bucket_name, object_key, filesize, basedata_offset, position):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.queryArgs["position"] = str(position)
        response.generate_url()
        body = InputStream(filesize, basedata_offset=basedata_offset)
        response.return_data = self._run_amz_sdk(self._client.append_object, Bucket=bucket_name, Key=object_key,
                                                 Body=body, Position=position)
        response.send_bytes = body.tell()

    @get_response
    def initiate_multipart_upload(self, response, bucket_name, object_key):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name, Key=object_key)
        response.return_data = self._run_amz_sdk(self._client.create_multipart_upload, **params)

    @get_response
    def upload_part(self, response, bucket_name, object_key, part_num, upload_id, filesize, basedata_offset):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.queryArgs['uploadId'] = str(upload_id)
        response.queryArgs['partNumber'] = str(part_num)
        response.generate_url()
        body = InputStream(filesize, basedata_offset=basedata_offset)
        content_length = filesize

        params = self._param_conversion(Bucket=bucket_name, Key=object_key, Body=body, PartNumber=part_num,
                                        UploadId=upload_id, ContentLength=content_length)
        response.return_data = self._run_amz_sdk(self._client.upload_part, **params)
        response.send_bytes = body.tell()

    @get_response
    def complete_multipart_upload(self, response, bucket_name, object_key, upload_id, parts):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.queryArgs['uploadId'] = str(upload_id)
        response.generate_url()
        params = self._param_conversion(Bucket=bucket_name, Key=object_key, UploadId=upload_id,
                                        MultipartUpload={'Parts': parts})
        response.return_data = self._run_amz_sdk(self._client.complete_multipart_upload, **params)

    @staticmethod
    def _param_conversion(**kwargs):
        params = {}
        for key in kwargs:
            if kwargs[key] is not None:
                params[key] = kwargs[key]
        return params

    @staticmethod
    def _run_amz_sdk(func, *args, **kwargs):
        try:
            resp = func(*args, **kwargs)
        except ClientError as e:
            resp = e.response
        return resp


class DefineResponse:
    def __init__(self):
        self.status = ''
        self.request_id = '9999999999999999'
        self.start_time = time.time()
        self.end_time = 0.0
        self.send_bytes = 0
        self.recv_bytes = 0
        self.return_data = None
        self.position = '0'  # 普通对象上传Position默认为-1
        self.url = ''
        self.bucket_name = ''
        self.object_key = ''
        self.queryArgs = {}

    def __str__(self):
        return 'request_id: %s, status: %s,  return_data: %r, ' \
               'start_time: %.3f, end_time: %.3f, sendBytes: %d, ' \
               'recvBytes: %d, x-amz-next-append-position: %s' % (self.request_id, self.status, self.return_data,
                                                                  self.start_time, self.end_time, self.send_bytes,
                                                                  self.recv_bytes, self.position)

    def generate_url(self):
        self.url = ''
        # 根据virtualHost，桶，对象生成url
        if self.bucket_name:
            self.url = '/{}'.format(self.bucket_name)
        self.url += "/{}".format(urllib.quote_plus(self.object_key))
        # 将参数加入url
        for key in sorted(self.queryArgs):
            if self.queryArgs[key] and self.queryArgs[key].strip():
                if self.url.find('?') != -1:
                    # self.url += '&{}={}'.format(key, urllib.quote_plus(self.queryArgs[key]))
                    self.url += '&{}={}'.format(key, self.queryArgs[key])
                else:
                    # self.url += '?{}={}'.format(key, urllib.quote_plus(self.queryArgs[key]))
                    self.url += '?{}={}'.format(key, self.queryArgs[key])

            elif self.queryArgs[key] is None or self.queryArgs[key].strip() == '':
                if self.url.find('?') != -1:
                    self.url += ('&{}'.format(key))
                else:
                    self.url += ('?{}'.format(key))
