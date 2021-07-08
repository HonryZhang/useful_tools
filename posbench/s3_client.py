# -*- encoding=utf8 -*-

"""
description: s3 接口
author: baorb
"""

import time
import urllib
import functools

from boto3.session import Session
from botocore import UNSIGNED
from botocore.client import Config as S3Config
from botocore.exceptions import ClientError, ReadTimeoutError, ConnectTimeoutError, ConnectionClosedError

from common import Log, Common
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
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            j = 0
            while j < Config.ObjectsPerBucketPerThread:
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
                                                             infos=[{'size': content_length, 'offset': basedata_offset}])
                j += 1
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
            j = 0
            while j < Config.ObjectsPerBucketPerThread:
                object_key = '{}-{}-{}'.format(self._process_id, Config.ObjectNamePrefix, j)
                if Config.TpsPerThread:  # 限制tps
                    # 按限制的tps数计算当前应该到的时间。计算方法： 当前已完成的请求/限制TPS +　并发开始时间
                    dst_time = (buckets_cover * Config.ObjectsPerBucketPerThread + j) * 1.0 / Config.TpsPerThread\
                               + start_time
                    wait_time = dst_time - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                # 获取对象的信息
                object_info = self._basic_check_data.get_object_offset(bucket_name=bucket_name, object_key=object_key)
                if not object_info:
                    raise Exception("there is no {} {} info".format(bucket_name, object_key))
                resp = self._s3_client.get_object(bucket_name=bucket_name, object_key=object_key,
                                                  except_infos=object_info)
                self._result_queue.put(
                    (self._process_id, self._user.username, resp.url, request_type, resp.start_time,
                     resp.end_time, resp.send_bytes, resp.recv_bytes, resp.request_id, resp.status))
                # 如果有不一致则测试退出
                if '9901' in resp.status or '9902' in resp.status:
                    self._data_error.value = 1
                j += 1
            buckets_cover += 1

    def delete_object(self):
        request_type = 'DeleteObject'
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        buckets_cover = 0  # 已经遍历桶数量
        for i in range_arr:
            bucket_name = '%s-%s-%d' % (self._user.sk.lower(), Config.BucketNamePrefix, i)
            j = 0
            while j < Config.ObjectsPerBucketPerThread:
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
                j += 1
            buckets_cover += 1

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
                                                             infos=[check_info])
                j += 1

    def multi_parts_upload(self):
        range_arr = range(self._process_id % Config.BucketsPerUser, Config.BucketsPerUser)
        range_arr.extend(range(0, self._process_id % Config.BucketsPerUser))
        start_time = None
        if Config.TpsPerThread:
            start_time = time.time()  # 开始时间
        total_requests = 0
        fixed_size = False
        content_length = 0
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
                check_infos = list()
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

                        if not check_infos:
                            # 如果check_infos为空说明是第一次
                            check_infos.append({'size': content_length, 'offset': basedata_offset})
                        elif basedata_offset == check_infos[-1]['size'] + check_infos[-1]['offset']:
                            # 如果这次起始位置是check_infos中最后一次的offset和size的和，则修改最后一次的记录
                            check_infos[-1]['size'] += content_length
                        else:
                            # 如果这次起始位置是check_infos中最后一次的offset和size的和，说明上一次上传失败，需要添加记录
                            check_infos.append({'size': content_length, 'offset': basedata_offset})

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
                                                             infos=check_infos)
                total_requests += 1
                j += 1

    TestCase = {101: create_bucket,
                104: delete_bucket,
                201: put_object,
                202: get_object,
                204: delete_object,
                208: append_object,
                216: multi_parts_upload}


def get_response(func):

    @functools.wraps(func)
    def _run_func(*args, **kwargs):
        response = DefineResponse()
        response.start_time = time.time()
        s3_resp = ''
        try:
            if func.__name__ in ('list_buckets'):
                s3_resp = func(*args, **kwargs)
            else:
                s3_resp = func(response=response, *args, **kwargs)
            response.generate_url()
            response.request_id = s3_resp['ResponseMetadata']['RequestId']
            response.position = s3_resp.get('x-amz-next-append-position', -1)
            response.end_time = time.time()
            if 'Error' in s3_resp:
                response.status = str(s3_resp['ResponseMetadata']['HTTPStatusCode']) + ' ' + s3_resp['Error']['Code']
            else:
                response.status = str(s3_resp['ResponseMetadata']['HTTPStatusCode'])
            response.return_data = s3_resp
            log_str = 'Request:[%s], URL:[%s], wait_response_time:[%.3f], responseStatus:[%s], %s' % (
                        func.__name__, response.url, response.end_time-response.start_time,
                        s3_resp['ResponseMetadata']['HTTPStatusCode'], s3_resp)
            if s3_resp['ResponseMetadata']['HTTPStatusCode'] < 400:
                Log.logger.debug(log_str)
            elif s3_resp['ResponseMetadata']['HTTPStatusCode'] < 500:
                Log.logger.warn(log_str)
            else:
                Log.logger.error(log_str)
        except KeyboardInterrupt:
            if not response.status:
                response.status = '9991 KeyboardInterrupt'
                Log.logger.warn(response.status)
        except ReadTimeoutError, data:
            import traceback
            stack = traceback.format_exc()
            Log.logger.error('Caught exception:%s, Request:[%s], URL:[%s], responseStatus:[%s], responseBody:[%r]' % (
                    data, func.__name__, response.url, response.status, s3_resp))
            Log.logger.error('print stack: %s' % stack)
            response.status = '9993 the read operation timed out'
        except ConnectTimeoutError, data:
            import traceback
            stack = traceback.format_exc()
            Log.logger.error('Caught exception:%s, Request:[%s], URL:[%s], responseStatus:[%s], responseBody:[%r]' % (
                data, func.__name__, response.url, response.status, s3_resp))
            Log.logger.error('print stack: %s' % stack)
            response.status = '9994 connection timed out'
        except ConnectionClosedError, data:
            import traceback
            stack = traceback.format_exc()
            Log.logger.error('Caught exception:%s, Request:[%s], URL:[%s], responseStatus:[%s], responseBody:[%r]' % (
                data, func.__name__, response.url, response.status, s3_resp))
            Log.logger.error('print stack: %s' % stack)
            response.status = '9998 connection reset by peer'
        except DataError:
            response.status = '9901 data check error'
        except ContentLengthError:
            response.status = '9902 data error content-length'
        except Exception, data:
            import traceback
            stack = traceback.format_exc()
            Log.logger.error('Caught exception:%s, Request:[%s], URL:[%s], responseStatus:[%s], responseBody:[%r]' % (
                data, func.__name__, response.url, response.status, s3_resp))
            Log.logger.error('print stack: %s' % stack)
            response.status = '9999 {}'.format(data)
            raise
        finally:
            return response
    return _run_func


class S3Client(object):

    def __init__(self, server, ak, sk, timeout):
        session = Session(ak, sk)
        self._client = session.client('s3', endpoint_url=server, config=S3Config(retries={'max_attempts': 0},
                                                                                 read_timeout=timeout))

    @get_response
    def create_bucket(self, response, bucket_name):
        response.bucket_name = bucket_name
        params = self._param_conversion(Bucket=bucket_name)
        return self._run_amz_sdk(self._client.create_bucket, **params)

    @get_response
    def list_buckets(self):
        return self._run_amz_sdk(self._client.list_buckets)

    @get_response
    def delete_bucket(self, response, bucket_name):
        response.bucket_name = bucket_name
        return self._run_amz_sdk(self._client.delete_bucket, Bucket=bucket_name)

    @get_response
    def list_objects(self, response, bucket_name, prefix=None, marker=None, max_keys=None, delimiter=None):
        response.bucket_name = bucket_name
        params = self._param_conversion(Bucket=bucket_name, Prefix=prefix, Marker=marker, MaxKeys=max_keys,
                                        Delimiter=delimiter)
        return self._run_amz_sdk(self._client.list_objects, **params)

    @get_response
    def put_object(self, response, bucket_name, object_key, filesize, basedata_offset):
        response.bucket_name = bucket_name
        response.object_key = object_key
        body = InputStream(filesize, basedata_offset=basedata_offset)
        content_length = filesize

        params = self._param_conversion(Bucket=bucket_name, Key=object_key, Body=body, ContentLength=content_length)
        resp = self._run_amz_sdk(self._client.put_object, **params)
        response.send_bytes = body.tell()
        return resp

    @get_response
    def get_object(self, response, bucket_name, object_key, except_infos):
        response.bucket_name = bucket_name
        response.object_key = object_key
        params = self._param_conversion(Bucket=bucket_name, Key=object_key)
        resp = self._run_amz_sdk(self._client.get_object, **params)

        if resp['ResponseMetadata']['HTTPStatusCode'] < 300:
            check_object = CheckSum(bucket_name=bucket_name, object_name=object_key)
            data_ok, obj_size = check_object.start_check(resp['Body'], except_infos)
            resp['Body'].close()
            response.recv_bytes = obj_size
            if obj_size != resp['ContentLength']:
                Log.logger.error('bucket: {}   object: {} content length is error, '
                                 'content_length: {}   true body length: {}'.format(bucket_name, object_key,
                                                                                    resp['ContentLength'], obj_size))
                raise ContentLengthError(bucket_name, object_key, obj_size, resp['ContentLength'])
            if data_ok is False:
                raise DataError(bucket_name, object_key)
        return resp

    @get_response
    def delete_object(self, response, bucket_name, object_key, version_id=None):
        response.bucket_name = bucket_name
        response.object_key = object_key
        params = self._param_conversion(Bucket=bucket_name, Key=object_key, VersionId=version_id)
        return self._run_amz_sdk(self._client.delete_object, **params)

    @get_response
    def append_object(self, response, bucket_name, object_key, filesize, basedata_offset, position):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.queryArgs["position"] = str(position)
        body = InputStream(filesize, basedata_offset=basedata_offset)
        resp = self._run_amz_sdk(self._client.append_object, Bucket=bucket_name, Key=object_key, Body=body,
                                 Position=position)
        response.send_bytes = body.tell()
        return resp

    @get_response
    def initiate_multipart_upload(self, response, bucket_name, object_key):
        response.bucket_name = bucket_name
        response.object_key = object_key
        params = self._param_conversion(Bucket=bucket_name, Key=object_key)
        return self._run_amz_sdk(self._client.create_multipart_upload, **params)

    @get_response
    def upload_part(self, response, bucket_name, object_key, part_num, upload_id, filesize, basedata_offset):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.queryArgs['uploadId'] = str(upload_id)
        response.queryArgs['partNumber'] = str(part_num)
        body = InputStream(filesize, basedata_offset=basedata_offset)
        content_length = filesize

        params = self._param_conversion(Bucket=bucket_name, Key=object_key, Body=body, PartNumber=part_num,
                                        UploadId=upload_id, ContentLength=content_length)
        resp = self._run_amz_sdk(self._client.upload_part, **params)
        response.send_bytes = body.tell()
        return resp

    @get_response
    def complete_multipart_upload(self, response, bucket_name, object_key, upload_id, parts):
        response.bucket_name = bucket_name
        response.object_key = object_key
        response.queryArgs['uploadId'] = str(upload_id)
        params = self._param_conversion(Bucket=bucket_name, Key=object_key, UploadId=upload_id,
                                        MultipartUpload={'Parts': parts})
        return self._run_amz_sdk(self._client.complete_multipart_upload, **params)

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
                    self.url += '&{}={}'.format(key, urllib.quote_plus(self.queryArgs[key]))
                else:
                    self.url += '?{}={}'.format(key, urllib.quote_plus(self.queryArgs[key]))

            elif self.queryArgs[key] is None or self.queryArgs[key].strip() == '':
                if self.url.find('?') != -1:
                    self.url += ('&{}'.format(key))
                else:
                    self.url += ('?{}'.format(key))
