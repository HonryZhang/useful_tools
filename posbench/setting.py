# -*- encoding=utf8 -*-

"""
description: 配置
author: baorb
"""


# Testcase参照
# 101 = CreateBucket
# 102 = ListObjectsInBucket
# 104 = DeleteBucket
# 201 = PutObject
# 202 = GetObject
# 203 = HeadObject
# 204 = DeleteObject
# 206 = CopyObject
# 208 = AppendObject
# 210 = GetCopyObject
# 216 = MultiPartsUpload    # 多段上传对象


class Config:

    # ********************** 基础配置 **********************
    Users = [{'username': '', 'ak': '', 'sk': ''}]

    # 本次测试执行的操作，按照顺序执行, testcase指要执行的测试，nums指前面testcase要执行的次数
    TestCase = [{'testcase': 101, 'nums': 1},
                {'testcase': [201, 202], 'nums': 10},
                {'testcase': [204, 104], 'nums': 1}]

    EndPoint = ''   # 域名或者ip
    ThreadsPerUser = 1  # 每个用户下的进程数量
    HTTPPort = 20480
    HTTPsPort = 20481
    IsHTTPs = False
    OutputPath = ''    # 不填写并且-o不配置，则表示在执行目录下创建output

    # 连接建立/请求等待超时时间。
    ConnectTimeout = 300

    # ********************** 桶配置 **********************
    BucketsPerUser = 10     # 每个用户下的桶个数
    BucketNamePrefix = 'bucket'     # 桶名标识符

    # ********************** 对象配置 **********************
    # 示例： ObjectSize = 4k 上传指定大小对象。4096=4K, 104857600=100MB, 65536=64K
    # 示例：ObjectSize = 0~1k 上传随机大小对象。 0 ~ 1024  bytes (512B的倍数)
    # 示例：ObjectSize = 0,1024,2048  随机上传大小为0,1024或2048大小的对象。
    ObjectSize = '1m~100m'  # 必须是512B的倍数
    ObjectsPerBucketPerThread = 1000    # 每个并发每个桶中的对象个数
    ObjectNamePrefix = 'obj'    # 对象名标识符

    ObjectDeleteRatio = 100     # 对象删除比例，合法范围在1~100，100表示全量删除
    # 下载对象时，是否按照range下载，如果按照range下载，会在下载前执行一遍HeadObject，获取对象长度，然后随机生成range
    ObjectGetRange = False

    # ********************** 多段配置 **********************
    # 当采用多段时，对象个数使用ObjectsPerBucketPerThread，但是对象大小不再根据ObjectSize计算，而是由PartsForEachUploadID和PartSize决定
    PartsForEachUploadID = 3
    PartSize = '5m'  # 格式同ObjectSize

    # ********************** 追加写 **********************
    # 当采用追加写时，对象个数使用ObjectsPerBucketPerThread，对象大小为AppendSize*AppendNumPerObject
    AppendNumPerObject = 3
    AppendSize = '5m'   # 格式同ObjectSize

    # ********************** 高级配置 **********************
    # 运行时长（秒）
    # 运行指定时长后退出。若未到指定时长时，配置的请求数完成，工具也会退出。配置为0表示不配置，即按配置的请求数完成后退出。
    RunSeconds = 0

    # 每个请求的重试次数，0代表不重试。比如4代表在初始请求后再最多重试4次（一共最多5次请求）
    RetriesNum = 0

    # 是否打印运行中的实时结果和进度。自动化调用工具时关闭。
    PrintProgress = True

    # 限制每并发每秒的最大请求数，可为整数或浮点数，0表示不限制。
    # 常用于响应时延较小的请求。
    TpsPerThread = 0

    # 性能统计时间间隔(单位:s)，0代表关闭。　一般设置为多倍的请求的平均响应时间。
    StatisticsInterval = 10

    # 性能统计结果是否包含各个请求的时延，true|false，关闭该功能不影响性能结果统计，如果是长时间运行上亿对象操作，建议关闭
    LatencyPercentileMap = False

    # 和LatencyPercentileMap联合使用，如果LatencyPercentileMap为true，根据情况可选定需要观察的时延变化的点。
    # 目前需求是10%, 50%, 90%, 95%, 99%五个点。
    # 举例说明：若1并发，每并发100请求数上传对象，那最后上传100对象。系统将每个请求的时延记录到列表中，最后排序，根据默认需求取上述五个点
    # 得到的即是排序后的第10个时延，第50个时延，90个，95个，99个。
    # 系统会根据这个值给出类似统计结果xx(10%),xx(50%),xx(90%),xx(95%),xx(99%)
    LatencyPercentileMapSections = (10, 50, 90, 95, 99)

    # 是否只需要打印基本数据，为减少主线程cpu占用
    CollectBasicData = False

    # 统计结果时间段(单位：ms)，系统根据这个时间段，给出每个时间段的请求占百分比
    # 最好不要超过5个值。#系统会根据这个值给出类似统计结果：
    # <=500(90.3%), <=1000(94.9%), <=3000(98.0%), <=10000(100.0%), >10000(0.0%)
    LatencySections = (500, 1000, 3000, 10000)

    # 性能统计结果是否包含各个时延段请求数，True|False
    LatencyRequestsNumber = False

    # 最大时延和最小时延的差值取10份
    LatencyRequestsNumberSections = 20

    # 是否记录每个请求的详细结果到detail文件,true|false,关闭该功能不影响性能结果统计。
    RecordDetails = True

    # 性能统计结果是否包含错误请求,影响统计结果项：avgLatency, tps, sendBPS, recvBPS
    BadRequestCounted = False

    @staticmethod
    def get_attr_order():
        return ['Users', 'TestCase', 'EndPoint', 'ThreadsPerUser', 'HTTPPort', 'HTTPsPort', 'IsHTTPs', 'OutputPath',
                'ConnectTimeout', 'BucketsPerUser', 'BucketNamePrefix', 'ObjectSize', 'ObjectsPerBucketPerThread',
                'ObjectNamePrefix', 'ObjectDeleteRatio', 'PartsForEachUploadID', 'PartSize', 'AppendNumPerObject',
                'AppendSize', 'RunSeconds', 'RetriesNum', 'PrintProgress', 'TpsPerThread', 'StatisticsInterval',
                'LatencyPercentileMap', 'LatencyPercentileMapSections', 'CollectBasicData', 'LatencySections',
                'LatencyRequestsNumber', 'LatencyRequestsNumberSections', 'RecordDetails', 'BadRequestCounted']