# -*- encoding=utf8 -*-

"""
description: 入口
author: baorb
"""

import os
import sys
import time
import json
import multiprocessing
from optparse import OptionParser

import error
import results
import httpconnect
from inputstream import BasicCheckData
from lib import Log
from setting import Config
from s3_client import S3TestCase, S3Client


class User:
    doc = """
        This is user class
    """

    def __init__(self, username, ak, sk):
        self.username = username
        self.ak = ak
        self.sk = sk


def param_analysis():
    """参数解析"""
    version = "%prog {4.0.4.01}"
    parser = OptionParser(version=version)

    parser.add_option("-f", "--config_file",
                      type="str",
                      dest="config_file",
                      default=None,
                      help='Required:False   Type:str   Help:config file(json)')

    parser.add_option("-o", "--output_dir",
                      type="str",
                      dest="output_dir",
                      default=None,
                      help='Required:False   Type:str   Help:result file dir')

    options, args = parser.parse_args()
    # 解析-f参数
    if options.config_file is not None:
        config_file = options.config_file
        if not os.path.exists(config_file):
            raise error.ConfigError("{} not exist".format(config_file))
        with open(config_file, 'r') as fd:
            json_msg = json.load(fd)
        for key, value in json_msg.items():
            setattr(Config, key, value)

    # 解析-o参数
    if options.output_dir is None:
        output = os.path.join(os.getcwd(), 'output')
    else:
        output = options.output_dir
    # 判断目录是否存在
    if not os.path.exists(output):
        os.mkdir(output, 0777)
        os.mkdir(os.path.join(output, 'result'), 0777)
        os.mkdir(os.path.join(output, 'data'), 0777)
    else:
        # 清理之前的日志
        import shutil
        log_path = os.path.join(output, 'result')
        data_path = os.path.join(output, 'data')
        if os.path.exists(log_path):
            shutil.rmtree(log_path)
        if os.path.exists(data_path):
            shutil.rmtree(data_path)
        os.mkdir(log_path, 0777)
        os.mkdir(data_path, 0777)
    Config.OutputPath = output


def init_log():
    log_path = os.path.join(Config.OutputPath, 'result')
    Log.set_log(log_path=log_path)


def check_config():
    # 检查配置
    # 检查账户信息
    for user_info in Config.Users:
        if not user_info['username']:
            raise error.ConfigError('Users is error')

    # 检查要执行的测试项
    for mem in Config.TestCase:
        if isinstance(mem['testcase'], (list, tuple)):
            for test_case in mem['testcase']:
                if test_case not in S3TestCase.TestCase:
                    Log.logger.error('TestCase is error {}'.format(test_case))
                    raise error.ConfigError('TestCase is error')
        else:
            if mem['testcase'] not in S3TestCase.TestCase:
                Log.logger.error('TestCase is error {}'.format(mem['testcase']))
                raise error.ConfigError('TestCase is error')

    # 检查网络
    print 'Testing connection to %s\t' % Config.EndPoint.ljust(20),
    sys.stdout.flush()
    test_conn = None
    try:
        test_conn = httpconnect.MyHTTPConnection(host=Config.EndPoint, port=Config.HTTPPort, timeout=60)
        test_conn.create_connection()
        test_conn.connect_connection()
        ssl_ver = ''
        rst = '\033[1;32;40mSUCCESS\033[0m'.ljust(10)
        print rst
        Log.logger.info('connect %s success, python version: %s,  ssl_ver: %s' % (Config.EndPoint,
                                                                                  sys.version.replace('\n', ' '),
                                                                                  ssl_ver))
    except Exception, data:
        Log.logger.error('Caught exception when testing connection with %s, except: %s' % (Config.EndPoint, data))
        print '\033[1;31;40m%s *%s*\033[0m' % (' Failed'.ljust(8), data)
        raise error.ConfigError('Check connection failed')
    finally:
        if test_conn:
            test_conn.close_connection()


class Main(object):

    def __init__(self):
        self._users = []

    def run_test(self):
        # 业务函数

        # 打印配置
        print_str_lst = []
        config_file = os.path.join(Config.OutputPath, 'result', 'config')
        with open(config_file, 'w') as fd:
            for key in Config.get_attr_order():
                value = getattr(Config, key)
                print_str_lst.append("{}:{}".format(key, value))
                fd.write("{} = {}\n".format(key, value))
        print_str = ';  '.join(print_str_lst)
        print print_str

        # 读取用户信息
        for user_info in Config.Users:
            self._users.append(User(username=user_info['username'], ak=user_info['ak'], sk=user_info['sk']))
        if not self._users:
            raise error.ConfigError('users is null')

        # 生成原始数据
        BasicCheckData.create_data()

        msg = '\nStart at %s, pid:%d. Press Ctr+C to stop. Screen Refresh Interval: 3 sec' % (time.strftime('%X %x %Z'),
                                                                                              os.getpid())
        print msg
        print 'my pid is: {}'.format(os.getpid())
        Log.logger.info(msg)

        valid_start_time = multiprocessing.Value('d', float(sys.maxint))
        valid_end_time = multiprocessing.Value('d', float(sys.maxint))
        current_threads = multiprocessing.Value('i', 0)
        # results_queue, 请求记录保存队列。多进程公用。
        results_queue = multiprocessing.Queue(0)
        manager = multiprocessing.Manager()
        create_bucket_finish = manager.dict()

        delete_bucket_begin = manager.dict()
        data_error = multiprocessing.Value('i', 0)  # 用来检查是否有不一致的标志
        # 启动统计计算结果的进程 。用于从队列取请求记录，保存到本地，并同时刷新实时结果。
        result_path = os.path.join(Config.OutputPath, 'result')
        results_writer = results.ResultWriter(results_queue, self._get_total_requests(), valid_start_time,
                                              valid_end_time, current_threads, result_path)
        results_writer.daemon = True
        results_writer.name = 'resultsWriter'
        results_writer.start()
        Log.logger.info('resultWriter started, pid: %d' % results_writer.pid)
        # 增加该进程的优先级
        os.system('renice -19 -p ' + str(results_writer.pid) + ' >/dev/null 2>&1')
        time.sleep(.2)

        # 顺序启动多个业务进程
        process_list = []
        # 多进程公用锁
        lock = multiprocessing.Lock()
        i = 0

        while i < len(Config.Users) * Config.ThreadsPerUser:
            p = multiprocessing.Process(target=self.start_process, args=(
                i, self._users[i / Config.ThreadsPerUser], results_queue, valid_start_time, valid_end_time, 
                current_threads, lock, create_bucket_finish, delete_bucket_begin, data_error))
            i += 1
            p.daemon = True
            p.name = 'worker-%d' % i
            p.start()
            # 将各工作进程的优先级提高1
            os.system('renice -1 -p ' + str(p.pid) + ' >/dev/null 2>&1')
            process_list.append(p)

        Log.logger.info('All %d threads started, valid_start_time: %.3f' % (len(process_list), valid_start_time.value))

        # 请求未完成退出
        def exit_force(signal_num, e):
            msg = "\n\n\033[5;33;40m[WARN]Terminate Signal %d Received. Terminating... please wait\033[0m" % signal_num
            Log.logger.warn('%r' % msg)
            print msg, '\nWaiting for all the threads exit....'
            lock.acquire()
            current_threads.value = -2
            lock.release()
            time.sleep(.1)
            tmpi = 0
            for j in process_list:
                if j.is_alive():
                    if tmpi >= 100:
                        Log.logger.warning('force to terminate process %s' % j.name)
                        j.terminate()
                    else:
                        time.sleep(.1)
                        tmpi += 1
                        break

            print "\033[1;32;40mWorkers exited.\033[0m Waiting results_writer exit...",
            sys.stdout.flush()
            while results_writer.is_alive():
                current_threads.value = -2
                tmpi += 1
                if tmpi > 1000:
                    Log.logger.warn('retry too many times, shutdown results_writer using terminate()')
                    # results_writer.generate_write_final_result()
                    results_writer.terminate()
                time.sleep(.01)
            print "\n\033[1;33;40m[WARN] Terminated\033[0m\n"
            sys.exit()

        import signal

        signal.signal(signal.SIGINT, exit_force)
        signal.signal(signal.SIGTERM, exit_force)

        time.sleep(1)
        # 正常退出
        stop_mark = False
        while not stop_mark:
            time.sleep(.3)
            if data_error.value != 0:
                Log.logger.warn('there is a data error')
                # results_writer.generate_write_final_result()
                exit_force(98, None)
            if Config.RunSeconds and (time.time() - valid_start_time.value >= Config.RunSeconds):
                Log.logger.warn('time is up, exit')
                # results_writer.generate_write_final_result()
                exit_force(99, None)
            for j in process_list:
                if j.is_alive():
                    break
                stop_mark = True
        for j in process_list:
            j.join()
        # 等待结果进程退出。
        Log.logger.info('Waiting results_writer to exit...')

        print "\033[1;32;40m[WARN] Terminated\033[0m\n"
        while results_writer.is_alive():
            current_threads.value = -1  # inform results_writer
            time.sleep(.3)
        print "\n\033[1;32;40mall requests finish\033[0m\n"

    def start_process(self, process_id, user, results_queue, valid_start_time, valid_end_time, current_threads, lock,
                      create_bucket_finish, delete_bucket_begin, data_error):
        lock.acquire()
        current_threads.value += 1
        lock.release()
        # 等待所有用户启动
        while True:
            # 如果时间已经被其它进程刷新，直接跳过。
            if valid_start_time.value == float(sys.maxint):
                # 若所有用户均启动，记为合法的有效开始时间
                if current_threads.value == len(Config.Users) * Config.ThreadsPerUser:
                    valid_start_time.value = time.time() + 2
                else:
                    time.sleep(.06)
            else:
                break
        time.sleep(2)

        # 解析要执行的测试
        create_bucket_count = 0
        delete_bucket_count = 0
        if Config.IsHTTPs:
            server = "https://{}:{}".format(Config.EndPoint, Config.HTTPsPort)
        else:
            server = "http://{}:{}".format(Config.EndPoint, Config.HTTPPort)
        s3_client = S3Client(server=server, ak=user.ak, sk=user.sk, timeout=Config.ConnectTimeout)
        s3_testcase = S3TestCase(process_id, user, s3_client, results_queue, data_error)
        for test_case in self._get_all_test():
            if test_case == 104:
                # 删除桶需要等所有进程都走到才一起开始删，不然有可能桶不为空
                delete_bucket_begin[process_id] = delete_bucket_count
                while True:
                    if delete_bucket_begin.values().count(delete_bucket_count) == len(Config.Users) * \
                            Config.ThreadsPerUser:
                        # 所有进程都刷新了，说明都走到要删除桶
                        break
                    else:
                        time.sleep(.06)
                delete_bucket_count += 1
            try:
                method_to_call = S3TestCase.TestCase[test_case]
                Log.logger.debug('method %s called ' % method_to_call.__name__)
                method_to_call(s3_testcase)
            except KeyboardInterrupt:
                pass
            except Exception, e:
                import traceback
                Log.logger.error('Call method for test case %d except: %s' % (test_case, traceback.format_exc()))
            if test_case == 101:
                # 创建桶需要特殊处理，需要等所有进程桶创建完成
                create_bucket_finish[process_id] = create_bucket_count
                while True:
                    if create_bucket_finish.values().count(create_bucket_count) == len(Config.Users) * \
                            Config.ThreadsPerUser:
                        # 所有进程都刷新了，说明都创建完成桶
                        break
                    else:
                        time.sleep(.06)
                create_bucket_count += 1

        # 执行完业务后，当前用户是第一个退出的用户，记为合法的结束时间
        if current_threads.value == len(Config.Users) * Config.ThreadsPerUser:
            valid_end_time.value = time.time()
            Log.logger.info('thread [' + str(process_id) + '], exit, set valid_end_time = ' + str(valid_end_time.value))
        # 退出
        lock.acquire()
        current_threads.value -= 1
        lock.release()
        Log.logger.info('process_id [%d] exit, set current_threads.value = %d' % (process_id, current_threads.value))

    def _get_all_test(self):
        test_lst = []
        for mem in Config.TestCase:
            if isinstance(mem['testcase'], (list, tuple)):
                test_lst.extend(mem['testcase'] * mem['nums'])
            else:
                test_lst.extend([mem['testcase']] * mem['nums'])
        return test_lst

    def _get_total_requests(self):
        """统计所有的请求个数"""
        if Config.ObjectDeleteRatio != 100:
            return -1
        total_request_num = 0
        for mem in Config.TestCase:
            nums = mem['nums']
            if isinstance(mem['testcase'], (list, tuple)):
                for test_case in mem['testcase']:
                    request_num = self._get_step_requests(test_case)
                    if request_num == -1:
                        return -1
                    total_request_num += nums * request_num
            else:
                request_num = nums * self._get_step_requests(mem['testcase'])
                if request_num == -1:
                    return -1
                total_request_num += request_num
        return total_request_num

    def _get_step_requests(self, step):
        """统计某个动作的请求个数"""
        if step in (101, 104):
            # 桶的创建|删除操作是每个桶操作一次
            return Config.BucketsPerUser * len(Config.Users)
        elif step in (201, 202, 204, 203, 206, 210):
            # 对象的操作 每个桶每个进程的对象数*桶数*进程数
            return Config.ObjectsPerBucketPerThread * Config.BucketsPerUser * len(Config.Users) * Config.ThreadsPerUser
        elif step in (216,):
            return Config.ObjectsPerBucketPerThread * Config.BucketsPerUser * len(Config.Users) * \
                   Config.ThreadsPerUser * (2 + Config.PartsForEachUploadID)
        elif step in (208,):
            return Config.ObjectsPerBucketPerThread * Config.BucketsPerUser * len(Config.Users) * \
                   Config.ThreadsPerUser * Config.AppendNumPerObject
        elif step in (102,):
            # 列举对象，由于不知道列举时对象个数，所以无法统计请求个数
            return -1
        else:
            return 0


def main():
    """入口函数"""
    # 解析参数
    param_analysis()

    # 初始化日志
    init_log()

    # 配置检查
    check_config()

    # 开始业务
    Main().run_test()


if __name__ == '__main__':
    main()
