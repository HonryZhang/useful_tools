#  -*- coding:utf-8 -*- 
import sys
import time
from multiprocessing import Process
import logging
import os
import Queue
import copy


class ResultWriter(Process):
    def __init__(self, config, testcase, results_queue, total_requests, valid_start_time, valid_end_time,
                 current_threads, result_dir):
        Process.__init__(self)
        self.__init__resultFolder__()
        self.config = copy.deepcopy(config)
        self.testcase = testcase
        self.results_queue = results_queue

        detail_result_file = os.path.join(result_dir, time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime()) + '_' +
                                          testcase + '_' + str(self.config['Users'] * self.config['ThreadsPerUser']) +
                                          '_detail.csv')
        detail_writer_handler = logging.handlers.RotatingFileHandler(detail_result_file, mode='a',
                                                                     maxBytes=1024 * 1024 * 1024,
                                                                     backupCount=5, encoding=None, delay=0)
        self.detailWriterLogger = logging.getLogger("detailWriter")
        self.detailWriterLogger.propagate = 0
        self.detailWriterLogger.addHandler(detail_writer_handler)
        self.detailWriterLogger.setLevel(logging.INFO)

        realtime_perf_file = detail_result_file[0: detail_result_file.rfind('_')] + '_realtime.txt'
        realtime_writer_handler = logging.handlers.RotatingFileHandler(realtime_perf_file, mode='a',
                                                                       maxBytes=100 * 1024 * 1024,
                                                                       backupCount=5, encoding=None, delay=0)
        self.realtimeWriterLogger = logging.getLogger("realtimeWriter")
        self.realtimeWriterLogger.propagate = 0
        self.realtimeWriterLogger.addHandler(realtime_writer_handler)
        self.realtimeWriterLogger.setLevel(logging.INFO)

        self.brief_result_file = detail_result_file[0: detail_result_file.rfind('_')] + '_brief.txt'
        self.archive_file = 'result/archive.csv'
        self.totalRequests = total_requests  # ????????????
        self.valid_start_time = valid_start_time  # ???????????????????????????????????????
        self.valid_end_time = valid_end_time  # ?????????????????????????????????????????????
        self.last_end_time = 0.0  # ???????????????tps????????????
        self.lastUpdateTime = 0  # ???????????????????????????
        self.currentProgressPercent = 0.0  # ??????????????????

        self.refresh_frequency = 3
        self.execute_path = os.getcwd()

        self.progressLatency = []
        self.hasThreadQuit = False
        self.totalThreads = self.config['Users'] * self.config['ThreadsPerUser']

        self.rough_summary_dict = {'currentRequests': 0, 'totalOK': 0, 'totalClientErr': 0, 'totalServerErr': 0,
                                   'totalOuterFlowControl': 0, 'totalInnerFlowControl': 0, 'totalOtherErr': 0,
                                   'errorRate': 0.0,
                                   'roughTotalSendBytes': 0, 'roughTotalRecvBytes': 0}
        # currentRequests     ?????????????????????????????????
        # totalOK             ???????????????????????????????????????
        # totalClientErr      ???????????????????????????????????????
        # totalServerErr      ???????????????????????????????????????
        # totalOuterFlowControl     ???????????????????????????????????????????????????
        # totalInnerFlowControl     ???????????????????????????????????????????????????
        # totalOtherErr     ??????????????????????????????????????????????????????????????????????????????
        # errorRate?????????????????????????????????
        # totalSendBytes     ??????????????????????????????????????????
        # totalRecvBytes     ????????????????????????????????????????????????????????????0

        self.accurate_summary_dict = {'requests': 0, 'totalOK': 0, 'totalClientErr': 0, 'totalServerErr': 0,
                                      'totalOuterFlowControl': 0, 'totalInnerFlowControl': 0, 'totalOtherErr': 0,
                                      'errorRate': 0,
                                      'totalLatency': 0, 'totalSendBytes': 0, 'totalRecvBytes': 0, 'worstRequests': {},
                                      'bestRequests': {}, 'avgLatency': 0.0, 'tps': 0.0, 'sendBPS': 0.0, 'recvBPS': 0.0,
                                      'latencySections': {}, 'latencyPercentDescription': '',
                                      'latencyPercentileMapSections': {}, 'latencyPercentileMapDescription': '',
                                      'runTime': '', 'firstThreadQuitTime': '', 'requestsWhenThreadQuit': 0}
        # requests     ?????????????????????????????????????????????????????????????????????????????????
        # totalOK     ??????????????????????????????????????????????????????????????????
        # totalClientErr     ????????????????????????????????????????????????????????????
        # totalServerErr     ????????????????????????????????????????????????????????????
        # totalOuterFlowControl     ??????????????????????????????????????????????????????????????????
        # totalInnerFlowControl     ??????????????????????????????????????????????????????????????????
        # totalOtherErr     ???????????????????????????????????????????????????????????????????????????????????????
        # errorRate     ?????????????????????????????????????????????
        # totalLatency     ????????????????????????????????????????????????????????????????????? ????????????
        # totalSendBytes     ???????????????????????????????????????????????????????????????????????? ????????????
        # totalRecvBytes     ???????????????????????????????????????????????????????????????????????? ????????????
        # worstRequests      ??????????????????????????????????????????????????????3?????????
        # bestRequests       ??????????????????????????????????????????????????????3?????????
        # avgLatency         ????????????????????????????????????????????????????????????????????????
        # tps                ??????????????????????????????????????????????????????
        # sendBPS            ????????????????????????????????????????????????????????????????????????
        # recvBPS            ????????????????????????????????????????????????????????????????????????
        # latencySections    ?????????????????????????????????????????????????????????
        # latencyPercentDescription ???????????????????????????????????????????????????????????????????????????????????????
        self.httpStatus_dict = {}  # ????????????http?????????????????????
        self.currentThreads = current_threads  # ?????????????????????
        self.refreshed_once = False
        self.last10_Realtime_Stat = {}  # ????????????10?????????????????????
        self.last_serial_no = 1

        if not self.config['CollectBasicData']:
            self.__init__latencySections__()

        if self.config['LatencyPercentileMap']:
            logging.info("initialize latency Percentile Map")
            self.__init__latencyPercentileMapSections__()

    @staticmethod
    def __init__resultFolder__():
        if not os.path.exists('result'):
            os.mkdir('result')

    def __init__latencySections__(self):
        latency_sections = sorted([int(x) for x in self.config['LatencySections'].split(',')])
        for time_mark in latency_sections:
            self.accurate_summary_dict['latencySections'][time_mark] = 0
        # ??????????????????sys.maxint??????
        self.accurate_summary_dict['latencySections'][sys.maxint] = 0

    def __init__latencyPercentileMapSections__(self):
        latency_percentile = sorted([int(x) for x in self.config['LatencyPercentileMapSections'].split(',')])
        for stage_mark in latency_percentile:
            self.accurate_summary_dict['latencyPercentileMapSections'][stage_mark] = 0

    def __writeRealTimeFile__(self, statistic_item):
        if statistic_item is None:
            return
        # ??????????????????????????????????????????????????????????????????1???????????????
        while self.last_serial_no < statistic_item.serial_no:
            tmp_statistic_item = StatisticItem(self.last_serial_no, self.valid_start_time.value,
                                               self.config['StatisticsInterval'])
            self.realtimeWriterLogger.info(tmp_statistic_item.to_string())
            self.last_serial_no += 1
        self.realtimeWriterLogger.info(statistic_item.to_string())
        self.last_serial_no = statistic_item.serial_no + 1

    def run(self):
        #  ctrl+c monitoring handler
        def terminate_result(signal_num, e):
            logging.warning('result writer exit, %d,%s' % (signal_num, e))
            # ??????????????????????????????????????????????????????
            self.currentThreads.value = -2

        def clear_err_statics(signal_num, e):
            logging.warning('signal_num %d %r received, to clear err statics' % (signal_num, e))
            # ?????????????????????
            if signal_num == 10:
                logging.warning('clear error stats signal 10 received')
                for key in self.httpStatus_dict.keys():
                    if key >= '400':
                        self.httpStatus_dict[key] = 0
                self.rough_summary_dict['totalClientErr'] = 0
                self.rough_summary_dict['totalServerErr'] = 0
                self.rough_summary_dict['totalOuterFlowControl'] = 0
                self.rough_summary_dict['totalInnerFlowControl'] = 0
                self.rough_summary_dict['totalOtherErr'] = 0

        import signal

        signal.signal(signal.SIGINT, terminate_result)
        signal.signal(signal.SIGUSR1, clear_err_statics)

        if self.config['RecordDetails']:
            self.detailWriterLogger.info(
                'ProcessId,UserId,URL,Operation,Start_At,End_At,Latency(s),DataSend(Bytes),DataRecv(Bytes),Mark,RequestID,Response,x-amz-id-2')
        self.realtimeWriterLogger.info(
            'NO      StartTime           OK          Requests    ErrRate(%)  TPS       AvgLatency(s) SendBytes        RecvBytes')
        writer_buffer = []
        last_write_detail_time = time.time()
        while True:
            # self.currentThreads.value == -2??????????????????????????????-1???????????????????????????????????? 
            if self.currentThreads.value == -2 or (self.currentThreads.value == -1 and self.results_queue.empty()):
                # ????????????????????????????????????
                if self.config['RecordDetails']:
                    self.detailWriterLogger.info('\n'.join(writer_buffer))
                print 'waiting for writing real time file '
                for i in sorted(self.last10_Realtime_Stat)[:]:
                    if i >= self.last_serial_no:
                        self.__writeRealTimeFile__(self.last10_Realtime_Stat[i])
                break
            q_tuple = None
            try:
                # ???Queue????????????
                q_tuple = self.results_queue.get(block=True, timeout=1)
                # ??????????????????
                if self.config['RecordDetails']:
                    writer_buffer.append('%d,%s,%s,%s,%f,%f,%f,%d,%d,%s,%s,%s,%s' % (
                        q_tuple[0], q_tuple[1], q_tuple[2], q_tuple[3], q_tuple[4], q_tuple[5], q_tuple[5] - q_tuple[4],
                        q_tuple[6], q_tuple[7], q_tuple[8], q_tuple[9], q_tuple[10], q_tuple[11]))
                    # ???3????????????
                    current_time = time.time()
                    if current_time - last_write_detail_time > 3:
                        self.detailWriterLogger.info('\n'.join(writer_buffer))
                        writer_buffer = []
                        last_write_detail_time = current_time
            except Queue.Empty:
                time.sleep(.01)
            except Exception, data:
                logging.warning('get record from queue exception: %s ' % data)
                time.sleep(.01)
            finally:
                # ????????????????????????????????????
                self.upgrade_and_print_result(q_tuple)

        self.generate_write_final_result()
        logging.info('ResultWriter exit')

    def upgrade_and_print_result(self, q_tuple):
        # ?????????????????????tuple???????????????????????????????????????
        if not q_tuple:
            current_time = time.time()
            if current_time - self.lastUpdateTime > 3:
                self.lastUpdateTime = current_time
                if self.config['PrintProgress']:
                    self.print_progress()

            return

        # 1.?????????????????????
        status = q_tuple[10]
        start_time = float(q_tuple[4])
        end_time = float(q_tuple[5])
        data_send = int(q_tuple[6])
        data_recv = int(q_tuple[7])
        request_id = q_tuple[9]
        latency = end_time - start_time

        if data_send >= 1024 ** 3 or data_recv >= 1024 ** 3:
            self.refresh_frequency = 2

        is_accurate = False
        if (start_time >= self.valid_start_time.value) and (end_time <= self.valid_end_time.value):
            is_accurate = True
        elif end_time > self.valid_end_time.value:
            if not self.hasThreadQuit:
                logging.warn("runThreads: %d" % self.currentThreads.value)
                self.accurate_summary_dict['firstThreadQuitTime'] = '%-52s' % self.convert_time_format_str(
                    self.valid_end_time.value - self.valid_start_time.value)
                self.hasThreadQuit = True

        # 2.????????????????????????
        # httpStatus_dict
        # ?????????????????????'',????????????????????????1
        http_status = status.split(' ')[0]
        if http_status in self.httpStatus_dict:
            self.httpStatus_dict[http_status] += 1
        else:
            self.httpStatus_dict[http_status] = 1
        # rough_summary_dict
        if status < '400':
            self.rough_summary_dict['totalOK'] += 1
            if is_accurate:
                self.accurate_summary_dict['totalOK'] += 1
        elif status < '500':
            self.rough_summary_dict['totalClientErr'] += 1
            if is_accurate:
                self.accurate_summary_dict['totalClientErr'] += 1
        elif status <= '900':
            self.rough_summary_dict['totalServerErr'] += 1
            if is_accurate:
                self.accurate_summary_dict['totalServerErr'] += 1
        elif status >= '9900':
            self.rough_summary_dict['totalOtherErr'] += 1  # ??????????????????
            if is_accurate:
                self.accurate_summary_dict['totalOtherErr'] += 1  # unknown exception

        if status.find('Flow Control') != -1:
            self.rough_summary_dict['totalOuterFlowControl'] += 1  # ???????????????????????????
            if is_accurate:
                self.accurate_summary_dict['totalOuterFlowControl'] += 1
        elif status.find('Service Unavailable') != -1:
            self.rough_summary_dict['totalInnerFlowControl'] += 1  # ???????????????????????????
            if is_accurate:
                self.accurate_summary_dict['totalInnerFlowControl'] += 1  # ???????????????????????????

        self.rough_summary_dict['currentRequests'] += 1

        if not self.config['CollectBasicData']:
            self.rough_summary_dict['roughTotalSendBytes'] += data_send
            self.rough_summary_dict['roughTotalRecvBytes'] += data_recv

        # accurate_summary_dict    
        if is_accurate:
            self.accurate_summary_dict['requests'] += 1
            if status < '400' or self.config['BadRequestCounted']:
                self.accurate_summary_dict['totalLatency'] += latency
                # if self.config['LatencyPercentileMap']:
                self.progressLatency.append(latency)
                self.accurate_summary_dict['totalSendBytes'] += data_send
                self.accurate_summary_dict['totalRecvBytes'] += data_recv

            if not self.config['CollectBasicData']:
                # ??????accurate_summary_dict['latencySections']. ???latency?????????????????????????????????????????????????????????????????????????????????
                latency_sections = sorted([int(x) for x in self.config['LatencySections'].split(',')])
                time_mark = None
                for time_mark in latency_sections:
                    if latency * 1000 <= time_mark:
                        self.accurate_summary_dict['latencySections'][time_mark] += 1
                if latency * 1000 > time_mark:
                    self.accurate_summary_dict['latencySections'][sys.maxint] += 1

                # ??????accurate_summary_dict['worstRequests'], accurate_summary_dict['bestRequests']
                if len(self.accurate_summary_dict['worstRequests']) < 3:
                    self.accurate_summary_dict['worstRequests'][float("{0:.12f}".format(latency))] = request_id
                if len(self.accurate_summary_dict['bestRequests']) < 3:
                    self.accurate_summary_dict['bestRequests'][float("{0:.12f}".format(latency))] = request_id
                else:
                    if latency < float(sorted(self.accurate_summary_dict['bestRequests'])[2]) \
                            and latency not in self.accurate_summary_dict['bestRequests']:
                        self.accurate_summary_dict['bestRequests'].pop(
                            sorted(self.accurate_summary_dict['bestRequests'])[2])
                        self.accurate_summary_dict['bestRequests'][float("{0:.12f}".format(latency))] = request_id
                    if latency > float(sorted(self.accurate_summary_dict['worstRequests'])[0]) \
                            and latency not in self.accurate_summary_dict['worstRequests']:
                        self.accurate_summary_dict['worstRequests'].pop(
                            sorted(self.accurate_summary_dict['worstRequests'])[0])
                        self.accurate_summary_dict['worstRequests'][float("{0:.12f}".format(latency))] = request_id

        # ??????self.last10_Realtime_Stat = {} # ??????5??????????????????????????? ??????????????????????????????????????????tps??????MPS??????MPS
        if is_accurate and self.config['StatisticsInterval'] > 0 and not self.config['CollectBasicData']:
            # ??????????????????????????????????????????????????????????????????1,2,3,4,5,6,7,8,9,10......
            serial_no = int((end_time - self.valid_start_time.value) / self.config['StatisticsInterval']) + 1
            # serial_no???????????????????????????????????????0??????????????????1~5???????????????????????????6~9?????????
            # 1. ???????????????????????????????????????????????????????????????????????????<10??????????????????????????????????????????????????????????????????????????????
            # ???????????????>=6?????????????????????[6]????????????????????????
            if (serial_no not in self.last10_Realtime_Stat) and len(self.last10_Realtime_Stat) < 1200:
                self.last10_Realtime_Stat[serial_no] = StatisticItem(serial_no, self.valid_start_time.value,
                                                                     self.config['StatisticsInterval'],
                                                                     self.config['BadRequestCounted'])
                self.last10_Realtime_Stat[serial_no].refresh(latency, status, data_send, data_recv)
                if len(self.last10_Realtime_Stat) >= 1190:
                    self.__writeRealTimeFile__(
                        self.last10_Realtime_Stat[sorted(self.last10_Realtime_Stat, reverse=True)[1189]])
            # 2. ?????????????????????????????????????????????????????????????????????????????????????????????
            elif serial_no in self.last10_Realtime_Stat:
                self.last10_Realtime_Stat[serial_no].refresh(latency, status, data_send, data_recv)
            # 3. ???????????????????????????????????????????????????????????????????????????=10???
            elif (serial_no not in self.last10_Realtime_Stat) and len(self.last10_Realtime_Stat) >= 1200:
                # ???????????????????????????????????????????????????????????????
                if serial_no < sorted(self.last10_Realtime_Stat)[0]:
                    logging.warning('record is ignored. %s' % str(q_tuple))
                else:
                    # ?????????????????????????????????????????????
                    self.last10_Realtime_Stat[serial_no] = StatisticItem(serial_no, self.valid_start_time.value,
                                                                         self.config['StatisticsInterval'],
                                                                         self.config['BadRequestCounted'])
                    self.last10_Realtime_Stat[serial_no].refresh(latency, status, data_send, data_recv)
                    # ???[6]???????????????
                    self.__writeRealTimeFile__(
                        self.last10_Realtime_Stat[sorted(self.last10_Realtime_Stat, reverse=True)[1189]])
                    # ???????????????????????????????????????
                    del self.last10_Realtime_Stat[sorted(self.last10_Realtime_Stat)[0]]

        # ?????????????????????????????????????????????????????????        
        if (time.time() - self.lastUpdateTime < self.refresh_frequency) and self.totalRequests != \
                self.rough_summary_dict['currentRequests']:
            return

        # ???totalRequests == -1 ?????????????????????????????????????????????totalRequests ==0 ???????????????????????????????????????????????????
        if self.totalRequests > 0:
            self.currentProgressPercent = self.rough_summary_dict['currentRequests'] * 100.0 / self.totalRequests
        if self.currentProgressPercent > 100.0:
            self.currentProgressPercent = 100.0
        if self.rough_summary_dict['currentRequests'] > 0:
            # self.rough_summary_dict['errorRate'] = 100.0 -
            #  (100.0 * self.rough_summary_dict['totalOK']/self.rough_summary_dict['currentRequests'])
            self.rough_summary_dict['errorRate'] = 100.0 * (
                self.rough_summary_dict['totalClientErr'] + self.rough_summary_dict['totalServerErr'] +
                self.rough_summary_dict[
                    'totalOtherErr']) / self.rough_summary_dict['currentRequests']

        if is_accurate:
            if self.accurate_summary_dict['requests'] > 0:
                self.accurate_summary_dict['errorRate'] = 100.0 - (
                    100.0 * self.accurate_summary_dict['totalOK'] / self.accurate_summary_dict['requests'])
                if self.config['BadRequestCounted']:
                    self.accurate_summary_dict['avgLatency'] = self.accurate_summary_dict['totalLatency'] / \
                                                               self.accurate_summary_dict[
                                                                   'requests']
                elif (not self.config['BadRequestCounted']) and self.accurate_summary_dict['totalOK'] > 0:
                    self.accurate_summary_dict['avgLatency'] = self.accurate_summary_dict['totalLatency'] / \
                                                               self.accurate_summary_dict[
                                                                   'totalOK']

                # ??????????????????????????????????????????end_time??????????????????????????????tps???Queue??????????????????????????????tps?????????????????????end_time<?????????????????????????????????
                if end_time > self.last_end_time:
                    self.last_end_time = end_time
                time_passed = self.last_end_time - self.valid_start_time.value

                if time_passed > 0:
                    if self.config['BadRequestCounted']:
                        self.accurate_summary_dict['tps'] = self.accurate_summary_dict['requests'] / time_passed
                    else:
                        self.accurate_summary_dict['tps'] = self.accurate_summary_dict['totalOK'] / time_passed
                    self.accurate_summary_dict['sendBPS'] = self.accurate_summary_dict['totalSendBytes'] / time_passed
                    self.accurate_summary_dict['recvBPS'] = self.accurate_summary_dict['totalRecvBytes'] / time_passed

                if not self.config['CollectBasicData']:
                    # ??????accurate_summary_dict['latencyPercentDescription']
                    last_key = 0
                    if self.accurate_summary_dict['requests'] > 0:
                        self.accurate_summary_dict['latencyPercentDescription'] = ''
                        for key in sorted(self.accurate_summary_dict['latencySections']):
                            latency_sections_percent = float("{0:.1f}".format(
                                self.accurate_summary_dict['latencySections'][key] * 100.0 / self.accurate_summary_dict[
                                    'requests']))
                            if key != sys.maxint:
                                self.accurate_summary_dict['latencyPercentDescription'] = ''.join(
                                    [self.accurate_summary_dict['latencyPercentDescription'], '<=', str(key), '(',
                                     str(latency_sections_percent), '%),'])
                                last_key = key
                            else:
                                self.accurate_summary_dict['latencyPercentDescription'] = ''.join(
                                    [self.accurate_summary_dict['latencyPercentDescription'], '>', str(last_key), '(',
                                     str(latency_sections_percent), '%),'])
                        if self.accurate_summary_dict['latencyPercentDescription'].endswith(','):
                            self.accurate_summary_dict['latencyPercentDescription'] = \
                                self.accurate_summary_dict['latencyPercentDescription'][:-1]

        self.lastUpdateTime = time.time()
        if self.config['PrintProgress']:
            self.print_progress()
        else:
            run_time_origin = self.lastUpdateTime - self.valid_start_time.value
            self.accurate_summary_dict['runTime'] = run_time_origin

    def print_progress(self):
        if self.currentThreads.value == -2:
            return
        last5_static = ''
        if self.config['StatisticsInterval'] > 0 and not self.config['CollectBasicData']:
            # ?????????????????????????????????,??????????????????
            for key in sorted(self.last10_Realtime_Stat, reverse=True)[1:6]:
                last5_static += '[#%d,%s]' % (
                    self.last10_Realtime_Stat[key].serial_no, self.last10_Realtime_Stat[key].tps)
        if self.accurate_summary_dict['tps'] <= 0.0:
            time_left_str = '  EST:--\'--\'--'
        else:
            time_left_str = '  EST:' + self.convert_time_format_str(
                int((self.totalRequests - self.rough_summary_dict['currentRequests']) / self.accurate_summary_dict[
                    'tps']))
            logging.debug("time_left_str:%s" % time_left_str)
        num_hashes = int(round(self.currentProgressPercent) / 100.0 * 70)
        proc_bar = '[' + '#' * num_hashes + '-' * (70 - num_hashes) + ']'
        if self.currentProgressPercent < 0.1:
            percent_place = (len(proc_bar) / 2) - 4
            percent_string = '<0.1%'
        else:
            percent_place = (len(proc_bar) / 2) - len("{0:.1f}".format(self.currentProgressPercent))
            percent_string = "{0:.1f}".format(self.currentProgressPercent) + '%'
        proc_bar = proc_bar[0:percent_place] + (percent_string + proc_bar[percent_place + len(percent_string):])
        proc_bar += time_left_str
        if self.totalRequests <= 0:
            proc_bar = ''
        # ??????????????????????????????????????????
        ok_str = ' '.join([str((k, v)) for (k, v) in self.httpStatus_dict.items() if '200' <= k < '400']).replace('\'',
                                                                                                                  '').replace(
            ' ', '')
        client_err_str = ' '.join(
            [str((k, v)) for (k, v) in self.httpStatus_dict.items() if '400' <= k < '500']).replace('\'',
                                                                                                    '').replace(
            ' ', '')
        server_err_str = ' '.join(
            [str((k, v)) for (k, v) in self.httpStatus_dict.items() if '500' <= k < '900']).replace('\'',
                                                                                                    '').replace(
            ' ', '')
        unknown_err_str = ' '.join([str((k, v)) for (k, v) in self.httpStatus_dict.items() if k >= '900']).replace('\'',
                                                                                                                   '').replace(
            ' ', '')
        if self.currentThreads.value < 0:
            current_threads = 0
        else:
            current_threads = self.currentThreads.value
        run_time_origin = self.lastUpdateTime - self.valid_start_time.value
        run_time = self.convert_time_format_str(run_time_origin)
        self.accurate_summary_dict['runTime'] = run_time_origin
        total_result_arr = [proc_bar.ljust(100),
                            '%-18s%-20s RunTime: %-52s' % ('[Test Case]', self.testcase, run_time),
                            '%-18s%-82d' % ('[RunningThreads]', current_threads),
                            '%-18s%-82d' % ('[Requests]', self.rough_summary_dict['currentRequests']),
                            '%-18s%-9d%-73s' % ('[OK]', self.rough_summary_dict['totalOK'], ok_str)]

        if not self.config['CollectBasicData']:
            if self.rough_summary_dict['totalClientErr'] > 0:
                total_result_arr.append('%-18s\033[1;31;40m%-9d%-73s\033[0m\033[0;32;40m' % (
                    '[ClientErrs]', self.rough_summary_dict['totalClientErr'], client_err_str))
            else:
                total_result_arr.append('%-18s%-82d' % ('[ClientErrs]', self.rough_summary_dict['totalClientErr']))
            if self.rough_summary_dict['totalServerErr'] > 0:
                total_result_arr.append('%-18s\033[1;31;40m%-9d%-73s\033[0m\033[0;32;40m' % (
                    '[ServerErrs]', self.rough_summary_dict['totalServerErr'], server_err_str))
            else:
                total_result_arr.append('%-18s%-82d' % ('[ServerErrs]', self.rough_summary_dict['totalServerErr']))
            if self.rough_summary_dict['totalOuterFlowControl'] > 0:
                total_result_arr.append('%-18s\033[1;31;40m%-82d\033[0m\033[0;32;40m' % (
                    ' -OuterFlwCtr', self.rough_summary_dict['totalOuterFlowControl']))
            else:
                total_result_arr.append(
                    '%-18s%-82d' % (' -OuterFlwCtr', self.rough_summary_dict['totalOuterFlowControl']))
            if self.rough_summary_dict['totalInnerFlowControl'] > 0:
                total_result_arr.append('%-18s\033[1;31;40m%-82d\033[0m\033[0;32;40m' % (
                    ' -InnerFlwCtr', self.rough_summary_dict['totalInnerFlowControl']))
            else:
                total_result_arr.append(
                    '%-18s%-82d' % (' -InnerFlwCtr', self.rough_summary_dict['totalInnerFlowControl']))
            if self.rough_summary_dict['totalOtherErr'] > 0:
                total_result_arr.append('%-18s\033[1;31;40m%-9d%-73s\033[0m\033[0;32;40m' % (
                    '[OtherErrs]', self.rough_summary_dict['totalOtherErr'], unknown_err_str))
            else:
                total_result_arr.append('%-18s%-82d' % ('[OtherErrs]', self.rough_summary_dict['totalOtherErr']))

        error_rate = '%.2f %%' % self.rough_summary_dict['errorRate']
        if self.rough_summary_dict['errorRate'] > 0.0:
            total_result_arr.append('%-18s\033[1;31;40m%-82s\033[0m\033[0;32;40m' % ('[ErrRate]', error_rate))
        else:
            total_result_arr.append('%-18s%-82s' % ('[ErrRate]', error_rate))
        if self.accurate_summary_dict['tps'] <= 0.0:
            total_result_arr.append('%-18s%-82s' % ('[TPS*]', '--'))
        else:
            total_result_arr.append('%-18s%-82.2f' % ('[TPS*]', self.accurate_summary_dict['tps']))

        if not self.config['CollectBasicData']:
            if last5_static == '':
                last5_static = '--'
            total_result_arr.append('%-18s%-82s' % ('[Last5TPS*]', last5_static))

        if self.accurate_summary_dict['avgLatency'] <= 0.0:
            total_result_arr.append('%-18s%-82s' % ('[AvgLatency*]', '--'))
        else:
            total_result_arr.append(
                '%-18s%-82s' % ('[AvgLatency*]', self.convert_time_str(self.accurate_summary_dict['avgLatency'])))

        if not self.config['CollectBasicData']:
            if self.accurate_summary_dict['latencyPercentDescription'] == '':
                self.accurate_summary_dict['latencyPercentDescription'] = '--'
            total_result_arr.append(
                '%-18s%-82s' % ('[latencyPercent*]', self.accurate_summary_dict['latencyPercentDescription']))

            if self.rough_summary_dict['roughTotalSendBytes'] <= 0:
                total_result_arr.append('%-18s%-82s' % ('[DataSend]', '--'))
            else:
                total_result_arr.append(
                    '%-18s%-82s' % (
                    '[DataSend]', self.convert_to_size_str(self.rough_summary_dict['roughTotalSendBytes'])))

            if self.rough_summary_dict['roughTotalRecvBytes'] <= 0:
                total_result_arr.append('%-18s%-82s' % ('[DataRecv]', '--'))
            else:
                total_result_arr.append(
                    '%-18s%-82s' % (
                    '[DataRecv]', self.convert_to_size_str(self.rough_summary_dict['roughTotalRecvBytes'])))

        if self.accurate_summary_dict['sendBPS'] <= 0:
            total_result_arr.append('%-18s%-82s' % ('[SendThroughput*]', '--'))
        else:
            send_bps = self.convert_to_size_str(self.accurate_summary_dict['sendBPS']) + '/s'
            total_result_arr.append(
                '%-18s%-82s' % ('[SendThroughput*]', send_bps))
        if self.accurate_summary_dict['recvBPS'] <= 0:
            total_result_arr.append('%-18s%-82s' % ('[RecvThroughput*]', '--'))
        else:
            recv_bps = self.convert_to_size_str(self.accurate_summary_dict['recvBPS']) + '/s'
            total_result_arr.append('%-18s%-82s' % ('[RecvThroughput*]', recv_bps))

        if not self.config['CollectBasicData']:
            total_result_arr.append('%-17s%s%-49s' % ('[BestReq*]', 'RequestID'.center(34), 'Latency(s)'))
            for key in sorted(self.accurate_summary_dict['bestRequests']):
                total_result_arr.append('%-17s%s%-49s' % (
                    ' ', self.accurate_summary_dict['bestRequests'][key].center(34), str(key)))
            for i in range(3 - len(self.accurate_summary_dict['bestRequests'])):
                total_result_arr.append('%-17s%s%-49s' % (' ', '-'.center(34), '-'))
            total_result_arr.append('[WorstReq*]'.ljust(100))
            for key in sorted(self.accurate_summary_dict['worstRequests']):
                total_result_arr.append('%-17s%s%-49s' % (
                    ' ', self.accurate_summary_dict['worstRequests'][key].center(34), str(key)))
            for i in range(3 - len(self.accurate_summary_dict['worstRequests'])):
                total_result_arr.append('%-17s%s%-49s' % (' ', '-'.center(34), '-'))

        total_result_str = '\n'.join(total_result_arr)
        # move the current cursor
        if self.refreshed_once:
            for i in range(total_result_str.count('\n') + 1):
                sys.stdout.write(chr(27) + '[G' + chr(27) + '[A')
        print '\033[0;32;40m%s\033[0m' % total_result_str
        self.refreshed_once = True

    @staticmethod
    def convert_time_str(time_sec):
        if time_sec < 1.0:
            return '%.2f ms' % (time_sec * 1000)
        else:
            return '%.2f sec' % time_sec

    @staticmethod
    def convert_time_format_str(time_sec):
        if time_sec < 0:
            return '--\'--\'--'
        if time_sec >= 8553600:
            return '>99 days'
        elif time_sec >= 86400:
            return '%2.2d Days %2.2d\'%2.2d\'%2.2d' % (
                time_sec / (3600 * 24), time_sec % (3600 * 24) / 3600, (time_sec % 3600 / 60), (time_sec % 60))
        else:
            ms = time_sec - int('%2.2d' % (time_sec % 60))
            return '%2.2d\'%2.2d\'%2.2d.%d' % (time_sec / 3600, (time_sec % 3600 / 60), (time_sec % 60), ms * 1000)

    @staticmethod
    def convert_to_size_str(size_bt):
        kb = 2 ** 10
        mb = 2 ** 20
        gb = 2 ** 30
        tb = 2 ** 40
        pb = 2 ** 50
        if size_bt >= 100 * pb:
            return '>100 PB'
        elif size_bt >= pb:
            return "%.2f PB" % (size_bt / (pb * 1.0))
        elif size_bt >= tb:
            return "%.2f TB" % (size_bt / (tb * 1.0))
        elif size_bt >= gb:
            return "%.2f GB" % (size_bt / (gb * 1.0))
        elif size_bt >= mb:
            return "%.2f MB" % (size_bt / (mb * 1.0))
        elif size_bt >= kb:
            return "%.2f KB" % (size_bt / (kb * 1.0))
        else:
            return "%.2f B" % size_bt

    def generate_write_final_result(self):
        logging.warn('generate_write_final_result enter')

        if self.config['LatencyPercentileMap'] and self.progressLatency is not None and len(self.progressLatency) > 0:
            self.generate_latency_percentile_map_description()
        total_requests = self.rough_summary_dict['currentRequests']
        total_ok = self.rough_summary_dict['totalOK']
        total_client_err = self.rough_summary_dict['totalClientErr']
        total_server_err = self.rough_summary_dict['totalServerErr']
        total_outer_flow_control = self.rough_summary_dict['totalOuterFlowControl']
        total_inner_flow_control = self.rough_summary_dict['totalInnerFlowControl']
        total_other_err = self.rough_summary_dict['totalOtherErr']
        total_send_bytes = int(self.rough_summary_dict['roughTotalSendBytes'])
        total_recv_bytes = int(self.rough_summary_dict['roughTotalRecvBytes'])
        error_rate = self.rough_summary_dict['errorRate']  # ?????????????????????????????????

        avg_latency = self.accurate_summary_dict['avgLatency']
        tps = self.accurate_summary_dict['tps']
        send_bps = self.accurate_summary_dict['sendBPS']
        recv_bps = self.accurate_summary_dict['recvBPS']
        latency_percent_description = self.accurate_summary_dict['latencyPercentDescription']
        best3 = self.accurate_summary_dict['bestRequests']
        worst3 = self.accurate_summary_dict['worstRequests']
        run_time = self.convert_time_format_str(self.accurate_summary_dict['runTime'])
        run_time = '%-52s' % run_time
        self.accurate_summary_dict['requestsWhenThreadQuit'] = len(self.progressLatency)

        latency_requests_number_map = None
        latency_requests_number_list = None

        if self.config['LatencyRequestsNumber']:
            if self.progressLatency is not None and len(self.progressLatency) > 0:
                latency_requests_number_map = {}
                latency_requests_number_list = []
                piece_number = int(self.config['LatencyRequestsNumberSections'])
                dis_first_part = avg_latency - self.progressLatency[0]
                dis_second_part = self.progressLatency[len(self.progressLatency) - 1] - avg_latency
                piece_size_for_first_part = dis_first_part / (piece_number / 2)
                piece_size_for_second_part = dis_second_part / (piece_number / 2)
                interval_min = 0
                interval_max = 0
                for i in range(piece_number):
                    if i == piece_number - 1:
                        interval_max = self.progressLatency[len(self.progressLatency) - 1]
                    elif i < piece_number / 2:
                        interval_max += piece_size_for_first_part
                    elif i >= piece_number / 2:
                        interval_max += piece_size_for_second_part
                    key = str("%.4f - %.4f" % (interval_min, interval_max))
                    latency_requests_number_list.append(key)
                    latency_requests_number_map[key] = sum(
                        k >= interval_min and k <= interval_max for k in self.progressLatency)
                    if i < piece_number / 2:
                        interval_min += piece_size_for_first_part
                    elif i >= piece_number / 2:
                        interval_min += piece_size_for_second_part

        ok_str = ' '.join([str((k, v)) for (k, v) in self.httpStatus_dict.items() if '200' <= k < '400']).replace('\'',
                                                                                                                  '').replace(
            ' ', '')
        client_err_str = ' '.join(
            [str((k, v)) for (k, v) in self.httpStatus_dict.items() if '400' <= k < '500']).replace('\'',
                                                                                                    '').replace(
            ' ', '')
        server_err_str = ' '.join(
            [str((k, v)) for (k, v) in self.httpStatus_dict.items() if '500' <= k < '900']).replace('\'',
                                                                                                    '').replace(
            ' ', '')
        unknown_err_str = ' '.join([str((k, v)) for (k, v) in self.httpStatus_dict.items() if k >= '900']).replace('\'',
                                                                                                                   '').replace(
            ' ', '')
        if not self.config['CollectBasicData']:
            total_result = '[TestCase]  ' + self.testcase + '\n' + \
                           '[RunTime]     ' + run_time + '\n' + \
                           '[FirstThreadQuitTime]       ' + self.accurate_summary_dict['firstThreadQuitTime'] + '\n' + \
                           '[RequestsWhenThreadQuit]    ' + str(
                self.accurate_summary_dict['requestsWhenThreadQuit']) + '\n' + \
                           '[HTTPs]                ' + str(self.config['IsHTTPs']) + '\n' + \
                           '[LongConnection]       ' + str(self.config['LongConnection']) + '\n' + \
                           '[Threads]       ' + str(self.config['Users'] * self.config['ThreadsPerUser']) + '\n' + \
                           '[Requests]    ' + str(total_requests) + '\n' + \
                           '[OK]          ' + str(total_ok) + '\t' + ok_str + '\n' + \
                           '[ClientErrs]  ' + str(total_client_err) + '\t' + client_err_str + '\n' + \
                           '[ServerErrs]  ' + str(total_server_err) + '\t' + server_err_str + '\n' + \
                           ' --OuterFlowControl ' + str(total_outer_flow_control) + '\n' + \
                           ' --InnerFlowControl ' + str(total_inner_flow_control) + '\n' + \
                           '[OtherErrs]   ' + str(total_other_err) + '\t' + unknown_err_str + '\n' + \
                           '[ErrRate]     ' + str(error_rate) + '%\n' + \
                           '[TPS]                       ' + str(tps) + '\n' + \
                           '[AvgLatency]                ' + str(avg_latency) + '\n' + \
                           '[latencyPercent]' + latency_percent_description + '\n' + \
                           '[DataSend]    ' + self.convert_to_size_str(total_send_bytes) + '\n' + \
                           '[DataRecv]    ' + self.convert_to_size_str(total_recv_bytes) + '\n' + \
                           '[SendThroughput]  ' + self.convert_to_size_str(send_bps) + '/s\n' + \
                           '[RecvThroughput]  ' + self.convert_to_size_str(recv_bps) + '/s\n' + \
                           '[ExecutePath]     ' + self.execute_path + '\n'
        else:
            total_result = '[TestCase]  ' + self.testcase + '\n' + \
                           '[RunTime]     ' + run_time + '\n' + \
                           '[FirstThreadQuitTime]       ' + self.accurate_summary_dict['firstThreadQuitTime'] + '\n' + \
                           '[RequestsWhenThreadQuit]    ' + str(
                self.accurate_summary_dict['requestsWhenThreadQuit']) + '\n' + \
                           '[HTTPs]                ' + str(self.config['IsHTTPs']) + '\n' + \
                           '[LongConnection]       ' + str(self.config['LongConnection']) + '\n' + \
                           '[Threads]       ' + str(self.config['Users'] * self.config['ThreadsPerUser']) + '\n' + \
                           '[Requests]    ' + str(total_requests) + '\n' + \
                           '[OK]          ' + str(total_ok) + '\t' + ok_str + '\n' + \
                           '[ClientErrs]  ' + str(total_client_err) + '\t' + client_err_str + '\n' + \
                           '[ServerErrs]  ' + str(total_server_err) + '\t' + server_err_str + '\n' + \
                           ' --OuterFlowControl ' + str(total_outer_flow_control) + '\n' + \
                           ' --InnerFlowControl ' + str(total_inner_flow_control) + '\n' + \
                           '[OtherErrs]   ' + str(total_other_err) + '\t' + unknown_err_str + '\n' + \
                           '[ErrRate]     ' + str(error_rate) + '%\n' + \
                           '[TPS]                       ' + str(tps) + '\n' + \
                           '[AvgLatency]                ' + str(avg_latency) + '\n' + \
                           '[SendThroughput]  ' + self.convert_to_size_str(send_bps) + '/s\n' + \
                           '[RecvThroughput]  ' + self.convert_to_size_str(recv_bps) + '/s\n' + \
                           '[ExecutePath]     ' + self.execute_path + '\n'

        if self.config['LatencyPercentileMap']:
            if self.progressLatency is not None and len(self.progressLatency) > 0:
                total_result += '[latencyPercentileMap]' + self.accurate_summary_dict[
                    'latencyPercentileMapDescription'] + '\n'
                latencyPercentileMapAvg = round(sum(self.progressLatency) / len(self.progressLatency) * 1000, 3)
                total_result += '[latencyPercentileMapAvg]' + str(latencyPercentileMapAvg) + ' ms\n\n'
            else:
                total_result += '[latencyPercentileMap] --\n'
                total_result += '[latencyPercentileMapAvg] --\n\n'
        else:
            del self.accurate_summary_dict['latencyPercentileMapSections']
            del self.accurate_summary_dict['latencyPercentileMapDescription']
            total_result += '\n'

        if not self.config['CollectBasicData']:
            total_result += 'The best request(s):\n    RequestId                            Latency(s)\n'
            for key in sorted(best3):
                total_result += best3[key] + '  ' + str(key) + '\n'
            total_result += 'The worst request(s):\n'
            for key in sorted(worst3):
                total_result += worst3[key] + '  ' + str(key) + '\n'

        print '\nResult in brief:\n', total_result, '\n', self.brief_result_file
        logging.info('\nResult in brief:\n' + total_result)
        reportwriter = open(self.brief_result_file, 'w')
        reportwriter.write(
            '***************Configuration***************\n\t' + str(
                [(key, self.config[key]) for key in sorted(self.config)]).replace(
                '[', '').replace(']', '').replace('(', ' ').replace('),', '\n').replace(')', ' ').replace('\'',
                                                                                                          '') + '\n')
        reportwriter.write('\n***************Result in brief***************\n' + total_result + '\n')

        if self.accurate_summary_dict['totalOK'] <= 0:
            warn_msg = 'Not enough requests to generate accurate performance results'
            print warn_msg, '\n'
            reportwriter.write(warn_msg)
            logging.warn(warn_msg)

        reportwriter.write('\n\n***************Result details***************\n')
        reportwriter.write(
            'Rough Result:\n' + str(
                [(key, self.rough_summary_dict[key]) for key in sorted(self.rough_summary_dict)]).replace('[',
                                                                                                          '').replace(
                ']', '').replace('(', ' ').replace('),', '\n').replace(')', ' ').replace('\'', '') + '\n')
        reportwriter.write(
            'Accurate Result:\n' + str(
                [(key, self.accurate_summary_dict[key]) for key in sorted(self.accurate_summary_dict)]).replace(
                '[', '').replace(']', '').replace('(', ' ').replace('),', '\n').replace(')', ' ').replace('\'',
                                                                                                          '') + '\n')
        reportwriter.write("latencyRequestsNumber,\n")
        if self.config[
            'LatencyRequestsNumber'] and latency_requests_number_map is not None and latency_requests_number_list is not None:
            for key in latency_requests_number_list:
                reportwriter.write("[%s]: %d\n" % (key, latency_requests_number_map[key]))
        reportwriter.close()
        logging.info('Done generating results. You can view your test result from ' + self.brief_result_file)
        # ??????????????????
        self.archive_result()

    def generate_latency_percentile_map_description(self):
        self.progressLatency.sort()

        progressMinLatency = round(self.progressLatency[0] * 1000, 3)
        progressMaxLatency = round(self.progressLatency[-1] * 1000, 3)

        self.accurate_summary_dict['latencyPercentileMapDescription'] = str(progressMinLatency) + '(' + 'min),'

        for key in sorted(self.accurate_summary_dict['latencyPercentileMapSections']):
            latency_index = int(round(
                len(self.progressLatency) * int(key) / 100) - 1)
            latency_index = latency_index if latency_index >= 0 else 0
            latency_percentile_map_result = round(self.progressLatency[latency_index] * 1000, 3)
            self.accurate_summary_dict['latencyPercentileMapDescription'] += str(
                latency_percentile_map_result) + '(' + str(key) + '%),'
            self.accurate_summary_dict['latencyPercentileMapSections'][key] = latency_percentile_map_result

        self.accurate_summary_dict['latencyPercentileMapDescription'] = ''.join(
            [self.accurate_summary_dict['latencyPercentileMapDescription'], str(progressMaxLatency), '(',
             'max)'])

        pass

    def archive_result(self):
        logging.info('Adding result to archive file %s' % self.archive_file)
        archive_file_obj = None
        config_keys = ['OSCs', 'Users', 'UserStartIndex', 'ThreadsPerUser', 'ObjSize', 'VirtualHost', 'IsHTTPs',
                       'LongConnection',
                       'ConnectTimeout', 'CalHashMD5', 'BucketNameFixed', 'ObjectNameFixed', 'RecordDetails',
                       'StatisticsInterval',
                       'BadRequestCounted',
                       'AvoidSinBkOp']
        config_str = ''
        for item in config_keys:
            if item in self.config:
                config_str += str(self.config[item]).replace(',', ';').replace('\n', ';').replace('\r', '').replace(
                    '\'', '').replace(
                    '{', '').replace('}', '')
            # ???????????????????????????????????????
            elif item == 'ObjSize' and self.config['Testcase'] == 201:
                config_str += str(self.config['ObjectSize'])
            config_str += ','

        result_keys = ['requests', 'totalOK', 'totalClientErr', 'totalServerErr', 'totalOuterFlowControl',
                       'totalInnerFlowControl',
                       'totalOtherErr', 'errorRate', 'totalSendBytes', 'totalRecvBytes', 'sendBPS', 'recvBPS', 'tps',
                       'avgLatency',
                       'latencyPercentDescription', 'bestRequests', 'worstRequests']
        result_str = ''
        for item in result_keys:
            result_str += str(self.accurate_summary_dict[item]).replace(',', ';').replace('\n', ';').replace('\r',
                                                                                                             '').replace(
                '\'',
                '').replace(
                '{', '').replace('}', '')
            result_str += ','
        result_str = result_str[:-1]
        i = -1
        while i < 3:
            try:
                i += 1
                # ??????????????????????????????????????????
                if not os.path.exists(self.archive_file):
                    archive_file_obj = open(self.archive_file, 'w')
                    archive_str = 'Start_At,End_At,TestCase,%s,%s\n%s,%s,%s,%s%s\n' % (
                        ','.join(config_keys), ','.join(result_keys),
                        str(self.valid_start_time.value),
                        str(self.valid_end_time.value), self.testcase,
                        config_str, result_str)
                    archive_file_obj.write(archive_str)
                else:
                    archive_file_obj = open(self.archive_file, 'a')
                    archive_str = '%s,%s,%s,%s%s\n' % (
                        str(self.valid_start_time.value), str(self.valid_end_time.value), self.testcase, config_str,
                        result_str)
                    archive_file_obj.write(archive_str)
                logging.info('Archive result:[%r]' % archive_str)
                break
            except Exception, e:
                logging.error('time %d , open and write file %s error: %s' % (i, self.archive_file, e))
                time.sleep(.5)
                continue
            finally:
                try:
                    archive_file_obj.close()
                except Exception, e:
                    logging.error('%d close file %s error: %s' % (i, self.archive_file, e))


# ??????10??????????????????????????? ??????????????????????????????????????????????????????tps,???MPS??????MPS
class StatisticItem:
    def __init__(self, serial_no, base_time, statistics_interval=10, bad_request_counted=False):
        self.serial_no = serial_no
        self.statistics_interval = statistics_interval
        self.bad_request_counted = bad_request_counted
        self.totalOK = 0
        self.totalRequests = 0
        self.totalLatency = 0
        self.totalSend = 0
        self.totalRecv = 0
        self.tps = ''
        start_time = base_time + (self.serial_no - 1) * statistics_interval
        self.start_time = time.strftime("%m/%d_%H:%M:%S", time.localtime(start_time)) + str(start_time % 1)[1:5]

    def refresh(self, latency, status, data_send, data_recv):
        self.totalRequests += 1
        if status < '400' or self.bad_request_counted:
            self.totalLatency += latency
        if status < '400':
            self.totalOK += 1
        if status < '400' or self.bad_request_counted:
            self.totalSend += data_send
        if status < '400' or self.bad_request_counted:
            self.totalRecv += data_recv
        if self.statistics_interval > 0 and self.bad_request_counted:
            self.tps = '%.1f' % (self.totalRequests * 1.0 / self.statistics_interval)
        elif self.statistics_interval > 0 and (not self.bad_request_counted):
            self.tps = '%.1f' % (self.totalOK * 1.0 / self.statistics_interval)

    def to_string(self):
        err_rate = 0.0
        avg_latency = 0.0
        if self.totalRequests > 0:
            err_rate = float("{0:.3f}".format(100.0 - (100.0 * self.totalOK / self.totalRequests)))
        if self.totalRequests > 0 and self.bad_request_counted:
            avg_latency = float("{0:.3f}".format(self.totalLatency / self.totalRequests))
        elif self.totalOK > 0 and (not self.bad_request_counted):
            avg_latency = float("{0:.3f}".format(self.totalLatency / self.totalOK))
        return (str(self.serial_no)).ljust(8) + self.start_time.ljust(20) + str(self.totalOK).ljust(12) \
               + str(self.totalRequests).ljust(12) + str(err_rate).ljust(12) + self.tps.ljust(10) + str(
            avg_latency).ljust(13) + \
               ' ' + str(self.totalSend).ljust(16) + ' ' + str(self.totalRecv).ljust(16)
