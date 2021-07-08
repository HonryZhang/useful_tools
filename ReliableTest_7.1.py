# !/usr/bin/python
# -*- encoding=utf8 -*-

"""
    日志：
    2020/9/22  yuming  新增：NodeFaultNoWait 节点下电重启
"""

import os
import re
import sys
import time
import json
import signal
import random
import logging
import traceback
import threading
import subprocess
import xml.dom.minidom
from threading import Timer
from optparse import OptionParser
from multiprocessing import Process

try:
    import xml.etree.cElementTree as Et
except ImportError:
    import xml.etree.ElementTree as Et

script_version = '4.0.4.01'


class ReliableError(Exception):
    def __init__(self, mesg="raise a ReliableError"):
        self.mesg = mesg

    def __str__(self):
        return self.mesg


class PscliError(ReliableError):
    def __init__(self, mesg="raise a PscliError"):
        ReliableError.__init__(self, mesg)


class SSHCommand(object):

    NODE_ACCOUNT = {}       # 记录已知节点账户 {'1.1.1.1': 'root', '1.1.1.2': 'storadmin'}
    ROOT = 'root'
    SOTRADMIN = 'storadmin'
    CLIENT_UPDATE = False   # 客户端默认root账户，只需要更新一次

    @classmethod
    def get_command(cls, node_ip, cmd):
        """获取ssh命令"""
        if '@' in node_ip:
            host = node_ip
        else:
            account = cls.get_node_account(node_ip)
            host = "{}@{}".format(account, node_ip)
        cmd = re.sub(r'[\\]*"', cls._get_escape_character, cmd)
        cmd = re.sub(r"[\\]*'", cls._get_escape_character, cmd)
        cmd = re.sub(r"[\\]*[$]", cls._get_escape_character, cmd)
        cmd = "sudo /bin/sh -c $'{}'".format(cmd)
        return host, cmd

    @staticmethod
    def _get_escape_character(_str):
        """处理引号的转义"""
        a = _str.group()
        return "{}\\{}".format('\\\\' * a.count('\\'), a[-1])

    @classmethod
    def get_node_account(cls, node_ip, timeout=10):
        """获取节点账户"""
        # 获取节点账号
        if node_ip in cls.NODE_ACCOUNT:
            account = cls.NODE_ACCOUNT[node_ip]
        else:
            account = cls._get_node_account(node_ip, timeout=timeout)
        return account

    @classmethod
    def _get_node_account(cls, node_ip, timeout=10):
        if cls._check_storadmin_exist(node_ip, timeout=timeout):
            cls.NODE_ACCOUNT[node_ip] = cls.SOTRADMIN
            return cls.SOTRADMIN
        else:
            cls.NODE_ACCOUNT[node_ip] = cls.ROOT
            return cls.ROOT

    @classmethod
    def _check_storadmin_exist(cls, node_ip, timeout=10):
        """
        :date:          20210421
        :author:        zhangcy
        :description:   检查是否存在storadmin账户
        :param node_ip: 节点ip
        :param timeout: 命令超时时间
        :return:        存在返回True，不存在返回False
        """
        cmd1 = 'timeout {} ssh {}@{} -o GSSAPIAuthentication=no "cat /etc/passwd | grep storadmin"'.format(
            timeout, cls.SOTRADMIN, node_ip)
        process = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   preexec_fn=os.setsid)

        def kill():
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)

        timer = Timer(timeout, kill)
        timer.start()
        output, unused_err = process.communicate()
        retcode = process.poll()
        timer.cancel()
        if retcode != 0:
            cmd1 = 'timeout {} ssh {}@{} -o GSSAPIAuthentication=no "cat /etc/passwd | grep storadmin"'.format(
                timeout, cls.ROOT, node_ip)
            process = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       preexec_fn=os.setsid)
            timer = Timer(timeout, kill)
            timer.start()
            output, unused_err = process.communicate()
            timer.cancel()
        if cls.SOTRADMIN in output:
            return True
        else:
            return False


class FaultBase(object):
    """故障基础类"""
    local_node_ip = ''  # 本节点ip
    local_node_flag = True  # 执行脚本的节点是否是集群节点的标志，True:是集群节点，False:非集群节点
    fault_node_ip_lst = []  # 指定故障节点
    fault_disk_type = ''  # 做故障磁盘的类型
    fault_disk_num = 0  # 做故障磁盘的数目
    fault_pro_lst = []  # 指定故障进程

    node_ip_lst = []  # 集群节点的管理ip，当执行脚本的节点不是集群节点时使用
    node_data_ip_lst = []  # 集群节点的数据ip，当执行脚本的节点不是集群节点时使用

    check_badobj_wait_time = 30  # 故障完成后到检查坏对象的等待时间, 单位:s

    wait_times = {'down_disk': [1, 300], 'del_disk': [300, 600],
                  'down_net': [10, 180], 'down_node': [1, 180], 'del_node': [600, 1200]}

    process_lst = ['oJmgs', 'oMgcd', 'oPara', 'oStor', 'oJob', 'oRole',
                   'oCnas', 'oPhx', 'oDnsmgr', 'oJmw', 'zk', 'oBuffer']

    '''
    提供给管理网和数据网复用的环境使用。
    1、如果管理网和数据网分开的，这个字典不用填写。
    2、如果管理网和数据网复用的环境，需要填写每个节点的一个非管理网的ip（可以ping通）
    数据类型是字典，键是节点的管理网ip，值是空闲的ip
    举例：free_ip_dir = {"10.2.40.1":"20.10.10.1", "10.2.40.2":"20.10.10.2"}
    "10.2.40.1"是管理网ip，"20.10.10.1"是数据网没有使用的ip，需要填写所有集群ip
    '''
    free_ip_dir = {}
    mgr_data_ip_same = False  # 管理网和数据网是否复用的标志

    def __init__(self):
        pass

    @staticmethod
    def command(cmd, node_ip=None, timeout=None):
        """执行基础命令"""
        # 20210401 yum 适配centos7.9
        if node_ip:
            host, cmd = SSHCommand.get_command(node_ip, cmd)
            cmd1 = 'ssh {} "{}"'.format(host, cmd)
        else:
            cmd1 = cmd

        if timeout is None:
            process = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output, unused_err = process.communicate()
            retcode = process.poll()
            return retcode, output
        else:
            result = [None, 0, "", "Timeout"]

            def target(result):
                p = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, preexec_fn=os.setsid)
                result[0] = p
                (result[2], result[3]) = p.communicate()
                result[1] = p.returncode

            thread = threading.Thread(target=target, kwargs={'result': result})
            thread.start()
            thread.join(timeout)
            if thread.is_alive():
                # Timeout
                p = result[0]
                wait_time = 5
                while p is None:
                    time.sleep(1)
                    p = result[0]
                    wait_time -= wait_time
                    if wait_time == 0:
                        print 'Create process for cmd %s failed.' % cmd
                        exit(1)
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                print 'Process %d is killed.' % p.pid
                thread.join()
            return result[1], result[2]

    @staticmethod
    def json_loads(stdout):
        """将字符串解析成json"""
        r1 = re.compile(r'[{].*[}]', re.S)
        json_lst = re.findall(r1, stdout)
        if json_lst:
            json_str = json_lst[0]
        else:
            json_str = stdout
        try:
            stdout_str = json.loads(json_str, strict=False)
            return stdout_str
        except Exception:
            logging.error(stdout)
            raise

    def check_ping(self, ip, check_ssh=True):
        """检查节点是否可以ping通"""
        cmd = 'ping -c 3 %s | grep "0 received" | wc -l' % ip
        rc, stdout = self.command(cmd, timeout=20)
        if '0' != stdout.strip():
            return False
        if check_ssh:
            cmd = 'ssh %s "ls /"' % ip
            rc, stdout = self.command(cmd, timeout=20)
            if rc != 0:
                return False
            else:
                return True
        else:
            return True

    def check_path(self, node_ip, path):
        """检查路径是否存在"""
        cmd = 'ls %s' % path
        rc, stdout = self.command(cmd, node_ip)
        return rc

    def check_datanet(self, node_ip):
        """检查节点数据网是否存在"""
        cmd = 'ip addr | grep "inet "'
        rc, stdout = self.command(cmd, node_ip)
        if 0 != rc:
            raise ReliableError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        lines = stdout.strip().split('\n')
        for line in lines:
            ip = line.split()[1].split('/')[0]
            if ip in self.node_data_ip_lst:
                return True
        return False

    @staticmethod
    def check_nwatch_stdout(stdout):
        """检查nWatch输出"""
        if not stdout.strip():
            return True
        if 'failed' in stdout or "Don't support this command" in stdout or 'Invalid command' in stdout:
            return True
        else:
            return False

    def wait_time(self, fault):
        """等待时间"""
        time_lst = self.wait_times.get(fault)
        min_time = time_lst[0]
        max_time = time_lst[1]

        wait_time = random.randint(min_time, max_time)
        logging.info("wait %d s" % wait_time)
        time.sleep(wait_time)
        return

    def pscli_command(self, cmd, fault_node_ip=None, timeout=None):
        """pscli或者nwatch命令执行"""
        if self.local_node_flag is False:
            if (fault_node_ip is not None) and (fault_node_ip in self.node_ip_lst):
                node_ips_list = self.node_ip_lst[:]
                node_ips_list.remove(fault_node_ip)
            else:
                node_ips_list = self.node_ip_lst[:]

            stdout = None
            for node_ip in node_ips_list:
                # 判断节点是否可以ping通
                if self.check_ping(node_ip) is False:
                    continue
                # 判断数据网是否正常
                if self.check_datanet(node_ip) is False:
                    continue
                # 判断节点上是否有/home/parastor/conf
                if 0 != self.check_path(node_ip, '/home/parastor/conf'):
                    continue
                # 判断节点上是否有集群
                rc, stdout = self.command(cmd, node_ip, timeout)
                if 'nWatch' in cmd and self.check_nwatch_stdout(stdout):
                    continue
                elif 'nWatch' not in cmd and (rc == 127 or 'FindMasterError' in stdout):
                    continue
                if (rc != 0) and ('FindMasterError' in stdout):
                    logging.warn('%s return "FindMasterError" ' % (cmd))
                    time.sleep(20)
                    continue
                if rc != 0:
                    logging.warn("node {} cmd {} failed".format(node_ip, cmd))
                return rc, stdout
            else:
                return 1, stdout
        else:
            rc, stdout = self.command(cmd, self.local_node_ip, timeout)
            if (rc != 0) and ('FindMasterError' in stdout):
                num = 1
                logging.warn('%s return "FindMasterError" %d times' % (cmd, num))
                while True:
                    time.sleep(20)
                    num += 1
                    rc, stdout = self.command(cmd, self.local_node_ip, timeout)
                    if (rc != 0) and ('FindMasterError' in stdout):
                        logging.warn('%s return "FindMasterError" %d times' % (cmd, num))
                    else:
                        break
            return rc, stdout

    def wait_ping_success(self, node_ip):
        start_time = time.time()
        while True:
            time.sleep(5)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            if self.check_ping(node_ip):
                logging.info('node %s ping successfully %dh:%dm:%ds' % (node_ip, h, m, s))
                break
            logging.info('node %s cannot ping pass %dh:%dm:%ds' % (node_ip, h, m, s))

    def update_param(self, section, name, value):
        """修改参数"""
        cmd = "pscli --command=update_param --section=%s --name=%s --current=%s" % (section, name, value)
        rc, stdout = self.pscli_command(cmd)
        return rc, stdout

    def update_param_default(self, section, name):
        """恢复参数为默认值"""
        cmd = "pscli --command=get_params --section=%s --name=%s" % (section, name)
        rc, stdout = self.pscli_command(cmd)
        stdout = self.json_loads(stdout)
        default_value = stdout['result']['parameters'][0]['default']
        cmd = "pscli --command=update_param --section=%s --name=%s --current=%s" % (section, name, default_value)
        return self.pscli_command(cmd)

    def get_param(self, section, name):
        """获取参数当前值"""
        cmd = "pscli --command=get_params --section=%s --name=%s" % (section, name)
        rc, stdout = self.pscli_command(cmd)
        stdout = self.json_loads(stdout)
        return stdout['result']['parameters'][0]['current']

    def _get_nodes_info(self, node_ids=None, fault_node_ip=None):
        """获取节点信息"""
        if node_ids is None:
            cmd = "pscli --command=get_nodes"
        else:
            cmd = "pscli --command=get_nodes --ids=%s" % node_ids
        rc, stdout = self.pscli_command(cmd, timeout=600, fault_node_ip=fault_node_ip)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            return self.json_loads(stdout)

    def get_nodes_ip(self):
        """获取所有节点的管理网ip"""
        nodes_ips = []
        node_info = self._get_nodes_info()
        nodes = node_info['result']['nodes']
        for node in nodes:
            nodes_ips.append(node['ctl_ips'][0]['ip_address'])
        return nodes_ips

    def get_nodes_data_ip(self):
        """获取集群的所有数据网ip"""
        data_ip_lst = []
        stdout = self._get_nodes_info()
        node_info_lst = stdout['result']['nodes']
        for node_info in node_info_lst:
            for data_ip_info in node_info['data_ips']:
                data_ip_lst.append(data_ip_info['ip_address'])
        return data_ip_lst

    def get_node_id_by_ip(self, node_ip):
        """通过节点ip获取节点的id"""
        node_info = self._get_nodes_info()
        nodes_info = node_info["result"]["nodes"]
        for node in nodes_info:
            ctl_ip = node["ctl_ips"][0]["ip_address"]
            if node_ip == ctl_ip:
                return node["node_id"]
        logging.info("there is not a node's ip is %s!!!" % node_ip)
        return None

    def get_node_ip_by_id(self, node_id):
        """通过节点id获取节点的管理网ip"""
        node_info = self._get_nodes_info(node_ids=node_id)
        node_info = node_info["result"]["nodes"][0]
        node_ip = node_info['ctl_ips'][0]['ip_address']
        return node_ip

    def get_mgr_node_ids(self):
        """获取所有管理节点的id"""
        mgr_node_id_lst = []
        msg = self._get_nodes_info()
        nodes_info = msg["result"]["nodes"]
        for node_info in nodes_info:
            for service_info in node_info['services']:
                if service_info['service_type'] == 'oJmgs':
                    mgr_node_id_lst.append(node_info['node_id'])
                    break
        return mgr_node_id_lst

    def get_nodes_ips_by_ip(self, node_ip):
        """通过输入的ip获取集群中的所有节点的ip"""
        cmd = 'pscli --command=get_nodes'
        rc, stdout = self.command(cmd, node_ip)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            node_ip_lst = []
        node_info = self.json_loads(stdout)
        nodes = node_info['result']['nodes']
        for node in nodes:
            node_ip_lst.append(node['ctl_ips'][0]['ip_address'])
        return node_ip_lst

    def get_nodes_data_ip_by_ip(self, node_ip):
        """获取集群的所有数据网ip"""
        cmd = 'pscli --command=get_nodes'
        rc, stdout = self.command(cmd, node_ip)
        if rc != 0:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        data_ip_lst = []
        stdout = self.json_loads(stdout)
        node_info_lst = stdout['result']['nodes']
        for node_info in node_info_lst:
            for data_ip_info in node_info['data_ips']:
                data_ip_lst.append(data_ip_info['ip_address'])
        return data_ip_lst

    def get_local_node_ip(self):
        """获取本节点的管理ip"""
        cmd = "pscli --command=get_nodes"
        nodes_ips = []
        rc, stdout = self.command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            node_info = self.json_loads(stdout)
            nodes = node_info['result']['nodes']
            for node in nodes:
                nodes_ips.append(node['ctl_ips'][0]['ip_address'])

        cmd = 'ip addr | grep "inet "'
        rc, stdout = self.command(cmd)
        if 0 != rc:
            raise Exception(
                "Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        lines = stdout.strip().split('\n')
        for line in lines:
            ip = line.split()[1].split('/')[0]
            if ip in nodes_ips:
                return ip
        return None

    def _get_volumes_info(self):
        """获取卷的信息"""
        cmd = "pscli --command=get_volumes"
        rc, stdout = self.pscli_command(cmd)
        if rc != 0:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        return self.json_loads(stdout)

    def _get_disk_info(self, node_ids):
        """获取磁盘信息"""
        cmd = "pscli --command=get_disks --node_ids=%s" % node_ids
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            return self.json_loads(stdout)

    def get_disk_speed_by_name(self, node_id, disk_name):
        """获取磁盘速率"""
        result = self._get_disk_info(node_id)
        disk_list = result['result']['disks']
        for disk in disk_list:
            if disk['devname'] == disk_name:
                return disk['speed_level']
        return None

    def change_disk_speed_level(self, disk_id, disk_speed):
        """修改磁盘速率"""
        cmd = "pscli --command=change_disk_speed_level --disk_ids=%s --speed_level=%s" % (disk_id, disk_speed)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))

    def expand_disk_2_storage_pool(self, storage_pool_id, disk_id):
        """磁盘添加到存储池中"""
        cmd = 'pscli --command=expand_storage_pool --storage_pool_id=%s --disk_ids=%s' % (storage_pool_id, disk_id)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        return

    def check_metanode(self, node_id):
        """检查某个节点是否可以故障元数据盘"""
        mgr_node_id_lst = self.get_mgr_node_ids()
        cmd = '/home/parastor/tools/nWatch -t oRole -i %s -c oRole#rolemgr_master_dump' % mgr_node_id_lst[0]
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc or self.check_nwatch_stdout(stdout):
            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
            return False
        master_node_id = stdout.split(':')[-1].strip()
        cmd1 = '/home/parastor/tools/nWatch -t oRole -i %s -c oRole#rolemgr_slaveready_dump' % master_node_id
        rc, stdout = self.pscli_command(cmd1)
        if 0 != rc or self.check_nwatch_stdout(stdout):
            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd1, stdout))
            return False
        stdout_lst = stdout.strip().split('\n')
        for line in stdout_lst:
            if 'nodeid' in line and 'is_takeoverable' in line:
                node_id_tmp = line.split()[-2].split(':')[-1].rstrip(',')
                takeoverable = line.split()[-1].split(':')[-1].strip()
                if node_id_tmp != str(node_id):
                    continue
                if takeoverable != 'yes':
                    return False
        return True

    def _keep_check_metanode(self, node_id, node_ip):
        """不断检查jnl，直到可以做故障"""
        start_time = time.time()
        while True:
            flag = self.check_metanode(node_id)
            if flag is True:
                logging.info("the node %s jnl is OK!" % (node_ip))
                break
            else:
                exist_time = int(time.time() - start_time)
                m, s = divmod(exist_time, 60)
                h, m = divmod(m, 60)
                logging.info("the node %s jnl is not OK %dh:%dm:%ds!!! can't fault!!!" % (node_ip, h, m, s))
                time.sleep(30)

    def _keep_check_obuf(self, node_id, node_ip):
        """不断检查obuf"""
        start_time = time.time()
        while True:
            flag = self.check_metanode(node_id)
            if flag is True:
                logging.info("the node %s obuf is OK!" % (node_ip))
                break
            else:
                exist_time = int(time.time() - start_time)
                m, s = divmod(exist_time, 60)
                h, m = divmod(m, 60)
                logging.info("the node %s obuf is not OK %dh:%dm:%ds!!! can't fault!!!" % (node_ip, h, m, s))
                time.sleep(30)

    def get_sysinfo(self):
        """获取系统信息"""
        cmd = 'pscli --command=get_cluster_overview'
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            sys_info = self.json_loads(stdout)
            sys_name = sys_info['result']['name']
            sys_id = sys_info['result']['sysid']
            sys_uuid = sys_info['result']['uuid']
        return sys_name, sys_id, sys_uuid

    def get_cabinetinfo(self):
        """获取机柜信息"""
        cmd = 'pscli --command=get_cabinets'
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            cabinet_lst = []
            cabinet_info = self.json_loads(stdout)
            cabinets = cabinet_info['result']['cabinets']
            for cabinet in cabinets:
                height = cabinet['height']
                name = cabinet['name']
                cabinet_lst.append([name, height])
        return cabinet_lst

    def get_all_disk_name(self, node_id, disk_type):
        """获取所有硬盘名字"""
        disk_name_lst = []
        stdout = self._get_disk_info(node_id)
        for disk_info in stdout['result']['disks']:
            if disk_info['usage'] == disk_type:
                disk_name_lst.append(disk_info['devname'])
        return disk_name_lst

    def check_rebuild_job(self, fault_node_ip=None):
        cmd = 'pscli --command=get_jobengine_state'
        rc, stdout = self.pscli_command(cmd, fault_node_ip)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            msg = self.json_loads(stdout)
            jobs_info = msg["result"]["job_engines"]
            for job in jobs_info:
                if job['type'] == 'JOB_ENGINE_REBUILD':
                    return True
            return False

    def get_nodes_id(self):
        """获取所有节点的id"""
        nodes_ids = []
        node_info = self._get_nodes_info()
        nodes = node_info['result']['nodes']
        for node in nodes:
            nodes_ids.append(node['node_id'])
        return nodes_ids

    def check_node_healthy(self):
        """检查节点状态"""
        fault_node_dic = {}
        stdout = self._get_nodes_info()
        for node_info in stdout['result']['nodes']:
            if node_info['state'] == 'NODE_STATE_HEALTHY':
                continue
            else:
                fault_node_dic[node_info['ctl_ips'][0]['ip_address']] = node_info['state']
        if fault_node_dic:
            logging.error("some node state abnormal  %s" % fault_node_dic)
            return False
        else:
            logging.info("all node state is healthy")
            return True

    def check_disk_healthy(self):
        """检查磁盘状态"""
        fault_disk_lst = []
        node_id_lst = self.get_nodes_id()
        node_id_str = ','.join(map(str, node_id_lst))
        stdout = self._get_disk_info(node_id_str)
        for disk_info in stdout['result']['disks']:
            if disk_info['usedState'] != 'IN_USE' or disk_info['usage'] == 'SYSTEM':
                continue
            if disk_info['state'] != 'DISK_STATE_HEALTHY':
                fault_disk_dic = {'node_id': disk_info['nodeId'],
                                  'disk_name': disk_info['devname'],
                                  'disk_usage': disk_info['usage'],
                                  'disk_state': disk_info['state']}
                fault_disk_lst.append(fault_disk_dic)
        if fault_disk_lst:
            for disk_info in fault_disk_lst:
                logging.error("node:%s  %s  %s  %s" % (disk_info['node_id'], disk_info['disk_name'],
                                                       disk_info['disk_usage'], disk_info['disk_state']))
            return False
        else:
            logging.info("all disk state is healthy")
            return True

    def check_env(self):
        """脚本开始时检查节点和磁盘状态"""
        node_rc = self.check_node_healthy()
        disk_rc = self.check_disk_healthy()
        if not (node_rc and disk_rc):
            raise ReliableError("check env failed!!!")

    def get_clients(self):
        """获取客户端"""
        cmd = "pscli --command=get_clients"
        rc, stdout = self.pscli_command(cmd, timeout=600)
        if rc != 0:
            raise PscliError("Execute command: get clients failed. \nstdout: %s" % stdout)
        stdout = self.json_loads(stdout)
        if isinstance(stdout['result'], list):
            return stdout['result']
        else:
            return stdout['result']['client_services']

    def get_sys_ip(self):
        """获取系统中所有集群和客户端节点的ip"""
        sys_ip_lst = []
        nodes_lst = self.get_clients()
        for node in nodes_lst:
            sys_ip_lst.append(node['ip'])
        return sys_ip_lst

    def get_client_id_by_ip(self, node_ip):
        """获取客户端的id"""
        node_ips = self._get_node_all_ips(node_ip)
        nodes_lst = self.get_clients()
        for node_info in nodes_lst:
            if node_info['ip'] in node_ips:
                return node_info['node_id']
        return None

    def _check_core(self, node_ip):
        """检查节点是否有core"""
        core_path_lst = ['/home/parastor/log/', '/', '/var/log/']
        for core_path in core_path_lst:
            core_path_tmp = os.path.join(core_path, 'core*')
            cmd = 'ls %s' % core_path_tmp
            rc, result = self.command(cmd, node_ip)
            if 0 != rc:
                return True
            else:
                return False

    def check_core(self):
        """检查环境中是否有core"""
        flag = True
        core_node_lst = []
        sys_ip_lst = self.get_sys_ip()
        for node_ip in sys_ip_lst:
            # 先检查是否可以ping通
            if self.check_ping(node_ip) is False:
                logging.warn('node %s ping failed!!!' % node_ip)
                continue
            else:
                if self._check_core(node_ip) is False:
                    flag = False
                    core_node_lst.append(node_ip)
        if flag is False:
            core_node = ','.join(core_node_lst)
            logging.warn("These nodes %s has core!!! ", core_node)
        else:
            logging.info("The current environment does not have core")
        return

    def _check_badseg(self):
        """检查是否有坏段, 无坏段返回True, 有坏段返回False"""
        cmd = "pscli --command=get_cluster_overview"
        rc, stdout = self.pscli_command(cmd)
        if rc != 0:
            raise PscliError("Execute command: get clients failed. \nstdout: %s" % stdout)
        stdout = self.json_loads(stdout)
        sys_data_state = stdout['result']['cluster_data_state']
        if sys_data_state == 'SYSTEM_FAULT':
            no_badseg = False
        else:
            no_badseg = True
        logging.info("System Data State: %s" % sys_data_state)
        return no_badseg

    def check_badseg(self):
        """检查坏段, 如果有坏段, 检查10次"""
        num = 0
        while True:
            if self._check_badseg() is False:
                num += 1
                if num >= 10:
                    sys.exit(1)
                else:
                    logging.info("The %s time system has badseg, total times is 10" % num)
                    continue
            else:
                logging.info("The current environment does not have badseg")
                break

    def _check_badobj(self, node_ip):
        """检查坏对象"""
        cmd = "/home/parastor/tools/badobj.sh"
        badobj_num = 0
        rc, stdout = self.command(cmd, node_ip=node_ip)
        for line in stdout.splitlines():
            if 'badobjnr:' in line:
                try:
                    badobj_num += int(line.split(':')[-1].strip())
                except ValueError:
                    pass
        if badobj_num != 0:
            logging.info("badobj_num = %s" % (badobj_num))
            return 1
        logging.info("The current environment does not have badobj")
        return 0

    def check_badobj(self, waitflag=True, fault_ip=None):
        """每隔一段时间检查一遍是否还有坏对象"""
        if waitflag is True:
            # 等待60s
            logging.info("wait %ds" % self.check_badobj_wait_time)
            time.sleep(self.check_badobj_wait_time)

        def _check_badjob():
            node_ip_lst_bak = self.node_ip_lst[:]
            if fault_ip:
                if fault_ip in node_ip_lst_bak:
                    node_ip_lst_bak.remove(fault_ip)
            for node_ip in node_ip_lst_bak:
                # 检查是否可以ping通
                if self.check_ping(node_ip) is False:
                    continue
                result = self._check_badobj(node_ip)
                if -1 == result:
                    continue
                elif 1 == result:
                    return 1
                else:
                    return 0

        start_time = time.time()
        num = 0
        total_num = 5
        while True:
            time.sleep(20)
            if self.local_node_flag is False:
                if 0 == _check_badjob():
                    num += 1
                    if num >= total_num:
                        break
                    else:
                        logging.info("The %s time badobj is 0, total times is %s" % (num, total_num))
                        continue
                else:
                    num = 0
            else:
                if 0 == self._check_badobj(self.local_node_ip):
                    num += 1
                    if num >= total_num:
                        break
                    else:
                        logging.info("The %s time badobj is 0, total times is %s" % (num, total_num))
                        continue
                else:
                    num = 0
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            time_str = "badobj exist %dh:%dm:%ds" % (h, m, s)
            logging.info(time_str)
        return

    def _check_vset(self):
        """检查某个节点是否可以故障元数据盘"""
        vmgr_view_dump = self._get_role_view_dump('JNL_VSET')
        for node_id, lnode_lst in vmgr_view_dump.items():
            for lnode_id in lnode_lst:
                cmd = '/home/parastor/tools/nWatch -i %s -t oPara -c oPara#vmgr_flattennr_dump -a "vmgrid=%s"' \
                      % (node_id, lnode_id)
                rc, stdout = self.pscli_command(cmd)
                if (0 != rc) or self.check_nwatch_stdout(stdout) or ('support' in stdout):
                    logging.warn("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
                    return -1, 0
                try:
                    vset_num = stdout.strip().split('\n')[-1].split()[2]
                    if int(vset_num) != 0:
                        return 1, int(vset_num)
                    else:
                        continue
                except Exception, e:
                    logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
                    raise Exception("Error msg is %s" % e)
        logging.info("The current environment all vset is flatten")
        return 0, 0

    def check_vset(self):
        """检查vset"""
        start_time = time.time()
        while True:
            time.sleep(20)
            rc, vset_num = self._check_vset()
            if 0 == rc:
                break
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            if 1 == rc:
                time_str = "has %s vset %dh:%dm:%ds" % (vset_num, h, m, s)
                logging.info(time_str)
        return

    def _check_ds(self):
        """检查所有ds是否提供服务"""
        node_ids = self.get_nodes_id()
        for node_id in node_ids:
            cmd = '/home/parastor/tools/nWatch -i %s -t oStor -c oStor#get_basicinfo' % node_id
            rc, stdout = self.pscli_command(cmd)
            if 0 != rc or self.check_nwatch_stdout(stdout):
                logging.warn("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
                return -1
            else:
                stdout_lst = stdout.strip().split('\n')
                for line in stdout_lst:
                    if 'ostor serv stat' in line:
                        flag = line.split(':')[-1].strip()
                        try:
                            if 1 != int(flag):
                                return 1
                        except Exception:
                            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
                            raise
        logging.info("The current environment all ds service is OK")
        return 0

    def check_ds(self):
        """检查ds是否提供服务"""
        start_time = time.time()
        while True:
            time.sleep(20)
            rc = self._check_ds()
            if 0 == rc:
                break
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            if 1 == rc:
                time_str = "ds don't provide service %dh:%dm:%ds" % (h, m, s)
                logging.info(time_str)

    def _get_orole_master(self):

        mgr_node_id_lst = self.get_mgr_node_ids()
        for node_id in mgr_node_id_lst:
            cmd = '/home/parastor/tools/nWatch -t oRole -i %s -c oRole#rolemgr_master_dump' % node_id
            rc, stdout = self.pscli_command(cmd)
            if rc == 0 and 'rolemgr id:' in stdout:
                master_node_id = stdout.split(':')[-1].strip()
                return master_node_id
            else:
                continue
        return None

    def _get_role_view_dump(self, role):
        """
        :author:      baoruobing
        :date:        2021.05.12
        :Description: 获取逻辑角色分布
        :param role:  (str)角色 JNL_MDS|JNL_VSET|JNL_OSAN|JNL_OBUF|JNL_OSSA|JNL_OST
        :return:      (dict){节点1id: [逻辑角色id1, 逻辑角色id2...],
                             节点2id: [逻辑角色id3, 逻辑角色id4...],}
        """
        role_id_dic = {'JNL_MDS': '0',  # 文件lmos
                       'JNL_VSET': '1',  # vmgr
                       'JNL_OSAN': '3',  # 块lmos
                       'JNL_OBUF': '4',  # obuf
                       'JNL_OSSA': '5',  # 对象olmos和ovmgr
                       'JNL_OST': '6',  # 对象逻辑机头
                       }

        # 获取主oRole的节点id
        orole_node_id = self._get_orole_master()
        if orole_node_id is None:
            raise PscliError('get oRole master failed')

        # 执行查看逻辑角色分布的命令
        cmd = '/home/parastor/tools/nWatch -i %s -t oRole -c oRole#rolemgr_view_dump' % orole_node_id
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc or self.check_nwatch_stdout(stdout):
            raise PscliError("nWatch oRole#rolemgr_view_dump failed")

        role_view_dump = {}
        node_now_id = None
        role_str = "jtype:{}|{}".format(role_id_dic[role], role)
        role_begin = False
        for line in stdout.splitlines():
            # 如果逻辑角色内容已经开始并且又有了jtype: 则认为逻辑角色内容结束
            if role_begin is True and 'jtype:' in line:
                break
            # 发现逻辑角色开始标志
            if role_str in line:
                role_begin = True
                continue
            if role_begin:
                # 处于要获取的逻辑角色内容段内
                if '-->--> node_sn:' in line:
                    node_id = int(re.findall(r'node_id: (\d+?),', line)[0])
                    role_view_dump[node_id] = []
                    node_now_id = node_id
                elif '-->-->--> lnodeid:' in line:
                    lnode_id = int(re.findall(r'lnodeid: (\d+?),', line)[0])
                    role_view_dump[node_now_id].append(lnode_id)
        return role_view_dump

    def _check_sys_data_stat(self):
        """检查系统数据状态是否正常"""
        cmd = "pscli --command=get_cluster_overview"
        rc, stdout = self.pscli_command(cmd)
        if rc != 0:
            raise PscliError("Execute command: get clients failed. \nstdout: %s" % stdout)
        stdout = self.json_loads(stdout)
        sys_data_state = stdout['result']['cluster_data_state']
        logging.info("System Data State: %s" % sys_data_state)
        return sys_data_state == 'SYSTEM_NORMAL'

    def check_sys_data_stat(self):
        """检查系统数据服务状态"""
        start_time = time.time()
        while True:
            rc = self._check_sys_data_stat()
            if rc:
                break
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            if not rc:
                time_str = "system data state not normal %dh:%dm:%ds" % (h, m, s)
                logging.info(time_str)
            time.sleep(20)

    def check_system_recover(self, waitflag=True):
        """检查环境是否恢复"""
        # 检查环境是否有core
        self.check_core()
        # 检查环境是否有坏段
        self.check_badseg()
        # 检查环境是否有vset没有展平
        self.check_vset()
        # 检查环境中所有ds是否提供服务
        self.check_ds()
        # 检查环境是否有坏对象
        self.check_badobj(waitflag=waitflag)
        # 检查元数据正确性
        # check_metadata()
        # 检查系统数据服务状态
        self.check_sys_data_stat()

    def _check_node_in_parastor(self, node_ip):
        """检查节点是否在集群中"""
        if node_ip in self.node_ip_lst or node_ip in self.node_data_ip_lst:
            return True
        else:
            return False

    def _get_node_all_ips(self, node_ip):
        """获取一个节点的所有ip"""
        cmd = 'ip addr | grep "inet "'
        rc, stdout = self.command(cmd, node_ip, timeout=10)
        ip_lst = []
        for line in stdout.splitlines():
            ip_lst.append(line.strip().split()[1].split('/')[0])    # inet 10.22.166.71/20 brd ....
        return ip_lst


class DiskFaultBase(FaultBase):
    """磁盘故障基础类"""

    def get_diff_usage_disk_ids(self, node_ids):
        """获取不同用途的磁盘的id"""
        msg = self._get_disk_info(node_ids)
        share_disk_names = []
        monopoly_disk_names = []
        cache_disk_names = []
        disks_pool = msg['result']['disks']
        for disk in disks_pool:
            if disk['usage'] == 'SHARED' and disk['usedState'] == 'IN_USE' and disk['state'] == 'DISK_STATE_HEALTHY':
                share_disk_names.append(disk['devname'])
            elif disk['usage'] == 'DATA' and disk['usedState'] == 'IN_USE' and disk['state'] == 'DISK_STATE_HEALTHY':
                monopoly_disk_names.append(disk['devname'])
            elif disk['usage'] == 'CACHE' and disk['usedState'] == 'IN_USE' and disk['state'] == 'DISK_STATE_HEALTHY':
                cache_disk_names.append(disk['devname'])
        return share_disk_names, monopoly_disk_names, cache_disk_names

    def get_scsiid_by_name(self, node_ip, disk_name):
        """获取磁盘的scsiid"""
        cmd = 'lsscsi'
        rc, stdout = self.command(cmd, node_ip)
        if 0 != rc:
            raise ReliableError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            list_stdout = stdout.strip().split('\n')
            for mem in list_stdout:
                if disk_name in mem:
                    list_mem = mem.split()
                    id = list_mem[0]
                    id = id[1:-1]
                    return id
        return None

    def get_disk_id_by_uuid(self, node_id, disk_uuid):
        """通过磁盘的uuid获取磁盘的id"""
        cmd = "pscli --command=get_disks --node_ids=%s" % node_id
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        else:
            result = self.json_loads(stdout)
            disk_list = result['result']['disks']
            for disk in disk_list:
                if disk['uuid'] == disk_uuid:
                    return disk['id']
        return None

    def check_disk_del_ostor(self, node_id, disk_id):
        """检查oStor是否删除了磁盘"""
        cmd = '/home/parastor/tools/nWatch -t oStor -i %s -c oStor#disk_is_deleted -a "diskid=%s"' % (node_id, disk_id)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
            return False
        else:
            if stdout.strip() == '1':
                return True
            else:
                return False

    def get_disk_info_by_name(self, node_ip, disk_name):
        """获取磁盘信息"""
        disk_lsscsi_id = self.get_scsiid_by_name(node_ip, disk_name)
        node_id = self.get_node_id_by_ip(node_ip)

        disk_id = None
        disk_usage = None
        disk_speed_level = None
        disk_uuid = None
        storage_pool_id = None
        msg = self._get_disk_info(node_id)
        disk_list = msg['result']['disks']
        for disk in disk_list:
            if disk['devname'] == disk_name:
                disk_usage = disk['usage']
                disk_id = disk['id']
                disk_uuid = disk['uuid']
                disk_speed_level = disk['speed_level']
                storage_pool_id = disk['storagePoolId']
        disk_info = {'node_ip': node_ip,
                     'node_id': node_id,
                     'disk_id': disk_id,
                     'disk_uuid': disk_uuid,
                     'disk_name': disk_name,
                     'disk_usage': disk_usage,
                     'disk_lsscsi_id': disk_lsscsi_id,
                     'disk_speed_level': disk_speed_level,
                     'storage_pool_id': storage_pool_id}
        logging.info(disk_info)
        return disk_info

    def get_all_volume_layout(self):
        """
        :author:      baoruobing
        :date  :      2018.08.15
        :description: 获取所有卷的配比
        :return:      (list)卷的配比信息,[{'disk_parity_num':2,'node_parity_num':1,'replica_num':4}]
        """
        volumes_info = self._get_volumes_info()
        volumes_lst = volumes_info['result']['volumes']
        layout_lst = []
        for volume in volumes_lst:
            layout_dic = {}
            layout_dic['disk_parity_num'] = volume['layout']['disk_parity_num']
            layout_dic['node_parity_num'] = volume['layout']['node_parity_num']
            layout_dic['replica_num'] = volume['layout']['replica_num']
            layout_lst.append(layout_dic)
        return layout_lst

    def check_share_disk_fault(self, share_disk_num):
        """
        :author:               baoruobing
        :date  :               2018.08.15
        :description:          检查是否可以做元数据盘故障
        :param share_disk_num: 共享盘个数
        """
        # 获取所有卷的最大副本数
        layout_lst = self.get_all_volume_layout()
        replica_num = 0
        for layout in layout_lst:
            if layout['disk_parity_num'] != 0:
                replica_num_tmp = layout['disk_parity_num'] + 1
            else:
                replica_num_tmp = layout['replica_num']
            replica_num = replica_num_tmp > replica_num and replica_num_tmp or replica_num

        if share_disk_num > replica_num:
            return True
        else:
            return False

    def choose_node_and_disk(self):
        """按照参数-f的值随机选择f个要故障的磁盘"""
        # 获取所有节点管理网
        share_disk_lst = []
        monopoly_disk_lst = []
        cache_disk_lst = []
        if len(self.fault_node_ip_lst) == 0:
            node_ip_lst = self.get_nodes_ip()
        else:
            node_ip_lst = self.fault_node_ip_lst[:]

        # 检查是否有节点不在集群内
        for node_ip in node_ip_lst:
            if not self._check_node_in_parastor(node_ip):
                logging.warn("node {} not in parastor".format(node_ip))
                return -1, None

        for node_ip in node_ip_lst:
            node_id = self.get_node_id_by_ip(node_ip)
            # 获取节点中的硬盘
            share_disk_names, monopoly_disk_names, cache_disk_names = self.get_diff_usage_disk_ids(node_id)
            for share_disk_name in share_disk_names:
                tmp_lst = [node_ip, share_disk_name]
                share_disk_lst.append(tmp_lst)
            for monopoly_disk_name in monopoly_disk_names:
                tmp_lst = [node_ip, monopoly_disk_name]
                monopoly_disk_lst.append(tmp_lst)
            for cache_disk_name in cache_disk_names:
                tmp_lst = [node_ip, cache_disk_name]
                cache_disk_lst.append(tmp_lst)

        all_disk_lst = share_disk_lst + monopoly_disk_lst + cache_disk_lst

        # 根据参数随机获取一块磁盘
        disk_names_dir = {'all': all_disk_lst,
                          'data': monopoly_disk_lst,
                          'meta': share_disk_lst,
                          'cache': cache_disk_lst}

        # 如果元数据盘小于等于副本数,则不做元数据盘故障
        # if self.check_share_disk_fault(len(share_disk_lst)) is False:
        #     if self.fault_disk_type == 'meta':
        #         logging.warn("share disk num < replica num, can't make meta disk fault!!!")
        #         return -1, None
        #     else:
        #         tem_disk_lst = disk_names_dir.get('data') + disk_names_dir.get('cache')
        # else:
        #     tem_disk_lst = disk_names_dir.get(self.fault_disk_type)
        tem_disk_lst = disk_names_dir.get(self.fault_disk_type)

        # 如果磁盘总个数小于配置的-n，则报错退出
        if len(tem_disk_lst) < self.fault_disk_num:
            logging.warn("The %s disk num is %d, less than -n %d" % (self.fault_disk_type, len(tem_disk_lst),
                                                                     self.fault_disk_num))
            return -1, None

        if self.fault_disk_type == 'meta':
            fault_disk_lst = random.sample(tem_disk_lst, 1)
        elif self.fault_disk_type == 'all':
            for i in range(10):
                fault_disk_lst = random.sample(tem_disk_lst, self.fault_disk_num)
                num = 0
                for fault_disk in fault_disk_lst:
                    if fault_disk in share_disk_lst:
                        num += 1
                if num <= 1:
                    break
            else:
                logging.warn("share can't fail more than 1 disk")
                return -1, None
        else:
            fault_disk_lst = random.sample(tem_disk_lst, self.fault_disk_num)

        for fault_disk in fault_disk_lst:
            if fault_disk in share_disk_lst:
                start_time = time.time()
                while True:
                    fault_node_ip = fault_disk[0]
                    fault_node_id = self.get_node_id_by_ip(fault_node_ip)
                    flag = self.check_metanode(fault_node_id)
                    if flag is True:
                        logging.info("the node %s jnl is OK!" % (fault_node_ip))
                        break
                    else:
                        exist_time = int(time.time() - start_time)
                        m, s = divmod(exist_time, 60)
                        h, m = divmod(m, 60)
                        logging.info(
                            "the node %s jnl is not OK %dh:%dm:%ds!!! can't fault!!!" % (fault_node_ip, h, m, s))
                        logging.info("wait 30s")
                        time.sleep(30)
        return 0, fault_disk_lst

    def remove_disk(self, node_ip, disk_id, disk_usage):
        """拔出某个节点的一个硬盘"""
        cmd = 'echo scsi remove-single-device %s > /proc/scsi/scsi' % disk_id
        logging.info('node %s pullout disk %s, disk usage is %s' % (node_ip, disk_id, disk_usage))
        rc, stdout = self.command(cmd, node_ip)
        if 0 != rc:
            logging.error('node %s remove disk %s fault!!!' % (node_ip, disk_id))
        return

    def remove_disks(self, fault_disk_info_lst):
        """批量拔盘"""
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            disk_lsscsi_id = fault_disk_info['disk_lsscsi_id']
            disk_usage = fault_disk_info['disk_usage']
            self.remove_disk(fault_node_ip, disk_lsscsi_id, disk_usage)

    def insert_disk(self, node_ip, disk_id, disk_usage):
        """插入某个节点的一个硬盘"""
        cmd = 'echo scsi add-single-device %s > /proc/scsi/scsi' % disk_id
        logging.info('node %s insert disk %s, disk usage is %s' % (node_ip, disk_id, disk_usage))
        rc, stdout = self.command(cmd, node_ip)
        if 0 != rc:
            logging.error('node %s add disk %s fault!!!' % (node_ip, disk_id))
        time.sleep(5)
        cmd = 'lsscsi'
        rc, stdout = self.command(cmd, node_ip)
        logging.info(stdout)
        return

    def insert_disks(self, fault_disk_info_lst):
        """批量插盘"""
        for fault_disk_info in fault_disk_info_lst:
            # 插盘
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_phy_id = fault_disk_info['disk_lsscsi_id']
            fault_disk_usage = fault_disk_info["disk_usage"]
            self.insert_disk(fault_node_ip, fault_disk_phy_id, fault_disk_usage)

    def delete_disk(self, disk_id):
        """同步删除磁盘"""
        cmd = "pscli --command=remove_disks --disk_ids=%s" % disk_id
        rc, stdout = self.pscli_command(cmd)
        return rc, stdout

    def delete_disk_noquery(self, disk_id):
        """异步删除磁盘"""
        cmd = "pscli --command=remove_disks --disk_ids=%s --auto_query=false" % disk_id
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        return

    def delete_disks(self, fault_disk_info_lst):
        """批量删盘"""
        fault_disk_id_lst = []
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_usage = fault_disk_info["disk_usage"]
            fault_disk_id_old = fault_disk_info['disk_id']
            logging.info(
                'node %s begin delete disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name, fault_disk_usage))
            fault_disk_id_lst.append(str(fault_disk_id_old))
        fault_disk_id_str = ','.join(fault_disk_id_lst)
        while True:
            rc, stdout = self.delete_disk(fault_disk_id_str)
            if rc != 0:
                stdout = self.json_loads(stdout)
                if stdout['err_no'] == 6117:
                    logging.warning('other delete disk task is running, wait 30s')
                    time.sleep(30)
                else:
                    raise Exception("Execute command: delete disk failed. \nstdout: %s" % (stdout))
            else:
                break
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_name = fault_disk_info['disk_name']
            logging.info('node %s delete disk %s success' % (fault_node_ip, fault_disk_name))

    def delete_disks_noquery(self, fault_disk_info_lst):
        """异步批量删除磁盘"""
        fault_disk_id_lst = []
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_usage = fault_disk_info["disk_usage"]
            fault_disk_id_old = fault_disk_info['disk_id']
            logging.info(
                'node %s begin delete disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name, fault_disk_usage))
            fault_disk_id_lst.append(str(fault_disk_id_old))
        fault_disk_id_str = ','.join(fault_disk_id_lst)
        self.delete_disk_noquery(fault_disk_id_str)

    def check_disk_del(self, fault_disk_info_lst):
        """检查磁盘是否删除"""
        start_time = time.time()
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_node_id = fault_disk_info['node_id']
            fault_disk_uuid = fault_disk_info['disk_uuid']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_id_old = fault_disk_info['disk_id']
            # 检查磁盘是否删除
            while True:
                if (not self.get_disk_id_by_uuid(fault_node_id, fault_disk_uuid) and
                        self.check_disk_del_ostor(fault_node_id, fault_disk_id_old)):
                    logging.info('node %s disk %s delete success!!!' % (fault_node_ip, fault_disk_name))
                    break
                time.sleep(20)
                exist_time = int(time.time() - start_time)
                m, s = divmod(exist_time, 60)
                h, m = divmod(m, 60)
                logging.info('node %s disk %s delete %dh:%dm:%ds' % (fault_node_ip, fault_disk_name, h, m, s))

    def cancel_delete_disk(self, disk_id):
        """取消删除磁盘"""
        cmd = "pscli --command=cancel_remove_disks --disk_ids=%s" % disk_id
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            logging.warn("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        return

    def cancel_delete_disks(self, fault_disk_info_lst):
        """取消删除磁盘"""
        fault_disk_id_lst = [str(fault_disk_info['disk_id']) for fault_disk_info in fault_disk_info_lst]
        logging.info("cancel delete disk %s" % fault_disk_id_lst)
        fault_disk_id_str = ','.join(fault_disk_id_lst)
        self.cancel_delete_disk(fault_disk_id_str)

    def add_disk(self, node_id, uuid, usage, exit_flag=True):
        """添加磁盘"""
        # 等磁盘被系统识别
        self.wait_disk_exist(node_id, uuid)
        cmd = ("pscli --command=add_disks --node_ids=%s --disk_uuids=%s --usage=%s" % (node_id, uuid, usage))
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
            if exit_flag:
                raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        return rc

    def add_disks(self, fault_disk_info_lst):
        """添加磁盘"""
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_node_id = fault_disk_info['node_id']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_uuid = fault_disk_info['disk_uuid']
            fault_disk_usage = fault_disk_info['disk_usage']
            fault_disk_speed = fault_disk_info['disk_speed_level']
            logging.info('node %s add disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name, fault_disk_usage))
            self.add_disk(fault_node_id, fault_disk_uuid, fault_disk_usage)
            logging.info('node %s add disk %s success' % (fault_node_ip, fault_disk_name))

            # 加入存储池
            if 'DATA' == fault_disk_usage:
                fault_disk_id_new = self.get_disk_id_by_uuid(fault_node_id, fault_disk_uuid)
                # 修改磁盘速率
                self.change_disk_speed_level(fault_disk_id_new, fault_disk_speed)

                storage_pool_id = fault_disk_info['storage_pool_id']
                logging.info(
                    'node %s add disk %s to storage_pool %s' % (fault_node_ip, fault_disk_name, storage_pool_id))
                self.expand_disk_2_storage_pool(storage_pool_id, fault_disk_id_new)
                logging.info('node %s add disk %s to storage_pool %s success'
                             % (fault_node_ip, fault_disk_name, storage_pool_id))

    def wait_disk_del_or_healthy(self, fault_disk_info_lst):
        """等待磁盘删除成功或者状态是healthy"""
        del_disk_info_lst = []
        start_time = time.time()
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_node_id = fault_disk_info['node_id']
            fault_disk_uuid = fault_disk_info['disk_uuid']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_id_old = fault_disk_info['disk_id']
            # 检查磁盘是否删除
            while True:
                # 检查磁盘是否删除
                if (0 == self.get_disk_id_by_uuid(fault_node_id, fault_disk_uuid) and
                        self.check_disk_del_ostor(fault_node_id, fault_disk_id_old)):
                    logging.info('node %s disk %s delete!!!' % (fault_node_ip, fault_disk_name))
                    del_disk_info_lst.append(fault_disk_info)
                    break
                # 检查磁盘是否是healthy
                if self.get_disk_state(fault_node_id, fault_disk_id_old) == 'DISK_STATE_HEALTHY':
                    break
                exist_time = int(time.time() - start_time)
                m, s = divmod(exist_time, 60)
                h, m = divmod(m, 60)
                logging.info('node %s disk %s cancel delete %dh:%dm:%ds' % (fault_node_ip, fault_disk_name, h, m, s))
                time.sleep(20)
        return del_disk_info_lst

    def get_disk_state(self, node_id, disk_id):
        """获取磁盘状态"""
        stdout = self._get_disk_info(node_id)
        for disk_info in stdout['result']['disks']:
            if disk_info['id'] == disk_id:
                return disk_info['state']
        return None

    def check_disk_state(self, disk_info_lst, state):
        """
        检查磁盘状态
        state: HEALTHY, ZOMBIE
        """
        disk_state = "DISK_STATE_" + state.upper()
        for disk_info in disk_info_lst:
            node_id = disk_info['node_id']
            disk_id = disk_info['disk_id']
            stdout = self._get_disk_info(node_id)
            for disk_info in stdout['result']['disks']:
                if disk_info['id'] == disk_id and disk_info['state'] != disk_state:
                    return False
        return True

    def get_devname_by_scsiid(self, node_ip, scsiid):
        """通过scsiid获取磁盘名字"""
        cmd = "lsscsi | grep %s" % scsiid
        rc, stdout = self.command(cmd, node_ip=node_ip)
        if 0 != rc or "dev" not in stdout:
            logging.error("get dev name failed stdout: %s" % stdout)
        dev_name = stdout.rstrip().split()[-1]
        return dev_name

    def get_disk_uuid_by_name(self, node_id, disk_name, new_disk=False):
        """通过磁盘名字获取uuid"""
        result = self._get_disk_info(node_id)
        disk_list = result['result']['disks']
        for disk in disk_list:
            if new_disk:
                if disk['devname'] == disk_name and 0 == disk['id']:
                    return disk['uuid']
            else:
                if disk['devname'] == disk_name:
                    return disk['uuid']
        return None

    def wait_disk_exist(self, node_id, uuid):
        start_time = time.time()
        while True:
            if self.check_uuid(node_id, uuid):
                break
            exist_time = int(time.time() - start_time)
            if exist_time > 300:
                raise ReliableError("node %s disk %s does not exist for more than 5 minutes")
            time.sleep(5)

    def check_uuid(self, node_id, uuid):
        """检查uuid的磁盘是否存在"""
        stdout = self._get_disk_info(node_id)
        for disk_info in stdout['result']['disks']:
            if disk_info['uuid'] == uuid:
                return True
        return False


class DiskDownNoWait(DiskFaultBase):
    """拔盘->插盘"""

    def __str__(self):
        return "[disk fault: pullout disk -> insert disk]"

    def main(self):
        """故障主函数"""
        # 恢复磁盘重建时间
        rc, stdout = self.update_param_default('MGR', 'disk_isolate2rebuild_timeout')
        if 0 != rc:
            logging.error('update param failed!!!')
            return False

        # 选择故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 获取磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]
            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            fault_disk_info_lst.append(tmp_dic)

        # 拔盘
        self.remove_disks(fault_disk_info_lst)

        self.wait_time('down_disk')

        # 插盘
        self.insert_disks(fault_disk_info_lst)

        # 共享盘和缓存盘需要删除
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info["node_ip"]
            fault_disk_usage = fault_disk_info["disk_usage"]
            fault_disk_name = fault_disk_info["disk_name"]
            fault_disk_id_old = fault_disk_info["disk_id"]
            if fault_disk_usage == 'SHARED' or fault_disk_usage == 'CACHE':
                logging.info(
                    'node %s delete disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name, fault_disk_usage))
                while True:
                    rc, stdout = self.delete_disk(fault_disk_id_old)
                    if rc != 0:
                        stdout = self.json_loads(stdout)
                        if stdout['err_no'] == 6117:
                            logging.warning('other delete disk task is running, wait 30s')
                            time.sleep(30)
                        else:
                            raise Exception("Execute command: delete disk failed. \nstdout: %s" % (stdout))
                    else:
                        break
                logging.info('node %s delete disk %s success' % (fault_node_ip, fault_disk_name))

        logging.info("wait 30s")
        time.sleep(30)

        # 检查是否删除
        start_time = time.time()
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_node_id = fault_disk_info['node_id']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_id_old = fault_disk_info['disk_id']
            fault_disk_usage = fault_disk_info["disk_usage"]
            fault_disk_uuid = fault_disk_info['disk_uuid']
            if fault_disk_usage == 'SHARED' or fault_disk_usage == 'CACHE':
                # 检查磁盘是否删除
                while True:
                    if (0 == self.get_disk_id_by_uuid(fault_node_id, fault_disk_uuid) and
                            self.check_disk_del_ostor(fault_node_id, fault_disk_id_old)):
                        logging.info('node %s disk %s delete success!!!' % (fault_node_ip, fault_disk_name))
                        break
                    time.sleep(20)
                    exist_time = int(time.time() - start_time)
                    m, s = divmod(exist_time, 60)
                    h, m = divmod(m, 60)
                    logging.info('node %s disk %s delete %dh:%dm:%ds' % (fault_node_ip, fault_disk_name, h, m, s))

        # 共享盘和缓存盘需要添加
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info["node_ip"]
            fault_node_id = fault_disk_info["node_id"]
            fault_disk_name = fault_disk_info["disk_name"]
            fault_disk_usage = fault_disk_info["disk_usage"]
            fault_disk_uuid = fault_disk_info['disk_uuid']
            if fault_disk_usage == 'SHARED' or fault_disk_usage == 'CACHE':
                logging.info('node %s add disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name,
                                                                        fault_disk_usage))
                self.add_disk(fault_node_id, fault_disk_uuid, fault_disk_usage)
                logging.info('node %s add disk %s success' % (fault_node_ip, fault_disk_name))
        return


class DiskDownWaitZombie(DiskFaultBase):
    """拔盘->zombie->插盘->删盘->加盘"""

    def __str__(self):
        return "[disk fault: pullout disk -> zombie -> insert disk -> del disk -> add disk]"

    def main(self):
        """主故障函数"""
        # 修改磁盘超时参数
        rc, stdout = self.update_param('MGR', 'disk_isolate2rebuild_timeout', 60000)
        if 0 != rc:
            logging.error('update param failed!!!')
            return

        # 随机选择故障节点和故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 用字典记录磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]
            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            fault_disk_info_lst.append(tmp_dic)

        # 拔盘
        self.remove_disks(fault_disk_info_lst)

        logging.info("waiting 90s")
        time.sleep(90)

        # 检查磁盘状态
        start_time = time.time()
        while True:
            if self.check_disk_state(fault_disk_info_lst, 'ZOMBIE') is True:
                logging.info('disk state is ZOMBIE!!!')
                break
            time.sleep(20)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            logging.info('disk state is not ZOMBIE %dh:%dm:%ds' % (h, m, s))

        # 检查坏对象
        self.check_badobj()

        # 插盘
        self.insert_disks(fault_disk_info_lst)

        # 删除磁盘
        self.delete_disks(fault_disk_info_lst)

        logging.info("wait 30s")
        time.sleep(30)

        # 检查是否删除
        self.check_disk_del(fault_disk_info_lst)

        # 加入磁盘
        self.add_disks(fault_disk_info_lst)

        # 恢复磁盘超时参数
        rc, stdout = self.update_param_default('MGR', 'disk_isolate2rebuild_timeout')
        if 0 != rc:
            logging.error('update param failed!!!')
            return


class DiskDownWaitRebuild(DiskFaultBase):
    """拔盘->rebuild->插盘->删盘->加盘"""

    def __str__(self):
        return "[disk fault: pullout disk -> rebuild -> insert disk -> del disk -> add disk]"

    def main(self):
        """故障主函数"""
        # 修改磁盘超时参数
        rc, stdout = self.update_param('MGR', 'disk_isolate2rebuild_timeout', 60000)
        if 0 != rc:
            logging.error('update param failed!!!')
            return

        # 随机选择故障节点和故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 用字典记录磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]
            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            fault_disk_info_lst.append(tmp_dic)

        # 拔盘
        self.remove_disks(fault_disk_info_lst)

        logging.info("waiting 60s")
        time.sleep(60)

        # 检查磁盘状态
        start_time = time.time()
        for _ in range(18):
            if self.check_disk_state(fault_disk_info_lst, 'REBUILDING_PASSIVE') is True:
                logging.info('disk state is REBUILDING_PASSIVE!!!')
                break
            time.sleep(10)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            logging.info('disk state is not REBUILDING_PASSIVE %dh:%dm:%ds' % (h, m, s))

        wait_time = random.randint(30, 120)
        logging.info("wait %ss" % wait_time)
        time.sleep(wait_time)

        # 删除磁盘
        self.delete_disks(fault_disk_info_lst)

        logging.info("wait 30s")
        time.sleep(30)

        # 检查是否删除
        self.check_disk_del(fault_disk_info_lst)

        # 插盘
        self.insert_disks(fault_disk_info_lst)

        # 加入磁盘
        self.add_disks(fault_disk_info_lst)

        # 恢复磁盘超时参数
        rc, stdout = self.update_param_default('MGR', 'disk_isolate2rebuild_timeout')
        if 0 != rc:
            logging.error('update param failed!!!')
            return


class DiskDel(DiskFaultBase):
    """删盘->加盘"""

    def __str__(self):
        return "[disk fault: del disk -> add disk]"

    def main(self):
        """
        故障主函数
        """
        # 随机选择故障节点和故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 用字典记录磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]
            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            fault_disk_info_lst.append(tmp_dic)

        # 删盘
        self.delete_disks(fault_disk_info_lst)

        logging.info("wait 30s")
        time.sleep(30)

        # 检查磁盘是否删除
        self.check_disk_del(fault_disk_info_lst)

        # 添加磁盘
        logging.info("wait 300s")
        time.sleep(300)

        self.add_disks(fault_disk_info_lst)


class DiskDelDownDisk(DiskFaultBase):
    """删盘->拔盘->插盘->加盘"""

    def __str__(self):
        return "[disk fault: del disk -> pullout disk -> insert disk -> add disk]"

    def main(self):
        """故障主函数"""
        # 随机选择故障节点和故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 用字典记录磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]
            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            fault_disk_info_lst.append(tmp_dic)

        # 删盘
        self.delete_disks_noquery(fault_disk_info_lst)

        wait_time = random.randint(30, 300)
        logging.info("wait %ss" % wait_time)
        time.sleep(wait_time)

        # 拔盘
        self.remove_disks(fault_disk_info_lst)

        logging.info("wait 30s")
        time.sleep(30)

        # 检查磁盘是否删除
        self.check_disk_del(fault_disk_info_lst)

        # 插盘
        self.insert_disks(fault_disk_info_lst)

        # 添加磁盘
        logging.info("wait 300s")
        time.sleep(300)

        self.add_disks(fault_disk_info_lst)


class DiskDelCancel(DiskFaultBase):
    """del disk -> cancel del disk"""

    def __str__(self):
        return "[disk fault: del disk -> cancel del disk]"

    def main(self):
        """故障主函数"""
        # 随机选择故障节点和故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 用字典记录磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]
            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            fault_disk_info_lst.append(tmp_dic)

        # 删盘
        self.delete_disks_noquery(fault_disk_info_lst)

        wait_time = random.randint(60, 300)
        logging.info("wait %ss" % wait_time)
        time.sleep(wait_time)

        # 取消删盘
        self.cancel_delete_disks(fault_disk_info_lst)

        logging.info("wait %s" % 30)
        time.sleep(30)

        # 等待磁盘状态是healthy或者删除成功
        del_disk_info_lst = self.wait_disk_del_or_healthy(fault_disk_info_lst)

        # 将删除的磁盘添加
        self.add_disks(del_disk_info_lst)


class DiskDownChangeUuid(DiskFaultBase):
    """拔盘->插盘->修改uuid->添加新盘->删除旧盘"""

    def __str__(self):
        return "[disk fault: pullout disk -> insert disk -> change uuid -> add new disk -> del old disk]"

    def main(self):
        """故障主函数"""
        # 修改磁盘超时参数
        logging.info("start to modify disk uuid")
        rc, stdout = self.update_param('MGR', 'disk_isolate2rebuild_timeout', 60000)
        if 0 != rc:
            logging.error('update param failed!!!')
            return

        # 随机选择故障节点和故障磁盘
        rc, fault_disk_lst = self.choose_node_and_disk()
        if rc != 0:
            logging.warn("can't select meta disk!!!")
            return

        # 用字典记录磁盘信息
        fault_disk_info_lst = []
        for fault_disk in fault_disk_lst:
            fault_node_ip = fault_disk[0]
            fault_disk_name = fault_disk[1]

            tmp_dic = self.get_disk_info_by_name(fault_node_ip, fault_disk_name)
            tmp_dic['disk_uuid_old'] = tmp_dic['disk_uuid']
            fault_disk_info_lst.append(tmp_dic)

            # 拔盘
            self.remove_disk(fault_node_ip, tmp_dic['disk_lsscsi_id'], tmp_dic['disk_usage'])

        # 触发被动重建后，不等待被动重建完成（模拟坏盘）
        self.wait_time('down_disk')

        try:
            for fault_disk_info in fault_disk_info_lst:
                # 插盘
                fault_node_ip = fault_disk_info['node_ip']
                fault_disk_phy_id = fault_disk_info['disk_lsscsi_id']
                fault_disk_usage = fault_disk_info["disk_usage"]
                self.insert_disk(fault_node_ip, fault_disk_phy_id, fault_disk_usage)

                # 修改uuid
                time.sleep(5)  # 刚插回来就修改会修改失败，等待5s
                fault_disk_name = self.get_devname_by_scsiid(fault_node_ip, fault_disk_phy_id)

                # 获取磁盘逻辑分区大小
                cmd = "parted -s %s print | grep Sector" % fault_disk_name
                rc, stdout = self.command(cmd=cmd, node_ip=fault_node_ip)
                logical_size = re.findall(r'(\d+)B/\d+', stdout)[0]

                for i in range(10):
                    cmd = "parted %s -s mklabel gpt" % fault_disk_name
                    logging.info("node ip: %s cmd: %s" % (fault_node_ip, cmd))
                    rc, stdout = self.command(cmd, node_ip=fault_node_ip)
                    if rc != 0:
                        time.sleep(2)
                        logging.error("modify uuid failed stdout: %s" % stdout)
                        continue

                    # 清理管理超级块
                    cmd = "dd if=/dev/zero of=%s bs=%s seek=34 count=1" % (fault_disk_name, logical_size)
                    rc, stdout = self.command(cmd, node_ip=fault_node_ip)
                    if rc != 0:
                        logging.error("dd failed! stdout: %s" % stdout)
                        time.sleep(2)
                        continue
                    logging.info("node: %s disk: %s modify uuid succeed" % (fault_node_ip, fault_disk_name))
                    break
                else:
                    raise ReliableError("modify uuid failed for 10 times")
        except ReliableError:
            # 插盘
            self.insert_disks(fault_disk_info_lst)

            time.sleep(60)

            # 删除磁盘
            self.delete_disks(fault_disk_info_lst)

            logging.info("wait 30s")
            time.sleep(30)

            # 检查是否删除
            self.check_disk_del(fault_disk_info_lst)

            # 加入磁盘
            self.add_disks(fault_disk_info_lst)
            return

        # 再做一次拔盘和删盘
        for fault_disk_info in fault_disk_info_lst:
            # 拔盘
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_phy_id = fault_disk_info['disk_lsscsi_id']
            fault_disk_usage = fault_disk_info['disk_usage']
            self.remove_disk(fault_node_ip, fault_disk_phy_id, fault_disk_usage)

        time.sleep(10)

        for fault_disk_info in fault_disk_info_lst:
            # 插盘
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_phy_id = fault_disk_info['disk_lsscsi_id']
            fault_disk_usage = fault_disk_info["disk_usage"]
            self.insert_disk(fault_node_ip, fault_disk_phy_id, fault_disk_usage)

        # 加入磁盘
        time.sleep(90)  # 等待管理扫到新盘
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_node_id = fault_disk_info['node_id']

            # 更新新盘数据
            fault_disk_name = self.get_devname_by_scsiid(fault_node_ip, fault_disk_info['disk_lsscsi_id'])
            while True:
                fault_disk_uuid = self.get_disk_uuid_by_name(fault_disk_info['node_id'], fault_disk_name, new_disk=True)
                if fault_disk_uuid:
                    break
                logging.info("wait mgr scan disk")
                time.sleep(10)
            fault_disk_info["disk_name"] = fault_disk_name
            fault_disk_info["disk_uuid"] = fault_disk_uuid

            fault_disk_usage = fault_disk_info['disk_usage']
            logging.info('node %s add disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name, fault_disk_usage))
            for _ in range(5):  # 扫描到磁盘后，不能立刻被集群捕获到，添加重试5min
                rc = self.add_disk(fault_node_id, fault_disk_uuid, fault_disk_usage, exit_flag=False)
                if 0 == rc:
                    break
                else:
                    logging.info("wait 60s and do next try")
                    time.sleep(60)
            else:
                raise ReliableError("add disk failed")
            logging.info('node %s add disk %s success' % (fault_node_ip, fault_disk_name))

            # 加入存储池
            if 'DATA' == fault_disk_usage:
                fault_disk_id_new = self.get_disk_id_by_uuid(fault_node_id, fault_disk_uuid)
                storage_pool_id = fault_disk_info['storage_pool_id']
                logging.info(
                    'node %s add disk %s to storage_pool %s' % (fault_node_ip, fault_disk_name, storage_pool_id))
                self.expand_disk_2_storage_pool(storage_pool_id, fault_disk_id_new)
                logging.info('node %s add disk %s to storage_pool %s success'
                             % (fault_node_ip, fault_disk_name, storage_pool_id))

        # 检查坏对象
        # self.check_badobj(waitflag=False)

        # 删除磁盘（恢复环境）
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_usage = fault_disk_info['disk_usage']
            fault_disk_id_old = fault_disk_info['disk_id']

            logging.info(
                'node %s delete disk %s, disk usage is %s' % (fault_node_ip, fault_disk_name, fault_disk_usage))
            while True:
                rc, stdout = self.delete_disk(fault_disk_id_old)
                if rc != 0:
                    stdout = self.json_loads(stdout)
                    if stdout['err_no'] == 6117:
                        logging.warning('other delete disk task is running, wait 30s')
                        time.sleep(30)
                    else:
                        raise Exception("Execute command: delete disk failed. \nstdout: %s" % (stdout))
                else:
                    break
            logging.info('node %s delete disk %s success' % (fault_node_ip, fault_disk_name))

        logging.info("wait 30s")
        time.sleep(30)

        # 检查是否删除
        start_time = time.time()
        for fault_disk_info in fault_disk_info_lst:
            fault_node_ip = fault_disk_info['node_ip']
            fault_node_id = fault_disk_info['node_id']
            fault_disk_name = fault_disk_info['disk_name']
            fault_disk_id_old = fault_disk_info['disk_id']
            # 检查磁盘是否删除
            while True:
                if (not self.check_uuid(fault_node_id, fault_disk_info['disk_uuid_old'])) \
                        and self.check_disk_del_ostor(fault_node_id, fault_disk_id_old):
                    logging.info('node %s disk %s delete success!!!' % (fault_node_ip, fault_disk_name))
                    break
                time.sleep(20)
                exist_time = int(time.time() - start_time)
                m, s = divmod(exist_time, 60)
                h, m = divmod(m, 60)
                logging.info('node %s disk %s delete %dh:%dm:%ds' % (fault_node_ip, fault_disk_name, h, m, s))

        # 恢复磁盘超时参数
        rc, stdout = self.update_param_default('MGR', 'disk_isolate2rebuild_timeout')
        if 0 != rc:
            logging.error('update param failed!!!')
            return False
        return


class ProcessKill(FaultBase):
    """进程故障"""

    def __str__(self):
        return "[process kill]"

    def main(self):
        """故障主函数"""
        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]
        # 随机获取一个节点ip
        node_ip = random.choice(fault_node_ip_lst)

        # 检查节点是否可以故障
        fault_node_id = self.get_node_id_by_ip(node_ip)
        start_time = time.time()
        while True:
            flag = self.check_metanode(fault_node_id)
            if flag is True:
                logging.info("the node %s jnl is OK!" % (node_ip))
                break
            else:
                exist_time = int(time.time() - start_time)
                m, s = divmod(exist_time, 60)
                h, m = divmod(m, 60)
                logging.info("the node %s jnl is not OK %dh:%dm:%ds!!! can't fault!!!" % (node_ip, h, m, s))
                logging.info("wait 30s, re select node")
                time.sleep(30)

        # 随机kill节点的一组进程
        fault_process_lst = self.random_kill_process(node_ip)

        # 不断检查进程是否起来
        while True:
            logging.info("wait 60 s")
            time.sleep(60)
            for process in fault_process_lst:
                if self.check_process(node_ip, process) is False:
                    logging.info('node %s process %s is not normal!!!' % (node_ip, process))
                    break
            else:
                break

        logging.info("all process is OK")
        return

    def random_kill_process(self, node_ip):
        """随机kill进程"""
        if self.fault_pro_lst:
            tem_process_lst = self.fault_pro_lst[:]
        else:
            # 随机获取一组进程，检查进程是否存在
            ran_num = random.randint(1, len(self.process_lst))
            tem_process_lst = random.sample(self.process_lst, ran_num)
        fault_process_lst = []
        for process in tem_process_lst:
            if self.check_process(node_ip, process) is True:
                fault_process_lst.append(process)
                self.run_kill_process(node_ip, process)
        return fault_process_lst

    def check_process(self, node_ip, process):
        """检查进程是否存在"""
        ps_cmd = ('ps -ef | grep %s | grep -v grep' % process)
        rc, stdout = self.command(ps_cmd, node_ip)
        if 0 == rc:
            return True
        else:
            return False

    def run_kill_process(self, node_ip, process):
        """kill单个进程"""
        pidof_pro = ['oStor', 'oPara', 'oRole', 'oMgcd', 'oJob', 'oOss', 'oOms', 'oCnas', 'oPhx', 'oDnsmgr']
        flag = False
        for pro in pidof_pro:
            if pro in process:
                flag = True
                break
        if flag:
            ps_cmd = "pidof %s" % process
            rc, stdout = self.command(ps_cmd, node_ip, timeout=60)
            if "" == stdout:
                return
            kill_cmd = ("kill -9 %s" % stdout)
            logging.info('node %s kill %s' % (node_ip, process))
            rc, stdout = self.command(kill_cmd, node_ip, timeout=60)
            if rc != 0:
                logging.error(
                    "node: %s, cmd: %s (process:%s) failed. \nstdout: %s \n" % (node_ip, kill_cmd, process, stdout))
        else:
            ps_cmd = ("ps -ef|grep %s | grep -v grep" % process)
            rc, stdout = self.command(ps_cmd, node_ip, timeout=60)
            if "" == stdout:
                return
            logging.info(stdout)
            lines = stdout.split('\n')
            for line in lines:
                if line:
                    vars = line.split()
                    pid = vars[1]
                    kill_cmd = ("kill -9 %s" % pid)
                    logging.info('node %s kill %s' % (node_ip, process))
                    rc, stdout = self.command(kill_cmd, node_ip, timeout=60)
                    if rc != 0:
                        logging.error("Execute command: \"%s\" failed. \nstdout: %s \n" % (kill_cmd, stdout))


class NetFaultBase(FaultBase):
    """网络故障基础类"""

    def get_net_eth(self, node_id, node_ip):
        """获取一个节点所有数据网的网卡名字、ip和掩码"""
        data_ip_list = []
        result = self._get_nodes_info(node_id)
        data_ips = result['result']['nodes'][0]['data_ips']
        for data_ip in data_ips:
            ip = data_ip['ip_address']
            data_ip_list.append(ip)

        eth_list = []
        for ip in data_ip_list:
            tem_dic = {}
            cmd1 = 'ip addr | grep %s' % ip
            rc, stdout = self.command(cmd1, node_ip)
            if 0 != rc:
                raise ReliableError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd1, stdout))
            else:
                eth_name = stdout.split()[-1]
                mask_int = int(stdout.split()[1].split('/')[-1])
                mask_str = self.exchange_maskint(mask_int)
                tem_dic["eth"] = eth_name
                tem_dic["dataip"] = ip
                tem_dic["mgrip"] = node_ip
                tem_dic["mask"] = mask_str
            eth_list.append(tem_dic)
        return eth_list

    def get_client_data_ip_info(self, node_ip):
        """获取客户端数据网"""
        parastor_node_data_ips = []
        result = self._get_nodes_info()
        for data_ip in result['result']['nodes'][0]['data_ips']:
            parastor_node_data_ips.append({'ip': data_ip['ip_address'],
                                           'mask': self.exchange_maskint(data_ip['subnet_mask'])})

        client_node_data_ips = []
        cmd = 'ip add | grep "inet "'
        rc, stdout = self.command(cmd, node_ip)
        if rc != 0:
            raise ReliableError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        for line in stdout.splitlines():
            eth_name = line.strip().split()[-1]
            mask_int = int(line.strip().split()[1].split('/')[-1])
            ip = line.strip().split()[1].split('/')[0]
            mask_str = self.exchange_maskint(mask_int)
            for ip_info in parastor_node_data_ips:
                if self.check_ip_route(ip_info['ip'], ip_info['mask'], ip, mask_str):
                    client_node_data_ips.append({'eth': eth_name, 'dataip': ip, 'mgrip': node_ip, 'mask': mask_str})
                    break
        return client_node_data_ips

    def exchange_maskint(self, mask_int):
        """将int掩码转换成str掩码"""
        bin_arr = ['0'] * 32
        for i in range(mask_int):
            bin_arr[i] = '1'
        tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
        tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
        return '.'.join(tmpmask)

    def run_down_net(self, node_ip, eth_lst):
        """断网故障"""
        for eth in eth_lst:
            cmd = 'ifconfig %s down' % eth
            logging.info("node %s ifdown %s" % (node_ip, eth))
            rc, stdout = self.command(cmd, node_ip)
            if 0 != rc:
                logging.warn("node %s  ifdown %s failed!!!" % (node_ip, eth))
        return

    def run_up_net(self, node_ip, eth_lst):
        """up网络"""
        for eth in eth_lst:
            cmd = 'ifconfig %s up' % eth
            for _ in range(3):
                logging.info("node %s ifup %s" % (node_ip, eth))
                rc, stdout = self.command(cmd, node_ip)
                if rc == 0:
                    logging.info("node %s ifup %s succeed" % (node_ip, eth))
                    break
                else:
                    logging.warn("node %s ifup %s failed!!!" % (node_ip, eth))
                    time.sleep(2)
            else:
                raise ReliableError("node %s ifup %s failed!!!" % (node_ip, eth))

    @staticmethod
    def check_ip_route(ip1, mask1, ip2, mask2):
        """检查两个ip的路由是否相同"""
        ip1_lst = ip1.split('.')
        mask1_lst = mask1.split('.')
        ip2_lst = ip2.split('.')
        mask2_lst = mask2.split('.')

        route1_lst = []
        route2_lst = []
        for i in range(4):
            route1_lst.append(str(int(ip1_lst[i]) & int(mask1_lst[i])))
            route2_lst.append(str(int(ip2_lst[i]) & int(mask2_lst[i])))

        route1 = '.'.join(route1_lst)
        route2 = '.'.join(route2_lst)

        if route1 == route2:
            return True
        else:
            return False

    def get_all_nodes_eths(self):
        """
        获取所有节点的网卡信息
        return:   eth_info_lst:[[{"eth":"eth1", "mgrip":"10.2.41.101", "dataip":"20.10.11.101", "mask":"255.255.252.0"},
                                {"eth":"eth1", "mgrip":"10.2.41.102", "dataip":"20.10.11.102", "mask":"255.255.252.0"}],
                               [{"eth":"eth2", "mgrip":"10.2.41.101", "dataip":"30.10.11.101", "mask":"255.255.252.0"},
                                {"eth":"eth2", "mgrip":"10.2.41.102", "dataip":"30.10.11.102", "mask":"255.255.252.0"}]]
        """
        eth_info_lst = []
        node_ips = self.get_nodes_ip()
        for node_ip in node_ips:
            node_id = self.get_node_id_by_ip(node_ip)
            eths_lst = self.get_net_eth(node_id, node_ip)
            for eth_tem in eths_lst:
                flag = False
                if len(eth_info_lst) == 0:
                    temp_lst = [eth_tem]
                    eth_info_lst.append(temp_lst)
                else:
                    ip1 = eth_tem['dataip']
                    mask1 = eth_tem['mask']
                    for temp_lst in eth_info_lst:
                        ip2 = temp_lst[0]['dataip']
                        mask2 = temp_lst[0]['mask']
                        if self.check_ip_route(ip1, mask1, ip2, mask2):
                            temp_lst.append(eth_tem)
                            flag = True
                            break
                    if flag is False:
                        temp_lst = [eth_tem]
                        eth_info_lst.append(temp_lst)
        return eth_info_lst


class NodeFaultBase(FaultBase):
    """节点故障基础类"""

    def get_node_state(self, node_id):
        """获取节点状态"""
        stdout = self._get_nodes_info(node_id)
        return stdout['result']['nodes'][0]['state']

    def wait_node_state(self, node_id, node_ip, node_state):
        """一直等节点状态变为node_state"""
        if isinstance(node_state, str):
            node_state_lst = [node_state]
        else:
            node_state_lst = node_state
        start_time = time.time()
        while True:
            stat = self.get_node_state(node_id)
            if stat in node_state_lst:
                logging.info('node %s state in %s!!!' % (node_ip, node_state_lst))
                break
            time.sleep(20)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            logging.info('node %s state not in %s %dh:%dm:%ds' % (node_ip, node_state_lst, h, m, s))

    def get_nodepoolid_by_nodeid(self, node_id):
        """获取节点所在的节点池"""
        msg = self._get_nodes_info(node_id)
        node_pool_id = msg["result"]["nodes"][0]['node_pool_id']
        return node_pool_id

    def get_node_add_info(self, node_id):
        """获取节点添加时用到的信息"""
        msg = self._get_nodes_info(node_id)
        node_pool_id = msg["result"]["nodes"][0]['node_pool_id']
        access_zone_id = msg["result"]["nodes"][0]["access_zone_id"]
        return {'node_pool_id': node_pool_id, 'access_zone_id': access_zone_id}

    def get_node_storage_pool_rel(self, node_id):
        """获取磁盘与存储池的对应关系"""
        relation_lst = []
        stdout = self._get_disk_info(node_id)
        disks_info = stdout['result']['disks']
        for disk_info in disks_info:
            if disk_info['usage'] != 'DATA' or disk_info['storagePoolId'] == 0:
                continue
            uuid = disk_info['uuid']
            storage_pool_id = disk_info['storagePoolId']
            speed_level = disk_info['speed_level']
            lst = [uuid, storage_pool_id, speed_level]
            relation_lst.append(lst)
        return relation_lst

    def get_disk_uuid_name_rel(self, node_id):
        """
        :author:        baorb
        :date:          2019.09.09
        :description:   获取节点中所有磁盘的uuid和name的关系
        :param node_id: 节点id
        :return:        节点中所有磁盘的uuid和name的关系，类型:dic
        """
        node_ip = self.get_node_ip_by_id(node_id)
        relation_lst = []
        stdout = self._get_disk_info(node_id)
        disks_info = stdout['result']['disks']
        for disk_info in disks_info:
            if disk_info['usage'] == 'SYSTEM':
                continue
            if disk_info['usedState'] == 'IN_USE' or disk_info['usedState'] == 'FREE':
                disk_name = disk_info['devname']
                disk_usage = disk_info['usage']
                disk_uuid = disk_info['uuid']
                disk_info_dic = {'uuid': disk_uuid, 'usage': disk_usage, 'name': disk_name}
                relation_lst.append(disk_info_dic)
        cmd = "cp /home/parastor/tools/hardware/disk/disk_get_uuid /tmp"
        self.command(cmd, node_ip)
        return relation_lst

    def run_down_node_echo(self, node_ip):
        """echo b下电节点"""
        cmd = "echo b > /proc/sysrq-trigger"
        logging.info("down node %s " % (node_ip))
        self.command(cmd, node_ip, timeout=10)

    def get_ipmi_ip(self, node_ip):
        """获取节点ipmi"""
        cmd = 'ipmitool lan print'
        rc, stdout = self.command(cmd, node_ip)
        if 0 != rc:
            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
            return None
        else:
            lines_lst = stdout.strip().split('\n')
            for line in lines_lst:
                if 'IP Address  ' in line:
                    ip = line.split(':')[-1].strip()
                    return ip
            return None

    def run_down_node(self, ipmi_ip):
        """通过ipmi下电节点"""
        cmd1 = 'ipmitool -H %s -I lan -U admin -P admin power off' % ipmi_ip
        cmd2 = 'ipmitool -H %s -I lan -U ADMIN -P ADMIN power off' % ipmi_ip
        rc, stdout = self.pscli_command(cmd1)
        if 0 != rc:
            if 'Invalid user name' in stdout:
                rc, stdout = self.pscli_command(cmd2)
                if 0 != rc:
                    return False
                else:
                    return True
            else:
                return False
        else:
            return True

    def run_up_node(self, ipmi_ip):
        """通过ipmi上电节点"""
        cmd1 = 'ipmitool -H %s -I lan -U admin -P admin power on' % ipmi_ip
        cmd2 = 'ipmitool -H %s -I lan -U ADMIN -P ADMIN power on' % ipmi_ip
        rc, stdout = self.pscli_command(cmd1)
        if 0 != rc:
            if 'Invalid user name' in stdout:
                rc, stdout = self.pscli_command(cmd2)
                if 0 != rc:
                    return False
                else:
                    return True
            else:
                return False
        else:
            return True

    def offline_node(self, node_id):
        """运维下线节点"""
        cmd = "pscli --command=make_node_offline --id=%s" % node_id
        logging.info("make node %s offline begin" % node_id)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        logging.info('make node %s offline finish' % node_id)

    def online_node(self, node_id):
        """运维上线节点"""
        cmd = "pscli --command=make_nodes_online --ids=%s" % node_id
        logging.info("make node %s online begin" % node_id)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        logging.info('make node %s online finish' % node_id)

    def add_node(self, config_file):
        """添加节点"""
        cmd = 'pscli --command=add_nodes --config_file=%s' % config_file
        logging.info('add node begin')
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        logging.info('add node finish')
        cmd = "rm -rf %s" % config_file
        self.command(cmd)
        if self.local_node_flag is False:
            for node_ip in self.node_ip_lst:
                self.command(cmd, node_ip=node_ip)

    def del_node(self, node_id, auto_query=False):
        """删除节点"""
        node_ip = self.get_node_ip_by_id(node_id)
        if auto_query is False:
            cmd = 'pscli --command=remove_node --id=%s --remove_mode=AUTO_REBOOT --auto_query=false' % node_id
        else:
            cmd = 'pscli --command=remove_node --id=%s --remove_mode=AUTO_REBOOT' % node_id
        logging.info('delete node id %s' % node_id)
        rc, stdout = self.pscli_command(cmd, fault_node_ip=node_ip)
        if 0 != rc:
            logging.error("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        return rc, stdout

    def cancel_del_node(self, node_ids, fault_node_ip):
        """取消删除节点"""
        cmd = "pscli --command=cancel_remove_nodes --ids=%s" % node_ids
        logging.info('cancel delete node id %s' % node_ids)
        self.pscli_command(cmd, fault_node_ip=fault_node_ip)

    def add_node_2_nodpool(self, node_pool_id, node_id):
        """将节点添加到节点池中"""
        logging.info("add node %s to node_pool begin" % node_id)
        cmd = 'pscli --command=get_node_pools --id=%s' % node_pool_id
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        node_info = self.json_loads(stdout)
        node_id_lst = node_info['result']['node_pools'][0]['node_ids'][:]
        node_pool_name = node_info['result']['node_pools'][0]['name']

        node_id_lst.append(node_id)
        node_id_str = ','.join(map(str, node_id_lst))

        cmd = 'pscli --command=update_node_pool --node_pool_id=%s --name=%s --node_ids=%s' \
              % (node_pool_id, node_pool_name, node_id_str)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        logging.info("add node %s to node_pool finish" % node_id)

    def add_node_2_accesszone(self, access_zone_id, node_id):
        """将节点添加到访问区内"""
        if access_zone_id == 0:
            logging.info("node {} not belong to access zone".format(node_id))
            return

        logging.info("add node {} to access_zone {} begin".format(node_id, access_zone_id))
        # 获取访问区内的节点
        cmd = "pscli --command=get_access_zones --ids={}".format(access_zone_id)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        access_zone_info = self.json_loads(stdout)
        node_id_lst = access_zone_info['result']['access_zones'][0]['node_ids'][:]
        node_id_lst.append(node_id)
        node_id_str = ','.join(map(str, node_id_lst))

        # 添加节点到访问区
        cmd = "pscli --command=update_access_zone --id={} --node_ids={}".format(access_zone_id, node_id_str)
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        logging.info("add node {} to access_zone {} finish".format(node_id, access_zone_id))

    def add_node_disks_2_storagepool(self, node_id, relation_lst):
        """添加节点的磁盘到存储池中"""
        logging.info("add all disk of node %s to storage_pool begin" % node_id)
        stdout = self._get_disk_info(node_id)
        disks_info = stdout['result']['disks']
        for disk_info in disks_info:
            for rel_tem in relation_lst:
                if disk_info['uuid'] == rel_tem[0]:
                    rel_tem.append(disk_info['id'])
                    break
        # 修改磁盘的速率
        for rel_tem in relation_lst:
            disk_id = rel_tem[-1]
            disk_speed = rel_tem[2]
            cmd = "pscli --command=change_disk_speed_level --disk_ids=%s --speed_level=%s" % (disk_id, disk_speed)
            rc, stdout = self.pscli_command(cmd)
            if 0 != rc:
                raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))

        # 根据存储池id划分磁盘
        storage_pool_disk_dic = {}
        for rel_tem in relation_lst:
            storage_pool_id = str(rel_tem[1])
            disk_id = str(rel_tem[-1])
            if storage_pool_id in storage_pool_disk_dic:
                storage_pool_disk_dic[storage_pool_id].append(disk_id)
            else:
                storage_pool_disk_dic[storage_pool_id] = [disk_id]

        # 每个存储池下的磁盘一起添加
        for storage_pool_id in storage_pool_disk_dic:
            disk_ids = ','.join(storage_pool_disk_dic[storage_pool_id])
            cmd = 'pscli --command=expand_storage_pool --storage_pool_id=%s --disk_ids=%s' % (storage_pool_id, disk_ids)
            rc, stdout = self.pscli_command(cmd)
            if 0 != rc:
                raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
        logging.info("add all disk of node %s to storage_pool finish" % node_id)

    def startup(self):
        """启动系统"""
        cmd = 'pscli --command=startup'
        rc, stdout = self.pscli_command(cmd)
        if 0 != rc:
            raise PscliError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))

    def print_data_disk_cache(self, node_id, node_ip):
        """下电节点前，打印下所有数据盘的缓存情况"""
        disk_name_lst = self.get_all_disk_name(node_id, 'DATA')
        for disk_name in disk_name_lst:
            cmd = "/home/parastor/tools/devdisk_cache_mgr -g -d %s" % disk_name
            rc, stdout = self.command(cmd, node_ip, timeout=10)
            logging.info(cmd)
            logging.info(stdout)

    def check_node_exist(self, node_id, fault_node_ip=None):
        """检查节点是否存在"""
        msg = self._get_nodes_info(fault_node_ip=fault_node_ip)
        nodes_info = msg["result"]["nodes"]
        for node in nodes_info:
            if node["node_id"] == node_id:
                return True
        return False

    def add_node_parastor(self, fault_node_id, fault_node_ip, auto_query=False):
        """删除、添加节点"""
        # 生成节点的配置文件
        config_file = self.make_node_xml(fault_node_id)
        # 获取节点所在的节点池的id
        node_add_info = self.get_node_add_info(fault_node_id)
        node_pool_id = node_add_info['node_pool_id']
        access_zone_id = node_add_info['access_zone_id']
        # 获取节点中所有磁盘与存储池的对应关系
        relation_lst = self.get_node_storage_pool_rel(fault_node_id)
        # 重启后盘符可能会变化，获取uuid和usage的关系
        uuid_name_rel_lst = self.get_disk_uuid_name_rel(fault_node_id)

        # 删除节点
        rc, stdout = self.del_node(fault_node_id, auto_query=auto_query)
        if rc != 0:
            return

        # 检查节点是否删除
        start_time = time.time()
        while True:
            if self.check_node_exist(fault_node_id, fault_node_ip) is False:
                logging.info('node %s delete success!!!' % (fault_node_id))
                break
            time.sleep(20)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            logging.info('node %s delete %dh:%dm:%ds' % (fault_node_id, h, m, s))

        # 不断ping节点，知道可以ping通
        self.wait_ping_success(fault_node_ip)

        # 重启后盘符可能会变化，重新更新一遍配置文件中盘符
        self.change_node_xml(fault_node_ip, config_file, uuid_name_rel_lst)
        # 添加节点
        self.add_node(config_file)

        time.sleep(60)

        node_id_new = self.get_node_id_by_ip(fault_node_ip)

        # 添加节点到节点池中
        self.add_node_2_nodpool(node_pool_id, node_id_new)

        # 启动系统
        self.startup()

        # 将节点中的所有磁盘添加到对应的存储池
        self.add_node_disks_2_storagepool(node_id_new, relation_lst)

        # 添加节点到访问区内
        self.add_node_2_accesszone(access_zone_id, node_id_new)

    def _make_text_tag(self, dom, tagname, value):
        """生成元素节点（子节点为文本节点）"""
        tag = dom.createElement(tagname)
        text = dom.createTextNode(value)
        tag.appendChild(text)
        return tag

    def _make_element_tag(self, dom, parent_tag, child_tagname):
        """生成元素节点（子节点为元素节点）"""
        child_tag = dom.createElement(child_tagname)
        parent_tag.appendChild(child_tag)
        return child_tag

    def make_node_xml(self, node_id):
        """创建节点的xml"""
        impl = xml.dom.minidom.getDOMImplementation()
        dom = impl.createDocument(None, 'install_config', None)
        root = dom.documentElement

        # 添加系统信息
        self._xml_add_sysinfo(dom, root)

        # 添加缓存占比
        self._xml_add_cache_ratio(dom, root)

        # 添加文件系统
        self._xml_add_scenario_id(dom, root)

        # 添加ssd cache开关
        self._xml_add_eache_set(dom, root)

        # 添加缓存盘开关
        self._xml_add_mono_cache_mode(dom, root)

        # 添加机柜信息
        self._xml_add_cabinetinfo(dom, root)

        # 添加节点信息
        self._xml_add_nodeinfo(dom, root, node_id)

        # 添加网络检查
        check_network = self._make_text_tag(dom, 'check_network', '1')
        root.appendChild(check_network)

        # 写到xml文件中
        domcopy = dom.cloneNode(True)
        self.indent_xml(domcopy, domcopy.documentElement)
        now_time = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
        config_file = os.path.join("/tmp", "%s_deploy_config_sample_node1.xml" % now_time)
        with open(config_file, 'wb') as f:
            # f = file(config_file, 'wb')
            domcopy.writexml(f, encoding='utf-8')
            domcopy.unlink()
        if self.local_node_flag is False:
            for node_ip in self.node_ip_lst:
                cmd = 'scp %s root@%s:/tmp' % (config_file, node_ip)
                self.command(cmd)
        return config_file

    def _xml_add_sysinfo(self, dom, root):
        """添加系统信息"""
        sys_name, sys_id, sys_uuid = self.get_sysinfo()
        uuid = self._make_text_tag(dom, 'uuid', sys_uuid)
        sysid = self._make_text_tag(dom, 'sysid', str(sys_id))
        name = self._make_text_tag(dom, 'name', sys_name)
        package_path = self._make_text_tag(dom, 'package_path', '')
        root.appendChild(uuid)
        root.appendChild(sysid)
        root.appendChild(name)
        root.appendChild(package_path)

    def _xml_add_cache_ratio(self, dom, root):
        """向xml中添加缓存占比信息"""
        cache_ratio_value = self.get_param('MGR', 'shared_pool_cache_ratio')
        cache_ratio = self._make_text_tag(dom, 'cache_ratio', cache_ratio_value)
        root.appendChild(cache_ratio)

    def _xml_add_scenario_id(self, dom, root):
        """向xml中添加缓存文件系统类型"""
        scenario_id_value = self.get_param('MGR', 'scenario_id')
        scenario_id = self._make_text_tag(dom, 'scenario_id', scenario_id_value)
        root.appendChild(scenario_id)

    def _xml_add_eache_set(self, dom, root):
        """向xml中添加缓存SSD cache"""
        enable_cache_set_value = self.get_param('MGR', 'enable_cache_set')
        enable_cache_set = self._make_text_tag(dom, 'enable_cache_set', enable_cache_set_value)
        root.appendChild(enable_cache_set)

    def _xml_add_mono_cache_mode(self, dom, root):
        """向xml中添加缓存cache mode"""
        mono_cache_mode_value = self.get_param('MGR', 'mono_cache_mode')
        cache_scenario_value = self.get_param('MGR', 'cache_scenario')
        cache_mode_value = self.get_param('oStor', 'cache_mode')
        mono_cache_mode = self._make_text_tag(dom, 'mono_cache_mode', mono_cache_mode_value)
        cache_scenario = self._make_text_tag(dom, 'cache_scenario', cache_scenario_value)
        cache_mode = self._make_text_tag(dom, 'cache_mode', cache_mode_value)
        root.appendChild(mono_cache_mode)
        root.appendChild(cache_scenario)
        root.appendChild(cache_mode)

    def _xml_add_cabinetinfo(self, dom, root):
        """向xml中添加机柜信息"""
        cabinet_lst = self.get_cabinetinfo()
        xml_cabinets = self._make_element_tag(dom, root, 'cabinets')
        for cabinet in cabinet_lst:
            name = self._make_text_tag(dom, 'name', cabinet[0])
            height = self._make_text_tag(dom, 'height', str(cabinet[1]))
            xml_cabinet = self._make_element_tag(dom, xml_cabinets, 'cabinet')
            xml_cabinet.appendChild(name)
            xml_cabinet.appendChild(height)

    def _xml_add_nodeinfo(self, dom, root, node_id):
        """向xml中添加节点信息"""
        nodes = self._make_element_tag(dom, root, 'nodes')
        node = self._make_element_tag(dom, nodes, 'node')
        node_json = self._get_nodes_info(node_id)
        node_info = node_json['result']['nodes'][0]

        # 添加节点名
        hostname_value = node_info['node_name']
        hostname = self._make_text_tag(dom, 'hostname', hostname_value)
        node.appendChild(hostname)

        # 添加节点管理ip
        self._xml_add_nodeip(dom, node, node_info, 'ctl_ips')

        # 添加节点数据ip
        self._xml_add_nodeip(dom, node, node_info, 'data_ips')

        # 添加haip
        self._make_element_tag(dom, node, 'ha_ips')

        # 添加节点机柜信息
        cabinet = self._make_text_tag(dom, 'cabinet', node_info['cabinet_name'])
        position = self._make_text_tag(dom, 'position', str(node_info['position']))
        node_model = self._make_text_tag(dom, 'node_model', node_info['model'])
        node.appendChild(cabinet)
        node.appendChild(position)
        node.appendChild(node_model)

        # 添加ipmi信息
        self._xml_add_ipmiinfo(dom, node, node_info)

        # 添加nvdevs信息
        self._xml_add_nodevs(dom, node, node_info)

        # 添加zk信息
        self._xml_add_zkinfo(dom, node, node_info)

        # 添加service信息
        self._xml_add_service(dom, node, node_info)

        # 添加硬盘信息
        self._xml_add_diskinfo(dom, node, node_info)

    def _xml_add_nodeip(self, dom, node, node_info, type):
        """向xml中添加节点ip信息"""
        ctl_ips = self._make_element_tag(dom, node, type)
        ips_info = node_info[type]
        for ip_info in ips_info:
            ip = self._make_text_tag(dom, 'ip', ip_info['ip_address'])
            ctl_ips.appendChild(ip)

    def _xml_add_ipmiinfo(self, dom, node, node_info):
        """向xml中添加节点ipmi信息"""
        ipmi = self._make_element_tag(dom, node, 'ipmi')
        ip = self._make_text_tag(dom, 'ip', node_info['ipmi']['ip'])
        username = self._make_text_tag(dom, 'username', node_info['ipmi']['username'])
        password = self._make_text_tag(dom, 'password', node_info['ipmi']['password'])
        ipmi.appendChild(ip)
        ipmi.appendChild(username)
        ipmi.appendChild(password)

    def _xml_add_nodevs(self, dom, node, node_info):
        """向xml中添加节点nodevs信息"""
        nvdevs = self._make_element_tag(dom, node, 'nvdevs')
        for device_info in node_info['nvdevs']:
            device = self._make_element_tag(dom, nvdevs, 'device')
            sn = self._make_text_tag(dom, 'sn', device_info['sn'])
            uuid = self._make_text_tag(dom, 'uuid', device_info['uuid'])
            device.appendChild(sn)
            device.appendChild(uuid)

    def _xml_add_zkinfo(self, dom, node, node_info):
        """向xml中获取zk信息"""
        zookeeper = self._make_element_tag(dom, node, 'zookeeper')
        zk_id = node_info['zk_id']
        id = self._make_text_tag(dom, 'id', str(zk_id))
        zookeeper.appendChild(id)

    def _xml_add_service(self, dom, node, node_info):
        """向xml中添加节点服务信息"""
        services = self._make_element_tag(dom, node, 'services')
        services_info = node_info['services']
        for service_info in services_info:
            service = self._make_element_tag(dom, services, 'service')
            type = self._make_text_tag(dom, 'type', service_info['service_type'])
            service.appendChild(type)

    def _xml_add_diskinfo(self, dom, node, node_info):
        """向xml中添加节点硬盘信息"""
        disks = self._make_element_tag(dom, node, 'disks')
        data_disks_info = node_info['data_disks']
        share_disks_info = node_info['shared_disks']
        cache_disks_info = node_info['cache_disks']
        disks_info = data_disks_info + share_disks_info + cache_disks_info
        for disk_info in disks_info:
            if disk_info['usedState'] == 'IN_USE' or disk_info['usedState'] == 'FREE':
                disk = self._make_element_tag(dom, disks, 'disk')
                dev_name = self._make_text_tag(dom, 'dev_name', disk_info['devname'])
                usage = self._make_text_tag(dom, 'usage', disk_info['usage'])
                state = self._make_text_tag(dom, 'state', 'FREE')
                disk.appendChild(dev_name)
                disk.appendChild(usage)
                disk.appendChild(state)

    def indent_xml(self, dom, node, indent=0):
        """将xml格式化"""
        children = node.childNodes[:]
        # Main node doesn't need to be indented
        if indent:
            text = dom.createTextNode('\n' + '    ' * indent)
            node.parentNode.insertBefore(text, node)
        if children:
            # Append newline after last child, except for text nodes
            if children[-1].nodeType == node.ELEMENT_NODE:
                text = dom.createTextNode('\n' + '    ' * indent)
                node.appendChild(text)
            # Indent children which are elements
            for n in children:
                if n.nodeType == node.ELEMENT_NODE:
                    self.indent_xml(dom, n, indent + 1)

    def change_node_xml(self, fault_node_ip, config_file, uuid_name_rel_lst):
        """刷新节点配置文件"""

        def _get_disk_uuid_by_name(uuid_name_rel_lst, disk_name):
            for disk_dic in uuid_name_rel_lst:
                if disk_dic['name'] == disk_name:
                    return disk_dic['uuid']
            return None

        tree = Et.parse(config_file)
        root = tree.getroot()
        nodes_xml = root.find("nodes")
        node_xml = nodes_xml.find("node")
        disks_xml = node_xml.find("disks")
        cmd = "lsscsi | grep dev"
        rc, stdout = self.command(cmd, fault_node_ip)
        now_rel = {}
        line_lst = stdout.splitlines()
        for line in line_lst:
            disk_now_name = line.strip().split()[-1]
            cmd = "/tmp/disk_get_uuid -p %s" % disk_now_name
            rc, stdout = self.command(cmd, fault_node_ip)
            if rc != 0:
                cmd = "/tmp/disk_get_uuid %s" % disk_now_name
                rc, stdout = self.command(cmd, fault_node_ip)
            disk_uuid = stdout.strip()
            disk_uuid_lst = re.findall(r'\w{8}-\w{4}-\w{4}-\w{4}-\w{12}', disk_uuid)
            if not disk_uuid_lst:
                logging.warn("get disk %s uuid failed" % disk_now_name)
                continue
            disk_uuid = disk_uuid_lst[0]
            now_rel[disk_uuid] = disk_now_name
        logging.info("new disk uuid:\n %s" % str(now_rel))
        logging.info("disk uuid name relation_lst:\n %s" % str(uuid_name_rel_lst))

        for disk_xml in disks_xml.findall("disk"):
            disk_name_xml = disk_xml.find("dev_name").text
            disk_uuid = _get_disk_uuid_by_name(uuid_name_rel_lst, disk_name_xml)
            disk_now_name = now_rel[disk_uuid]
            if disk_now_name != disk_name_xml:
                disk_xml.find("dev_name").text = disk_now_name
        tree.write(config_file)
        if self.local_node_flag is False:
            for node_ip in self.node_ip_lst:
                cmd = 'scp %s root@%s:/tmp' % (config_file, node_ip)
                self.command(cmd)


class NetFaultNoWait(NetFaultBase):
    """down 所有数据网 -> up 所有数据网"""

    def __str__(self):
        return "[net fault: down net -> up net]"

    def main(self):
        """故障主函数"""
        # 获取集群所有节点的管理ip
        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        # 修改节点isolate参数
        rc, stdout = self.update_param_default('MGR', 'node_isolate_timeout')
        if 0 != rc:
            logging.warn("update param failed!!!")

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break

        # 检查故障节点ip是否是集群内ip，给parabuffer功能做的
        if self._check_node_in_parastor(fault_node_ip):
            # 集群内部节点检查元数据
            fault_node_id = self.get_node_id_by_ip(fault_node_ip)
            self._keep_check_metanode(fault_node_id, fault_node_ip)
            eth_info_lst = self.get_net_eth(fault_node_id, fault_node_ip)
        else:
            # 集群外节点检查oBuf
            fault_node_id = self.get_client_id_by_ip(fault_node_ip)
            self._keep_check_obuf(fault_node_id, fault_node_ip)
            eth_info_lst = self.get_client_data_ip_info(fault_node_ip)

        eth_lst = []
        for tem in eth_info_lst:
            eth_lst.append(tem['eth'])

        if self.mgr_data_ip_same is True:
            fault_node_free_ip = self.free_ip_dir[fault_node_ip]
        else:
            fault_node_free_ip = fault_node_ip

        # down所有数据网
        self.run_down_net(fault_node_free_ip, eth_lst)

        self.wait_time('down_net')
        # time.sleep(20)

        # 不断ping节点，知道可以ping通
        self.wait_ping_success(fault_node_free_ip)

        # up所有数据网
        self.run_up_net(fault_node_free_ip, eth_lst)
        time.sleep(30)


class NetFaultWaitZombie(NetFaultBase, NodeFaultBase):
    """down net -> node zombie -> up net -> del node -> add node"""

    def __str__(self):
        return "[net fault: down net -> node zombie -> up net -> del node -> add node]"

    def main(self):
        # 修改节点isolate参数
        rc, stdout = self.update_param('MGR', 'node_isolate_timeout', 300000)
        if 0 != rc:
            logging.warn("update param failed!!!")

        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break

        # 检查是否有节点不在集群内, 给pb做的功能
        if not self._check_node_in_parastor(fault_node_ip):
            logging.warn("node {} not in parastor".format(fault_node_ip))
            return

        fault_node_id = self.get_node_id_by_ip(fault_node_ip)
        self._keep_check_metanode(fault_node_id, fault_node_ip)

        eth_info_lst = self.get_net_eth(fault_node_id, fault_node_ip)
        eth_lst = []
        for tem in eth_info_lst:
            eth_lst.append(tem['eth'])

        if self.mgr_data_ip_same is True:
            fault_node_free_ip = self.free_ip_dir[fault_node_ip]
        else:
            fault_node_free_ip = fault_node_ip

        # down所有数据网
        self.run_down_net(fault_node_free_ip, eth_lst)

        logging.info("waiting 330s")
        time.sleep(330)

        # 不断ping节点，知道可以ping通
        self.wait_ping_success(fault_node_free_ip)

        # 检查节点状态是不是ZOMBIE
        self.wait_node_state(fault_node_id, fault_node_ip, 'NODE_STATE_ZOMBIE')

        # 检查坏对象是否修复
        self.check_badobj(fault_ip=fault_node_ip)

        # up所有数据网
        self.run_up_net(fault_node_free_ip, eth_lst)

        time.sleep(30)

        # 修改回超时时间的参数
        rc, stdout = self.update_param_default('MGR', 'node_isolate_timeout')
        if 0 != rc:
            logging.warn("update param failed!!!")

        self.add_node_parastor(fault_node_id, fault_node_ip)


class NetDownWaitRebuild(NetFaultBase, NodeFaultBase):
    """down net -> rebuild -> up net"""

    def __str__(self):
        return "[net down: down net -> rebuild -> up net]"

    def main(self):
        """故障主函数"""
        # 修改节点isolate参数
        rc, stdout = self.update_param('MGR', 'node_isolate_timeout', 300000)
        if 0 != rc:
            logging.warn("update param failed!!!")

        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break

        # 检查是否有节点不在集群内, 给pb做的功能
        if not self._check_node_in_parastor(fault_node_ip):
            logging.warn("node {} not in parastor".format(fault_node_ip))
            return

        fault_node_id = self.get_node_id_by_ip(fault_node_ip)
        self._keep_check_metanode(fault_node_id, fault_node_ip)

        eth_info_lst = self.get_net_eth(fault_node_id, fault_node_ip)
        eth_lst = []
        for tem in eth_info_lst:
            eth_lst.append(tem['eth'])

        if self.mgr_data_ip_same is True:
            fault_node_free_ip = self.free_ip_dir[fault_node_ip]
        else:
            fault_node_free_ip = fault_node_ip

        # down所有数据网
        self.run_down_net(fault_node_free_ip, eth_lst)

        logging.info("waiting 330s")
        time.sleep(330)

        # 检查重建任务是否存在
        for i in range(12):
            if self.check_rebuild_job(fault_node_ip):
                logging.info("rebuild job exist")
                break
            time.sleep(10)

        self.wait_time('down_net')

        # up所有数据网
        self.run_up_net(fault_node_free_ip, eth_lst)

        time.sleep(60)

        # 检查坏对象是否修复
        self.check_badobj()

        # 修改回超时时间的参数
        rc, stdout = self.update_param_default('MGR', 'node_isolate_timeout')
        if 0 != rc:
            logging.warn("update param failed!!!")

        # 检查节点状态
        self.wait_node_state(fault_node_id, fault_node_ip, ['NODE_STATE_HEALTHY', 'NODE_STATE_ZOMBIE'])

        if self.get_node_state(fault_node_id) == 'NODE_STATE_ZOMBIE':
            self.add_node_parastor(fault_node_id, fault_node_ip)


class NetPartDown(NetFaultBase):
    """down 部分数据网 -> up 部分数据网"""

    def __str__(self):
        return "[down part net -> up part net]"

    def main(self):
        """故障主函数"""
        # 获取所有节点的数据网，放到字典中，键是管理ip，值是数据网网卡名（列表）
        nodes_eths_info_lst = self.get_all_nodes_eths()
        log_str = 'all nodes data eth: ', nodes_eths_info_lst
        logging.info(log_str)

        # 随机获取每个点上的部分数据网口，只有数据网大于1才能故障
        if len(nodes_eths_info_lst) <= 1:
            return
        ran_eths_num = random.randint(1, len(nodes_eths_info_lst) - 1)
        fault_node_eths_lst = random.sample(nodes_eths_info_lst, ran_eths_num)

        log_str = 'all nodes fault data eth: ', fault_node_eths_lst
        logging.info(log_str)

        # down每个节点的数据网
        for eths_info_lst in fault_node_eths_lst:
            for node_eth_info in eths_info_lst:
                if self.mgr_data_ip_same is True:
                    fault_node_free_ip = self.free_ip_dir[node_eth_info['mgrip']]
                else:
                    fault_node_free_ip = node_eth_info['mgrip']

                self.run_down_net(fault_node_free_ip, [node_eth_info['eth']])

        self.wait_time('down_net')

        # up每个节点的数据网
        for eths_info_lst in fault_node_eths_lst:
            for node_eth_info in eths_info_lst:
                if self.mgr_data_ip_same is True:
                    fault_node_free_ip = self.free_ip_dir[node_eth_info['mgrip']]
                else:
                    fault_node_free_ip = node_eth_info['mgrip']

                self.run_up_net(fault_node_free_ip, [node_eth_info['eth']])

        logging.info('wait 30s')
        time.sleep(30)


class NodeDel(NodeFaultBase):
    """del node -> add node"""

    def __str__(self):
        return "[node fault: del node -> add node]"

    def main(self):
        """故障主函数"""
        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break

        # 检查是否有节点不在集群内, 给pb做的功能
        if not self._check_node_in_parastor(fault_node_ip):
            logging.warn("node {} not in parastor".format(fault_node_ip))
            return

        fault_node_id = self.get_node_id_by_ip(fault_node_ip)
        self._keep_check_metanode(fault_node_id, fault_node_ip)

        self.add_node_parastor(fault_node_id, fault_node_ip, auto_query=True)


class NodeDelCancel(NodeFaultBase):
    """del node -> cancel del node"""

    def __str__(self):
        return "[node fault: del node -> cancel del node]"

    def main(self):
        """故障主函数"""
        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        if self.local_node_ip in fault_node_ip_lst:
            fault_node_ip_lst.remove(self.local_node_ip)

        for fault_node_ip in fault_node_ip_lst:
            # 检查是否有节点不在集群内, 给pb做的功能
            if not self._check_node_in_parastor(fault_node_ip):
                logging.warn("node {} not in parastor".format(fault_node_ip))
                return

            fault_node_id = self.get_node_id_by_ip(fault_node_ip)
            self._del_node_cancel(fault_node_id, fault_node_ip)

    def _del_node_cancel(self, fault_node_id, fault_node_ip):
        """删除节点并取消"""
        self._keep_check_metanode(fault_node_id, fault_node_ip)

        # 生成节点的配置文件
        config_file = self.make_node_xml(fault_node_id)
        # 获取节点所在的节点池的id
        node_add_info = self.get_node_add_info(fault_node_id)
        node_pool_id = node_add_info['node_pool_id']
        access_zone_id = node_add_info['access_zone_id']
        # 获取节点中所有磁盘与存储池的对应关系
        relation_lst = self.get_node_storage_pool_rel(fault_node_id)
        # 重启后盘符可能会变化，获取uuid和usage的关系
        uuid_name_rel_lst = self.get_disk_uuid_name_rel(fault_node_id)

        # 删除节点
        rc, stdout = self.del_node(fault_node_id, auto_query=True)
        if rc != 0:
            return

        # 等待一段时间
        wait_time = random.randint(60, 600)
        logging.info("wait %ss" % wait_time)
        time.sleep(wait_time)

        # 取消删除节点
        self.cancel_del_node(fault_node_id, fault_node_ip)

        # 检查节点是否删除
        if self.check_node_exist(fault_node_id, fault_node_ip) is False:
            pass

        # 检查节点是否删除或者是healthy
        node_del_flag = False
        start_time = time.time()
        while True:
            if self.check_node_exist(fault_node_id, fault_node_ip) is False:
                logging.info('node %s delete!!!' % (fault_node_id))
                node_del_flag = True
                break
            if self.get_node_state(fault_node_id) == 'NODE_STATE_HEALTHY':
                logging.info('node %s state is NODE_STATE_HEALTHY!!!' % (fault_node_id))
                break
            time.sleep(20)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            logging.info('node %s delete %dh:%dm:%ds' % (fault_node_id, h, m, s))

        if node_del_flag:
            # 不断ping节点，知道可以ping通
            self.wait_ping_success(fault_node_ip)

            # 重启后盘符可能会变化，重新更新一遍配置文件中盘符
            self.change_node_xml(fault_node_ip, config_file, uuid_name_rel_lst)
            # 添加节点
            self.add_node(config_file)

            time.sleep(60)

            node_id_new = self.get_node_id_by_ip(fault_node_ip)

            # 添加节点到节点池中
            self.add_node_2_nodpool(node_pool_id, node_id_new)

            # 启动系统
            self.startup()

            # 将节点中的所有磁盘添加到对应的存储池
            self.add_node_disks_2_storagepool(node_id_new, relation_lst)

            # 添加节点到访问区内
            self.add_node_2_accesszone(access_zone_id, node_id_new)


class NodeDelDownNet(NodeFaultBase, NetFaultBase):
    """del node -> down net -> add node"""

    def __str__(self):
        return "[node fault: del node -> down net -> add node]"

    def main(self):
        """故障主函数"""
        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break
        fault_node_id = self.get_node_id_by_ip(fault_node_ip)
        self._keep_check_metanode(fault_node_id, fault_node_ip)

        # 获取节点网卡信息
        eth_info_lst = self.get_net_eth(fault_node_id, fault_node_ip)
        eth_lst = []
        for tem in eth_info_lst:
            eth_lst.append(tem['eth'])

        if self.mgr_data_ip_same is True:
            fault_node_free_ip = self.free_ip_dir[fault_node_ip]
        else:
            fault_node_free_ip = fault_node_ip

        # 生成节点的配置文件
        config_file = self.make_node_xml(fault_node_id)
        # 获取节点所在的节点池的id
        node_add_info = self.get_node_add_info(fault_node_id)
        node_pool_id = node_add_info['node_pool_id']
        access_zone_id = node_add_info['access_zone_id']
        # 获取节点中所有磁盘与存储池的对应关系
        relation_lst = self.get_node_storage_pool_rel(fault_node_id)
        # 重启后盘符可能会变化，获取uuid和usage的关系
        uuid_name_rel_lst = self.get_disk_uuid_name_rel(fault_node_id)

        # 删除节点
        start_time = time.time()
        p1 = Process(target=self.del_node, kwargs={'node_id': fault_node_id, 'auto_query': True})
        p1.start()
        # 等15s，如果删除节点结束，说明删除失败
        time.sleep(15)
        if p1.exitcode is not None:
            logging.warn("node %s del failed" % fault_node_id)
            return

        # 再等一段时间，断节点数据网
        wait_time = random.randint(30, 600)
        logging.info("wait %ss" % wait_time)
        time.sleep(wait_time)

        # down所有数据网
        self.run_down_net(fault_node_free_ip, eth_lst)

        # 检查节点是否删除
        while True:
            if self.check_node_exist(fault_node_id, fault_node_ip) is False:
                logging.info('node %s delete success!!!' % (fault_node_id))
                break
            time.sleep(20)
            exist_time = int(time.time() - start_time)
            m, s = divmod(exist_time, 60)
            h, m = divmod(m, 60)
            logging.info('node %s delete %dh:%dm:%ds' % (fault_node_id, h, m, s))

        # 不断ping节点，知道可以ping通
        self.wait_ping_success(fault_node_ip)

        # up所有数据网
        self.run_up_net(fault_node_free_ip, eth_lst)
        time.sleep(30)

        # 重启后盘符可能会变化，重新更新一遍配置文件中盘符
        self.change_node_xml(fault_node_ip, config_file, uuid_name_rel_lst)
        # 添加节点
        self.add_node(config_file)

        time.sleep(60)

        node_id_new = self.get_node_id_by_ip(fault_node_ip)

        # 添加节点到节点池中
        self.add_node_2_nodpool(node_pool_id, node_id_new)

        # 启动系统
        self.startup()

        # 将节点中的所有磁盘添加到对应的存储池
        self.add_node_disks_2_storagepool(node_id_new, relation_lst)

        # 添加节点到访问区内
        self.add_node_2_accesszone(access_zone_id, node_id_new)


class NodeOffline(NodeFaultBase):
    """node offline -> node online"""

    def __str__(self):
        return "[node fault: node offline -> node online]"

    def main(self):
        """故障主函数"""
        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down net!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break

        # 检查是否有节点不在集群内, 给pb做的功能
        if not self._check_node_in_parastor(fault_node_ip):
            logging.warn("node {} not in parastor".format(fault_node_ip))
            return

        fault_node_id = self.get_node_id_by_ip(fault_node_ip)
        self._keep_check_metanode(fault_node_id, fault_node_ip)

        # 运维下线节点
        self.offline_node(fault_node_id)

        self.wait_time('down_node')

        # 运维上线节点
        self.online_node(fault_node_id)


class NodeFaultNoWait(NodeFaultBase):
    """节点下电重启(不等数据修复完成)"""

    def __str__(self):
        return "[node fault: down_node_no_wait]"

    def main(self):
        """故障主函数"""
        # 获取集群所有节点的管理ip
        if len(self.node_ip_lst) == 1 and self.local_node_ip in self.node_ip_lst:
            raise ReliableError("one node system can't down!!!")

        if len(self.fault_node_ip_lst) == 0:
            fault_node_ip_lst = self.node_ip_lst[:]
        else:
            fault_node_ip_lst = self.fault_node_ip_lst[:]

        while True:
            fault_node_ip = random.choice(fault_node_ip_lst)
            if fault_node_ip != self.local_node_ip:
                break

        # 检查故障节点ip是否是集群内ip，给parabuffer功能做的
        if self._check_node_in_parastor(fault_node_ip):
            # 集群内部节点检查元数据
            fault_node_id = self.get_node_id_by_ip(fault_node_ip)
            self._keep_check_metanode(fault_node_id, fault_node_ip)
        else:
            # 集群外节点检查oBuf
            fault_node_id = self.get_client_id_by_ip(fault_node_ip)
            self._keep_check_obuf(fault_node_id, fault_node_ip)

        # 节点下电重启
        self.run_down_node_echo(fault_node_ip)
        time.sleep(2)

        # 不断ping节点，直到可以ping通
        self.wait_ping_success(fault_node_ip)


class Main(FaultBase):
    """主流程类"""

    def arg_analysis(self):
        """解析参数"""
        usage = "usage: %prog [options]"
        version = "%prog {}".format(script_version)
        parser = OptionParser(usage=usage, version=version)
        parser.add_option("-o", "--operation",
                          action="append",
                          type="int",
                          dest="operation",
                          help="Required:True   Type:int                                     "
                               "fault operation                                              "
                               "0 : all                                                      "
                               "1 : disk (pullout -> insert)                                 "
                               "2 : disk (pullout -> zombie -> insert -> del -> add)         "
                               "3 : disk (pullout -> rebuild -> insert -> del -> add)        "
                               "4 : disk (del -> add)                                        "
                               "5 : disk (del -> pullout -> insert -> add)                   "
                               "6 : disk (del -> cancel)                                     "
                               "7 : disk (pullout -> insert -> change uuid -> add new        "
                               " -> del old)                                                 "
                               "8 : process (kill)                                           "
                               "9 : net (down -> up )                                        "
                               "10: net (down -> node zombie -> up -> del node -> add        "
                               " node)                                                       "
                               "11: net (down -> rebuild -> up)                              "
                               "12: net (down part net -> up part net)                       "
                               "13: node (del -> add)                                        "
                               "14: node (del -> cancel)                                     "
                               "15: node (offline -> online)                                 "
                               "16: node (down_node_no_wait)                                 "
                          )

        parser.add_option("-n", "--numbers",
                          type="int",
                          dest="num",
                          default=10000,
                          help="Required:False   Type:int  "
                               "Help:fault execution nums, default: %default, range is 1-10000")

        parser.add_option("-d", "--disk",
                          type="string",
                          dest="disktype",
                          metavar="TYPE",
                          default="data",
                          help="Required:False   Type:string  Help:fault disk type, e.g. all, data, meta, cache. "
                               "default: %default  "
                               "this parameter work when fault disk")

        parser.add_option("-f", "--disknum",
                          type="int",
                          dest="faultdisknum",
                          default=1,
                          help="Required:False   Type:int  Help:fault disk nums, default: %default, range is 1-10")

        parser.add_option("-i", "--ip",
                          type="str",
                          dest="mgrip",
                          default=None,
                          help="Required:False   Type:str   Help:MGR node IP")

        parser.add_option("-b", "--faultnode",
                          type="string",
                          dest="faultnode",
                          help='Required:False   Type:string  '
                               'Help:fault node, e.g. "10.2.40.1" or "10.2.40.1,10.2.40.2"')

        parser.add_option("-p", "--process",
                          type="string",
                          dest="process",
                          help='Required:False   Type:string  Help:-o 8 fault process, e.g. "oMgcd,oJmgs,oStor"')

        # xutengda 2019/06/25
        parser.add_option("-l", "--log_path",
                          type="string",
                          dest="log_path",
                          help='Required:False   Type:string  Help:log path. e.g. /home/log')

        options, args = parser.parse_args()

        # 检查-o参数
        if options.operation is None:
            parser.error("please input -o or --operation")
        operation_lst = list(set(options.operation))
        operation_lst.sort()

        if len(operation_lst) > 16:
            parser.error('the range of -o or --operation is 0-16')
        for tem in operation_lst:
            if tem not in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
                parser.error('the range of -o or --operation is 0-16')

        # 检查-n参数
        if options.num < 1 or options.num > 10000:
            parser.error("the range of -n or --num is 1-10000")

        # 检查-d参数
        if options.disktype not in ['data', 'meta', 'cache', 'all']:
            parser.error('the -d or --disk just can be "all", "data", "meta", "cache"')

        # 检查-f参数
        if options.faultdisknum < 1 or options.faultdisknum > 10:
            parser.error("the range of -f or --disknum is 1-10")

        # 检查-i参数
        if options.mgrip is not None:
            # 检查ip的正确性
            if self._check_ip(options.mgrip) is False:
                parser.error("-i the ip format is incorrent!!!")
            mgr_ip = options.mgrip
            FaultBase.local_node_flag = False
            FaultBase.node_ip_lst = self.get_nodes_ips_by_ip(mgr_ip)
            FaultBase.node_data_ip_lst = self.get_nodes_data_ip_by_ip(mgr_ip)

            # 如果本节点在集群内则报错
            def _check_localnode_in_ps(node_ip_lst):
                cmd = 'ip addr | grep "inet "'
                rc, stdout = self.command(cmd)
                if 0 != rc:
                    raise ReliableError("Execute command: \"%s\" failed. \nstdout: %s" % (cmd, stdout))
                lines = stdout.strip().split('\n')
                for line in lines:
                    ip = line.split()[1].split('/')[0]
                    if ip in node_ip_lst:
                        return True
                return False

            if _check_localnode_in_ps(self.node_ip_lst):
                parser.error("If the local node in the parastor, please don't enter -i or --ip")

            FaultBase.local_node_ip = None
        else:
            # 检查本节点是否是集群节点
            cmd = 'ls /home/parastor/bin'
            rc, stdout = self.command(cmd)
            if rc != 0:
                parser.error('the local node not in parastor, please input -i or --ip')
            FaultBase.local_node_flag = True
            FaultBase.local_node_ip = self.get_local_node_ip()
            FaultBase.node_ip_lst = self.get_nodes_ip()
            FaultBase.node_data_ip_lst = self.get_nodes_data_ip_by_ip(self.node_ip_lst[0])

        # 检查-b参数
        if options.faultnode is not None:
            FaultBase.fault_node_ip_lst = options.faultnode.split(',')
            for node_ip in self.fault_node_ip_lst:
                # if node_ip not in self.node_ip_lst and node_ip not in self.node_data_ip_lst:
                #     parser.error('-b %s is not in parastor' % node_ip)
                fault_lst = [0, 9, 10, 11, 13, 14, 15, 16]
                if node_ip == self.local_node_ip and len(set(fault_lst).intersection(set(operation_lst))) != 0:
                    parser.error("There is net or node fault, -b %s can't be local ip" % node_ip)
        else:
            FaultBase.fault_node_ip_lst = []

        # 检查-p参数
        if options.process is not None:
            FaultBase.fault_pro_lst = options.process.split(',')
        else:
            FaultBase.fault_pro_lst = []

        # 检查-l参数  # xutengda 2019/06/25
        if options.log_path is None:
            self.log_dir = ""
        else:
            dest_dir = options.log_path.strip()
            # 检查log存放目录是否存在
            if dest_dir == '' or os.path.exists(dest_dir) is False:
                parser.error('-l is not right, e.g. "/home/log"')
            self.log_dir = dest_dir

        # 参数内容设置到全局变量中
        self.operation_lst = operation_lst
        self.fault_numbers = options.num
        FaultBase.fault_disk_type = options.disktype
        FaultBase.fault_disk_num = options.faultdisknum

        # 如果管理网和数据网复用的情况，需要配置FREE_IP_DIR
        FaultBase.mgr_data_ip_same = False
        # if set(self.node_ip_lst).issubset(set(self.node_data_ip_lst)):
        #     FaultBase.mgr_data_ip_same = True
        #     if sorted(self.node_ip_lst) != sorted(self.free_ip_dir.keys()):
        #         parser.error('管理网和数据网复用的环境，需要手动填写FREE_IP_DIR，'
        #                      '字典的每一项的键是节点的管理ip，值是这个节点数据网没有用到的ip')
        return

    @staticmethod
    def _check_ip(ip):
        pattern = re.compile(r'((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        match = pattern.match(ip)
        if match:
            return True
        else:
            return False

    def log_init(self):
        """初始化日志"""
        if self.log_dir == "":
            file_path = os.path.split(os.path.realpath(__file__))[0]
        else:
            file_path = self.log_dir
        file_name = os.path.basename(__file__)
        file_name = file_name[:-3]
        now_time = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
        file_name = now_time + '_' + file_name + '.log'
        file_name = os.path.join(file_path, file_name)
        print file_name
        logging.basicConfig(level=logging.DEBUG,
                            format='[%(levelname)s][%(asctime)s]%(lineno)d:  %(message)s',
                            datefmt='%y-%m-%d %H:%M:%S',
                            filename=file_name,
                            filemode='a')

        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(levelname)s][%(asctime)s]   %(message)s', '%y-%m-%d %H:%M:%S')
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)

    def get_fault(self):
        """获取要做的故障类型"""
        all_fault_dic = {1: DiskDownNoWait(),
                         2: DiskDownWaitZombie(),
                         3: DiskDownWaitRebuild(),
                         4: DiskDel(),
                         5: DiskDelDownDisk(),
                         6: DiskDelCancel(),
                         7: DiskDownChangeUuid(),
                         8: ProcessKill(),
                         9: NetFaultNoWait(),
                         10: NetFaultWaitZombie(),
                         11: NetDownWaitRebuild(),
                         12: NetPartDown(),
                         13: NodeDel(),
                         14: NodeDelCancel(),
                         15: NodeOffline(),
                         16: NodeFaultNoWait()}

        fault_info_lst = []
        logging.info("These faults will be done:")
        if 0 in self.operation_lst:
            for key in all_fault_dic:
                fault_dic = {'key': key, 'func': all_fault_dic[key], 'num': 0}
                fault_info_lst.append(fault_dic)
                logging.info("%s %s" % (key, all_fault_dic[key]))
        else:
            for key in self.operation_lst:
                fault_dic = {'key': key, 'func': all_fault_dic[key], 'num': 0}
                fault_info_lst.append(fault_dic)
                logging.info("%s %s" % (key, all_fault_dic[key]))
        logging.info('')
        return fault_info_lst

    def run_fault(self):
        """执行故障函数"""
        logging.info(" ".join(sys.argv))
        # 检查环境
        self.check_env()

        logging.info("*********** the fault operation beginning ***********")
        # 获取要做的故障类型
        fault_info_lst = self.get_fault()

        # 检查环境是否恢复
        self.check_system_recover(waitflag=False)

        logging.info('*************************************************************************')
        run_times = 0

        try:
            for i in range(self.fault_numbers):
                for func_info_dic in random.sample(fault_info_lst, len(fault_info_lst)):
                    obj_fault = func_info_dic['func']

                    FaultBase.node_ip_lst = self.get_nodes_ip()
                    logging.info('node_ip_lst is %s' % self.node_ip_lst)

                    # 获取所有数据网ip
                    FaultBase.node_data_ip_lst = self.get_nodes_data_ip()
                    logging.info('node_data_ip_lst is %s' % self.node_data_ip_lst)

                    run_times += 1
                    self._set_fault_num(fault_info_lst, func_info_dic)

                    logging.info(
                        '***************************** the %d fault begin ******************************' % run_times)
                    logging.info("***************** %s %s begin, num:%s *****************"
                                 % (func_info_dic['key'], obj_fault, func_info_dic['num']))

                    # 执行故障
                    obj_fault.main()

                    # 检查环境是否恢复
                    self.check_system_recover()

                    print_str = '\n'
                    for func_info in fault_info_lst:
                        if func_info == fault_info_lst[-1]:
                            print_str += ("********** run nums: %s  (%s: %s)  **********"
                                          % (func_info['num'], func_info['key'], func_info['func']))
                        else:
                            print_str += ("********** run nums: %s  (%s: %s) **********\n"
                                          % (func_info['num'], func_info['key'], func_info['func']))
                    logging.info(print_str)
                    logging.info('***************************** the %d fault finish ******************************\n'
                                 % run_times)
        except Exception:
            logging.error("", exc_info=1)
            # traceback.print_exc()
            print_str = "********** all fault run nums: %s **********\n" % run_times
            for func_info_dic in fault_info_lst:
                print_str += ("********** run nums: %s  (%s: %s) **********\n"
                              % (func_info_dic['num'], func_info_dic['key'], func_info_dic['func']))
            logging.info(print_str)
            exit(1)

    def _set_fault_num(self, fault_info_lst, func_info_dic):
        for fault_info in fault_info_lst:
            if func_info_dic == fault_info:
                fault_info['num'] += 1


def main():
    obj_main = Main()
    # 参数解析
    obj_main.arg_analysis()
    # 初始化日志文件
    obj_main.log_init()
    # 执行故障
    obj_main.run_fault()


if __name__ == '__main__':
    main()
