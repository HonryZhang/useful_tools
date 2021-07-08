from platform import uname
import threading,subprocess,time

def multi_process_account(func_name,**kwargs):
    threads = []

    for i in range(1,3):
        uname = 'uname-'+str(i)
        # kwargs.update(uname=uname)
        nkwargs = kwargs.copy()
        nkwargs.update({'uname':uname})
        #kwargs['uname']=uname
        t = threading.Thread(target=func_name,kwargs=nkwargs)
        threads.append(t)
        #print ('{} function:{}'.format(func_name.__name__))
    
    for t in threads:
        #t.setDaemon(True)
        t.start()
    
    for t in threads:
        t.join()
        print (dir(t))
        print (t._stop())
        print (t.isAlive())
    


def create_account(uname = None,node_ip = None):
    cmd = '{} create {} is {}'.format(node_ip,uname,uname)
    print (cmd)


def delete_account(uname=None,node_ip=None):
    cmd = '{} delete {}'.format(node_ip,uname)
    print (cmd)


def list_account(uname=None,node_ip=None):
    cmd = '{} list'.format(node_ip)
    print (cmd)


if __name__=="__main__":
    #node_ip = raw_input('Node IP:')
    node_ip = '10.10'
    multi_process_account(create_account,node_ip = node_ip)
    multi_process_account(list_account,node_ip = node_ip)
    multi_process_account(delete_account,node_ip = node_ip)