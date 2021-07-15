# !/usr/bin/python
# -*- encoding=utf8 -*-


import sys
import time


for mem in sys.argv[1:]:
    print time.strftime("%y-%m-%d_%H:%M:%S", time.localtime(float(mem))) + str(float(mem) % 1)[1:5]