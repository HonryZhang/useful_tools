# !/usr/bin/python
# -*- encoding=utf8 -*-

"""
description: 恢复源文件
author: baorb
"""

import os
import sys
from inputstream import BasicCheckData, InputStream


def main():
    if len(sys.argv) != 4 and len(sys.argv) != 5:
        print "   python restore_object_tool.py basic_data_seed object_size offset"
        print "or python restore_object_tool.py basic_data_seed object_size offset file_path"
        sys.exit(1)

    basic_data_seed = int(sys.argv[1])
    object_size = int(sys.argv[2])
    object_offset = int(sys.argv[3])
    if len(sys.argv) == 4:
        file_abs_path = 'source_file'
    else:
        file_abs_path = os.path.join(sys.argv[4], 'source_file')

    # 生成原始数据
    BasicCheckData.create_data(seed=basic_data_seed)

    input_stream = InputStream(size=object_size, basedata_offset=object_offset)

    chunk_size = 64*1024
    with open(file_abs_path, 'wb') as f:
        while True:
            content = input_stream.read(chunk_size)
            if not content:
                break
            f.write(content)


if __name__ == '__main__':
    main()
