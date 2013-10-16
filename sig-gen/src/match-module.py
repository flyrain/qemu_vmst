#! /usr/bin/env python
import sys
import argparse

'''
Calculate module offsets of two snapshots
Author: Yufei Gu
Time-stamp: <2013-09-08 17:07:37 cs3612>
'''


def process_command_line():
    argv = sys.argv[1:]

    # initializing the parser object
    parser = argparse.ArgumentParser(description='Calculate module offsets of two snapshots')

    # defining command options
    parser.add_argument('module', help='module md5 file')
    parser.add_argument('snapshot_a', help='all md5 of snapshot a')
    parser.add_argument('snapshot_b', help='all md5 of snapshot b')
    args = parser.parse_args(argv)
    return args.module, args.snapshot_a, args.snapshot_b


def match(modules_md5, all_md5):
    result = {}
    for module_item in reversed(modules_md5):
        #print 'module_item', module_item[0]
        base_no = 0
        for idx, md5_item in enumerate(module_item[1]):
            for item in all_md5:
                item_strings = item.split()
                if md5_item.split()[0] == item_strings[0] and (idx == 0 or int(md5_item.split()[2]) + base_no == int(item_strings[2])):
                    if base_no == 0 or idx == 0:
                        base_no = int(item_strings[2])
                    #print idx, "match"
                    if idx == len(module_item[1]) - 1:
                        #print "md5_item.split()", md5_item.split()
                        offset = int(md5_item.split()[2])
                        #print module_item[0], int(item.split()[1], 16) - offset * 0x1000,  (offset + 1) * 0x1000
                        if not result.has_key(module_item[0]):
                            size = (offset + 1) * 0x1000
                            start_addr = int(item.split()[1], 16) - offset * 0x1000
                            result[module_item[0]] = [start_addr, size, 0]
                        else:
                            result[module_item[0]][2] += 1

    result_single = {}
    for (key, value) in result.items():
        if value[2] == 0:
            result_single[key] = value
            #print key, value
    return result_single


def get_lines(filename):
    f_all = open(filename)
    lines_all = f_all.readlines()
    all_md5 = []
    for line in lines_all:
        strings = line.split()
        if len(strings) == 3 and len(line) >= 44:
            all_md5.append(line)

    return all_md5


def main():
    (module, snapshot_a, snapshot_b) = process_command_line()
    f = open(module)
    lines = f.readlines()
    modules_md5 = []
    module_item = []
    modules_size = {}
    for line in lines:
        strings = line.split()
        if len(strings) == 6 and strings[1] == '~':
            module_item = [strings[3], []]
            modules_md5.append(module_item)
            modules_size[strings[3]] = int(strings[2][:len(strings[2])-1],16) - int(strings[0],16)
        if len(strings) == 3 and len(line) >= 44:
            if len(module_item) > 1:
                module_item[1].append(line)


#    for (key,value) in modules_size.items():
#        print key,hex(value)

#    for module_item in reversed(modules_md5):
#        print module_item

    all_md5_a = get_lines(snapshot_a)
    all_md5_b = get_lines(snapshot_b)

    #match
    match_a = match(modules_md5, all_md5_a)
    #print '*'*80
    match_b = match(modules_md5, all_md5_b)
    #print '*'*80
    #print_match_result(match_a)
    #print_match_result(match_b)

    for (key, value) in match_a.items():
        if match_b.has_key(key):
            print "%s %x %x %x" % (key, match_b[key][0], modules_size[key], value[0] - match_b[key][0])

    return 0


def print_match_result(result):
    for (key, value) in result.items():
        print key, value
    print '*'*80


if __name__ == "__main__":
    status = main()
    sys.exit(status)
