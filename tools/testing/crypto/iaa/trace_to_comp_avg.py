#!/usr/bin/env python3

import argparse
import glob
from multiprocessing import Process

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-d', '--dir', default='.', help='input and output data directory')
parser.add_argument('-e', '--event', default='load', help='load or store')
args = parser.parse_args()

files = glob.glob(f'{args.dir}/*.trace')

print("Dir: %s" % args.dir)
print("Event: %s" % args.event)


def processFile(path):
        dir_file = path.split('/')
        file = dir_file[-1]
        print("File: %s" % file)
        file = file.split('.')
        filebase = file[0]
        print("Filename: %s" % path)
        print("Filebase: %s" % filebase)
        avgfilename = "{}/{}_{}_comp_avg.csv".format(args.dir, filebase, args.event)
        print("avgfilename: %s" % avgfilename)
        sizefilename = "{}/{}_{}_size_stats.csv".format(args.dir, filebase, args.event)
        print("sizefilename: %s" % sizefilename)
        infile = open(path, 'r')
        avgfile = open(avgfilename, 'w')
        sizefile = open(sizefilename, 'w')

        lines = infile.readlines()

        count = 0
        total_dlen = 0

        print("name,size", file=sizefile)

        for line in lines:
                sline = line.strip()
                if sline.find(args.event) != -1:
                        metrics = {}
                        for word in sline.split(' '):
                                if word.find('=') != -1:
                                        key, value = word.split('=', 1)
                                        try:
                                                metrics[key] = int(value)
                                        except ValueError:
                                                metrics[key] = value

                        length = 0
                        by_n = metrics.get("by_n", 0);
                        if by_n > 1:
                                for i in range(1, by_n + 1):
                                        try:
                                                length += metrics[f"length{i}"]
                                        except KeyError:
                                                length += metrics.get(f"dlen{i}", 0)
                        else:
                                try:
                                        length = metrics["length"]
                                except KeyError:
                                        length = metrics.get("dlen", 0)
                        if length > 0:
                                print("len{},{}".format(count, length), file=sizefile)
                                total_dlen += length
                                count += 1

        print("total_dlen: %d" % total_dlen)
        print("count: %d" % count)
        print("total_size: %d" % (count * 4096))
        ratio = 0
        try:
                ratio = ((count * 4096) / total_dlen)
        except:
                pass
        print("Compression ratio = total_size / total_dlen: %f" % ratio)

        print("Compression ratio: %f" % ratio, file=avgfile)

        avgfile.close()
        sizefile.close()
        infile.close()


processes = []

for path in files:
        process = Process(target=processFile, args=[path])
        process.start()

for process in processes:
        process.join()
