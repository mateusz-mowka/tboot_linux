#!/usr/bin/env python3

import argparse
import glob
from multiprocessing import Process

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-d', '--dir', default='.', help='input and output data directory')
parser.add_argument('-e', '--event', default='load', help='load, store, or all')
args = parser.parse_args()

files = glob.glob(f'{args.dir}/*.trace')

print("Dir: %s" % args.dir)
print("Event: %s" % args.event)


def processFile(path):
        dir_file = path.split('/')
        file = dir_file[-1]
        file = file.split('.')
        filebase = file[0]
        print("Filename: %s" % path)
        print("File: %s" % file)
        print("Filebase: %s" % filebase)
        outfilename = "{}/{}_{}_lat_stats.csv".format(args.dir, filebase, args.event)
        print("Outfilename: %s" % outfilename)
        infile = open(path, 'r')
        outfile = open(outfilename, 'w')
        outfile.write("name,lat\n")

        lines = infile.readlines()

        count = 0

        for line in lines:
	        sline = line.strip()
	        if sline.find(args.event) != -1:
	                sline = sline.split(' ')
	                i = 0
	                for elt in sline:
	                        if elt.find("lat=") != -1:
                                        elt = elt.split('=')
                                        outfile.write("lat{},{}\n".format(count, int(elt[1])))
                                        i += 1
                                        count = count + 1
        outfile.close()
        infile.close()


processes = []

for path in files:
        process = Process(target=processFile, args=[path])
        process.start()

for process in processes:
        process.join()
