#!/usr/bin/env python3

import argparse
import glob

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-d', '--dir', default='.', help='input and output data directory')
args = parser.parse_args()

files = glob.glob(f'{args.dir}/*.trace')

print("Dir: %s" % args.dir)

for fl in files:
        dir_file = fl.split('/')
        file = dir_file[-1]
        print("File: %s" % file)
        file = file.split('.')
        filebase = file[0]
        print("Filename: %s" % fl)
        print("Filebase: %s" % filebase)
        outfilename = "{}/{}_store_comp_avg.csv".format(args.dir, filebase)
        print("Outfilename: %s" % outfilename)
        infile = open(fl, 'r')
        outfile = open(outfilename, 'w')

        lines = infile.readlines()

        count = 0
        total_dlen = 0

        # A compressed length which has been deferred from being added to the
        # total in case a by_n compression for that page followed it (in which
        # case the length for *that* compression replaces the deferred one
        # because the deferred one is assumed to be from the preceding by1
        # compression which was replaced by a by_n compression):
        deferred = 0

        for line in lines:
                sline = line.strip()
                if sline.find('store') != -1:
                        metrics = {}
                        for word in sline.split(' '):
                                if word.find('=') != -1:
                                        key, value = word.split('=', 1)
                                        try:
                                                metrics[key] = int(value)
                                        except ValueError:
                                                metrics[key] = value

                        by_n = metrics.get("by_n", 0);

                        if by_n > 1:
                                for i in range(1, by_n + 1):
                                        total_dlen += metrics[f"dlen{i}"]
                                count += 1
                                deferred = 0
                        else:
                                if deferred > 0:
                                        total_dlen += deferred
                                        count += 1
                                        deferred = 0
                                if metrics.get("dlen", 0) > 0:
                                        deferred = metrics["dlen"]

        if deferred > 0:
                total_dlen += deferred
                count += 1

        print("total_dlen: %d" % total_dlen)
        print("count: %d" % count)
        print("total_size: %d" % (count * 4096))
        print("Compression ratio = total_size / total_dlen: %f" % ((count * 4096) / total_dlen))

        outfile.write("Compression ratio: %f" % ((count * 4096) / total_dlen))

        outfile.close()
        infile.close()
