#!/usr/bin/env python3

import sys
filename = sys.argv[1]
nargs = len(sys.argv)

print("Filename: %s" % filename)

infile = open(filename, 'r')

lines = infile.readlines()

total_lat_map = {}
n_lat_map = {}

min_lat_map = {}
max_lat_map = {}

for line in lines:
	sline = line.strip()
	if (sline.find("iaa_lat:") != -1) or (sline.find("iaa_lat_len:") != -1):
	   ssline = sline.split('iaa_lat:')
	   if len(ssline) == 1:
                   ssline = sline.split('iaa_lat_len:')
	   sline = ssline
	   sline = sline[1].strip()
	   sline = sline.split(' ')

	   desc = sline[0]
	   desc = desc.split('=')
	   desc = desc[1]

	   lat = sline[1]
	   lat = lat.split('=')
	   lat = lat[1]

	   total_lat = total_lat_map.setdefault(desc, 0)
	   total_lat_map[desc] = total_lat + int(lat)
                   
	   n_lat = n_lat_map.setdefault(desc, 0)
	   n_lat_map[desc] = n_lat + 1

	   min_lat = min_lat_map.setdefault(desc, sys.maxsize)
	   if int(lat) < min_lat:
	           min_lat_map[desc] = int(lat)

	   max_lat = max_lat_map.setdefault(desc, 0)
	   if int(lat) > max_lat:
	   	   max_lat_map[desc] = int(lat)

for desc, n in n_lat_map.items():
	print("{}: n = {}, avg lat = {}, min = {}, max = {}".format(desc, n, total_lat_map[desc]/n, min_lat_map[desc], max_lat_map[desc]))

infile.close()
exit(0)
