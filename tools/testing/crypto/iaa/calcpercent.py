#!/usr/bin/env python3

import sys
filename = sys.argv[1]
nargs = len(sys.argv)

hits = 0
percentile = 98
thresh = hits * percentile / 100
print("Filename: %s" % filename)

infile = open(filename, 'r')
if nargs > 2:
        percentile = sys.argv[2]

print("Percentile: %s" % percentile)

lines = infile.readlines()

eq_0_map = {}
ne_0_map = {}

cur_event = ""
ret0 = False

for line in lines:
	sline = line.strip()
	if sline.find("hists:") != -1:
#	   print("\n")
#	   print(sline)
#	   print("\n")
	   sline = sline.split(' ')
	   cur_event = sline[0]
#	   print(cur_event)
	elif sline.find("ret == 0") != -1:
#	   print(sline)
	   ret0 = True
	elif sline.find("ret != 0") != -1:
#	   print(sline)
	   ret0 = False
	elif sline.find("Hits:") != -1:
#	   print(sline)
	   sline = sline.split(':')
#	   print(sline[1])           
	   if ret0 == True:
	   	eq_0_map[cur_event] = int(sline[1])
	   if ret0 == False:
	   	ne_0_map[cur_event] = int(sline[1])

#print(eq_0_map)
#print(ne_0_map)

infile.close()

infile = open(filename, 'r')

lines = infile.readlines()

for line in lines:
	sline = line.strip()
	if sline.find("hists") != -1:
#	   print("\n")
#	   print(line)
#	   print("\n")
	   sline = sline.split(' ')
	   cur_event = sline[0]
#	   print(cur_event)
	elif sline.find("trigger info") != -1:
#	   print(line)
	   if sline.find("ret == 0") != -1:
	   	hits = eq_0_map[cur_event]
	   	if hits == 0:
                        continue
	   	thresh = hits * .98
	   	print("\nhist event: %s with ret == 0" % cur_event)
	   	print("    event hit count: %s" % hits)
	   	print("    {} percent of hit count = {}".format(int(percentile), thresh))
	   	sum = 0
	   	printed = False
	   elif sline.find("ret != 0") != -1:
	   	hits = ne_0_map[cur_event]
	   	if hits == 0:
                        continue
	   	thresh = hits * .98
	   	print("\nhist event: %s with ret != 0 " % cur_event)
	   	print("    event hit count: %s" % hits)
	   	print("    {} percent of hit count = {}".format(int(percentile), thresh))
	   	sum = 0
	   	printed = False
	elif  sline.find("{ lat") != -1:
	   sline = sline.split(':')
	   sum += int(sline[2])
#	   print(sline[1])
#	   print(sum)
	   if sum >= thresh and not printed:
	   	   print("    hit threshold of %d at line:" % sum)
	   	   print("    %s" % line)
	   	   printed = True

infile.close()

