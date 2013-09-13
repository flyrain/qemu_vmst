import sys
filename = sys.argv[1]
f = open(filename, "r");
lines = f.readlines();
count = len(lines)/5;
outlines =[]
os_type = [
'Win-XP',
'Win-XP(sp2)',
'Win-XP(sp3)',
'Win-Vista',
'Win-7',
'Win-2003',
'Win-2003(sp2)',
'Win-2008',
'Win-2008(sp2)',
'FreeBSD-7.4',
'FreeBSD-8.0',
'FreeBSD-8.2',
'FreeBSD-8.3',
'FreeBSD-9.0',
'OpenBSD-4.7',
'OpenBSD-4.8',
'OpenBSD-4.9',
'OpenBSD-5',
'OpenBSD-5.1',
'NetBSD-4.0',
'NetBSD-4.0.1',
'NetBSD-5.0',
'NetBSD-5.0.1',
'NetBSD-5.0.2',
'NetBSD-5.1',
'NetBSD-5.1.2',
'Linux-2.6.26',
'Linux-2.6.27',
'Linux-2.6.28',
'Linux-2.6.28.1',
'Linux-2.6.28.2',
'Linux-2.6.29',
'Linux-2.6.30',
'Linux-2.6.31',
'Linux-2.6.32.27',
'Linux-2.6.33',
'Linux-2.6.34',
'Linux-2.6.35',
'Linux-2.6.36',
'Linux-2.6.36.1',
'Linux-2.6.36.2',
'Linux-2.6.36.3',
'Linux-2.6.36.4',
'Linux-3.0.0',
'Linux-3.0.4',
'Solaris-10',
]
# avg-time
for i in range(0, count):
    line1 = lines[i].split()
    line2 = lines[i+count].split()
    line3 = lines[i+count*2].split()
    line4 = lines[i+count*3].split()
    line5 = lines[i+count*4].split()
    title = line1[5]
    avg0 = (float(line1[0]) + float(line2[0]) + float(line3[0])+ float(line4[0])+ float(line5[0]))/5
    avg1 = (float(line1[1]) + float(line2[1]) + float(line3[1])+ float(line4[1])+ float(line5[1]))/5
    avg2 = (float(line1[2]) + float(line2[2]) + float(line3[2])+ float(line4[2])+ float(line5[2]))/5
    avg3 = (float(line1[3]) + float(line2[3]) + float(line3[3])+ float(line4[3])+ float(line5[3]))/5
    avg_sum = avg0+ avg1+avg2+avg3
    percent0 = avg0/avg_sum 
    percent1 = avg1/avg_sum 
    percent2 = avg2/avg_sum 
    percent3 = avg3/avg_sum 
   
    outline = [avg0,percent0,avg1,percent1,avg2,percent2,avg3,percent3,avg_sum,title]
    
    print "PGD:\t{:.1f}\t=>\t{:.3%}\tKDI:\t{:.1f}\t=>\t{:.3%}\tDISASS:\t{:.1f}\t=>\t{:.3%}\tSCAN:\t{:.1f}\t=>\t{:.3%}".format(avg0,percent0,avg1,percent1,avg2,percent2,avg3,percent3),
    print '\t', 
   # print avg_sum/1000,
    print '\t'+title
    
   # print outline
    outlines.append(outline)


for i in range(0, count):
    print os_type[i]+'\t',
    print "PGD:\t{:.1f}\t=>\t{:.3%}".format(outlines[i][0],outlines[i][1])

print '=multi'

for i in range(0, count):
    print os_type[i]+'\t',
    print "KDI:\t{:.1f}\t=>\t{:.3%}".format(outlines[i][2],outlines[i][3])

print '=multi'

for i in range(0, count):
    print os_type[i]+'\t',
    print "DISASS:\t{:.1f}\t=>\t{:.3%}".format(outlines[i][4],outlines[i][5])

print '=multi'

for i in range(0, count):
    print os_type[i]+'\t',
    print "SCAN:\t{:.1f}\t=>\t{:.3%}".format(outlines[i][6],outlines[i][7])
