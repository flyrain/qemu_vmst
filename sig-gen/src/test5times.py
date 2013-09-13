import os
os.system('rm outData')
os.system('rm outTime')
for i in range(5):
    print i,
    print 'begin'
    os.system('./testall.sh')
    print i, 
    print 'end'
