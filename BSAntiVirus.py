import json
from Virus_total import scan_virustotal
from HashReader import hash_dict
from MD5cal import md5
import os
from sys import argv,exit

if not 1<len(argv)<6 :
    print 1
    exit(1)

sender = {}
for file_to_scan in xrange(1,len(argv)):
    if os.path.isfile(argv[file_to_scan]) and os.path.exists(argv[file_to_scan]):
        sender[md5(os.path.abspath(argv[file_to_scan]))] = os.path.abspath(argv[file_to_scan])
    

for hash_value,file_name in sender.iteritems():
    if hash_value in hash_dict :
        print file_name,"contains malware."
    else:

        is_virus,virus_name = scan_virustotal(hash_value)
        if is_virus :

            fhan = open('main.hdb','a')
            fhan.write(hash_value+":0000:"+virus_name.replace(":",".")+"\n")
            fhan.close()
            hash_dict[hash_value]=virus_name
            print file_name,"contains malware."
        else :
           print file_name,"is safe."


