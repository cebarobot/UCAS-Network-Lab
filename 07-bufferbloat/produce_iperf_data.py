import os
import sys
import re

qlen_list = [10, 50, 100, 150, 200]
# qlen_list = [100]

pat = re.compile(r'([\d.]+)-.*\s([\d.]+) M?bits/sec')

for qlen in qlen_list:
    input_file_name = 'qlen-%d/iperf.txt.1' % (qlen)
    output_file_name = 'qlen-%d/iperf.1.csv' % (qlen)

    with open(input_file_name, "r") as input_file, open(output_file_name, "w") as output_file:
        for line in input_file:
            matches = pat.findall(line)
            if len(matches) > 0:
                for cell in matches[0]:
                    # print(cell)
                    output_file.write('%s, ' % (cell))
                output_file.write('\n')

    print("Finished %s" % output_file_name)
    
