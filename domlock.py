#!/usr/bin/python3

import optparse
import sys
import concurrent.futures
import aslookup
import socket

BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'

print(BLUE + "Domlock[1.0] by ARPSyndicate" + CLEAR)
print(YELLOW + "domain to asn & netblock" + CLEAR)

if len(sys.argv)<2:
	print(RED + "[!] ./domlock --help" + CLEAR)
	sys.exit()

else:
	parser = optparse.OptionParser()
	parser.add_option('-l', '--list', action="store", dest="list", help="list of domains to check")
	parser.add_option('-v', '--verbose', action="store_true", dest="verbose", help="enable logging", default=False)
	parser.add_option('-T', '--threads', action="store", dest="threads", help="threads", default=20)
	parser.add_option('-o', '--output', action="store", dest="output", help="output results")
	
inputs, args = parser.parse_args()
if not inputs.list:
	parser.error(RED + "[!] list of targets not given" + CLEAR)
list = str(inputs.list)
verbose = inputs.verbose
output = str(inputs.output)
threads = int(inputs.threads)
result = []
with open(list) as f:
	domains=f.read().splitlines()

def getResults(domain):
    try:
        asdata = aslookup.get_as_data(socket.gethostbyname(domain))
    except:
        if verbose:
            print(RED+"[!] "+domain+CLEAR)
    asn = asdata[0]
    name = asdata[2]
    block = asdata[5]
    country = asdata[6]
    summary = "{0} {1} {2} {3} {4}".format(domain, asn, name, country, block)
    print(BLUE+"[+] "+summary+CLEAR)
    result.append("{0}".format(summary))

with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
    try:
        executor.map(getResults, domains)
    except(KeyboardInterrupt, SystemExit):
        print(RED + "[!] interrupted" + CLEAR)
        executor.shutdown(wait=False)
        sys.exit()
if inputs.output:
    with open(output, 'a') as f:
        f.writelines("%s\n" % line for line in result)

print(YELLOW+"[*] done"+CLEAR)