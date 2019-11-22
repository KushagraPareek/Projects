"""
This program is a basic version of the dig tool
Only A, MX and NS records are supported
Author : Kushagra Pareek
SBU ID : 112551443
"""

import sys
import time
import os.path
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query


file_path = "root.txt"


# check if root file present
def is_file_present():
    if not os.path.isfile(file_path):
        print("Root file not present, Please check path")
        print("Exit.....")
        sys.exit(-1)


# Populate root server List from a file
def populate_servers():
    is_file_present()
    file = open(file_path, "r")
    root_servers = [line.rstrip() for line in file]
    return root_servers


# get user input from command line and format domain
def get_user_input():
    input_data = sys.argv
    if len(input_data) < 3:
        print("Enter correct number of argument:")
        print("Usage: <domain> <record>")
        sys.exit(-1)
    else:
        reqdomain = input_data[1]
        record = input_data[2]
        list_domain = reqdomain.split('.')
        if list_domain[0] == "www":
            list_domain.pop(0)
        reqdomain = '.'.join(list_domain)
        return reqdomain.lower(), record.lower()


# print results to console
def print_result(records):
    if records is not None:
        print(";; QUESTION SECTION")
        for ques in records.question:
            print(ques)
        print(";; ANSWER SECTION")
        for ans in records.answer:
            print(ans)
        print(";;AUTHORITY SECTION")
        for auth in records.authority:
            print(auth)
        print(";;ADDITIONAL SECTION")
        for addi in records.additional:
            print(addi)
        print("MSG RECVD : {} bytes".format(sys.getsizeof(records)))
    else:
        print("Not able to connect to fetch domain name")


# fetch records using recursor
def fetch_records(domain, oftype, server_list):
    reqmessage = dns.message.make_query(domain, oftype)
    for server in server_list:
        try:
            retdata = dns.query.udp(reqmessage, server)
        except dns.query.BadResponse:
            return None
        if retdata.rcode() != 0:
            continue
        else:
            if len(retdata.answer) == 0:
                """ Check additional section for glued record"""
                tldservers = []
                if len(retdata.additional) > 0:
                    for tld in retdata.additional:
                        if tld.items[0].rdtype == dns.rdatatype.A:
                            tldservers.append(str(tld.items[0]))
                    if len(tldservers) > 0:
                        return fetch_records(str(domain), oftype, tldservers)

                else:
                    """check authority for ns records"""
                    newdomains = []
                    for newd in retdata.authority:
                        for x in newd.items:
                            if x.rdtype == dns.rdatatype.NS:
                                newdomains.append(str(x))
                            if x.rdtype == dns.rdatatype.SOA:
                                return retdata
                    if len(newdomains) > 0:
                        for nsdomain in newdomains:
                            datanew = fetch_records(str(nsdomain), dns.rdatatype.A, ROOT)
                            if datanew is not None:
                                if len(datanew.answer) > 0:
                                    if datanew.answer[0].items[0].rdtype == dns.rdatatype.NS:
                                        return datanew

                                servernew = []
                                for newserver in datanew.answer:
                                    if newserver.items[0].rdtype == dns.rdatatype.A:
                                        servernew.append(str(newserver.items[0]))
                                if len(servernew) > 0:
                                    return fetch_records(domain, oftype, servernew)
                    return None
            else:
                """check if cname present"""
                if retdata.answer[0].items[0].rdtype == dns.rdatatype.CNAME:
                    cdomain = retdata.answer[0].items[0]
                    print("CNAME FOR DOMAIN {} is {}".format(domain, cdomain))
                    return fetch_records(str(cdomain), oftype, ROOT)
                else:
                    return retdata


ROOT = populate_servers()
requestdomain, rtype = get_user_input()
reqtype = None
if rtype == "a":
    reqtype = dns.rdatatype.A
elif rtype == "ns":
    reqtype = dns.rdatatype.NS
elif rtype == "mx":
    reqtype = dns.rdatatype.MX
else:
    print("Please enter correct record type")
    sys.exit(-1)

start = time.time()
# Try for 3 times if records are none
data = None
for luck in range(0, 3):
    data = fetch_records(requestdomain, reqtype, ROOT)
    if data is not None:
        break
end = time.time()
print_result(data)

print("Time to fetch records: {} ms".format(round((end - start) * 1000)))
print("------------------------------------------------------------------")
print("------------------------------------------------------------------")
