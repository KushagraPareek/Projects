"""
This is a secure version of dig tool uses DNSSEC
Author : Kushagra Pareek
SBU ID : 112551443
"""
import sys
import os.path
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.dnssec

# error code 1:  DNSSEC not supported
# error code 2:  DNSSEC not validated
# error code 3:  Further resolution required

# global variables
file_path = "root.txt"
ds_record = ["19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
             "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
ds_record = [x.lower() for x in ds_record]
root_record = ds_record
ds_algo = "sha256"
key_record = None
srecords = None
error_code = 0


def set_error_code(code):
    global error_code
    error_code = code


def get_error_code():
    global error_code
    return error_code


# set_ds_record
def set_ds_record(rec):
    global ds_record
    if isinstance(rec, list):
        ds_record = rec
    else:
        ds_record = [str(rec)]


# get ds record
def get_ds_record():
    global ds_record
    return ds_record


# set ds_algo
def set_ds_algo(algo):
    global ds_algo
    if algo == 1:
        ds_algo = "sha1"
    elif algo == 2:
        ds_algo = "sha256"


# get ds_algo
def get_ds_algo():
    global ds_algo
    return ds_algo


# set key_record
def set_key_record(rec):
    global key_record
    key_record = rec


# get key_record
def get_key_record():
    global key_record
    return key_record


def is_file_present():
    if not os.path.isfile(file_path):
        print("Root file not present, Please check path")
        print("Exit.....")
        sys.exit(-1)


# Populate root server List from a file
def populate_root_servers():
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
        redomain = input_data[1]
        record = input_data[2]
        list_domain = redomain.split('.')
        if list_domain[0] == "www":
            list_domain.pop(0)
        redomain = '.'.join(list_domain)
        return redomain.lower(), record.lower()


# split and reverse domain
def split_reverse(domain):
    if domain[-1] == '.':
        domain = domain[0:len(domain) - 1:1]
    dlist = domain.split('.')
    return dlist[::-1]


# validate ksk and dnskeyset
def validate_server_ksk(data):
    if len(data) == 0:
        return False
    public_ksk = []
    res = False
    dns_key_record = None
    dns_key_rrsig = None
    for rec in data:
        if rec.rdtype == dns.rdatatype.DNSKEY:
            dns_key_record = rec
        if rec.rdtype == dns.rdatatype.RRSIG:
            dns_key_rrsig = rec
    if dns_key_record is None:
        set_error_code(1)
        return False
    set_key_record(dns_key_record)
    for k in dns_key_record.items:
        if k.flags == 257:
            public_ksk.append(k)
    for ksk in public_ksk:
        ds = dns.dnssec.make_ds(dns_key_record.name, ksk, get_ds_algo())
        if str(ds) in get_ds_record():
            res = True
            break
    # validate dnsKeyRecord
    try:
        dns.dnssec.validate(dns_key_record, dns_key_rrsig, {dns_key_record.name: dns_key_record})
    except dns.dnssec.ValidationFailure:
        set_error_code(2)
        return False
    return res


# validate ds rrset
def validate_rrset(data):
    if len(data) == 0:
        return False
    child_ksk_hash = []
    check_rrsig = None
    for rec in data:
        if rec.rdtype == dns.rdatatype.DS:
            child_ksk_hash.append(rec)
        if rec.rdtype == dns.rdatatype.RRSIG:
            check_rrsig = rec
    if len(child_ksk_hash) == 0 or check_rrsig is None:
        set_error_code(1)
        return False
    for ksk_hash in child_ksk_hash:
        try:
            dns.dnssec.validate(ksk_hash, check_rrsig, {get_key_record().name: get_key_record()})
        except dns.dnssec.ValidationFailure:
            set_error_code(2)
            continue
        else:
            set_ds_record(ksk_hash.items[0])
            set_ds_algo(ksk_hash.items[0].digest_type)
            return True
    return False


# validate A , MX or NS sets
def validate_arrset(data):
    if len(data) == 0:
        return False
    current_rrsig = None
    current_set = None
    for rec in data:
        if not (not (rec.rdtype == dns.rdatatype.A) and not (rec.rdtype == dns.rdatatype.NS) and not (
                rec.rdtype == dns.rdatatype.MX)):
            current_set = rec
        if rec.rdtype == dns.rdatatype.RRSIG:
            current_rrsig = rec
    if current_set is None or current_rrsig is None:
        set_error_code(1)
        return False
    try:
        dns.dnssec.validate(current_set, current_rrsig, {get_key_record().name: get_key_record()})
    except dns.dnssec.ValidationFailure:
        set_error_code(2)
        return False
    else:
        return True


# message on the std out
def message_out(messag):
    print(messag)


# save records
def save_records():
    global srecords
    srecords = {1: get_ds_record(), 2: get_ds_algo(), 3: get_key_record()}


# restore records
def restore_records():
    set_ds_record(srecords[1])
    set_ds_algo(srecords[2])
    set_key_record(srecords[3])


# fetch records iteratively
def fetch_records(domain, oftype, server_list, inrecur, rvdomain):
    reqmessage = dns.message.make_query(domain, oftype, want_dnssec=True)
    dnsdomain = '.'.join(rvdomain[-len(rvdomain) + inrecur - 2::-1])
    reqdnsmessage = dns.message.make_query(dnsdomain, dns.rdatatype.DNSKEY, want_dnssec=True)
    for server in server_list:
        try:
            retdata = dns.query.udp(reqmessage, server)
            retdnsdata = dns.query.tcp(reqdnsmessage, server)
        except dns.query.BadResponse:
            return None
        if retdata.rcode() != 0 or retdnsdata.rcode() != 0:
            continue
        else:
            if not validate_server_ksk(retdnsdata.answer):
                return None
            if len(retdata.answer) == 0:
                if not validate_rrset(retdata.authority):
                    return None
                """ Check additional section for glued record"""
                tldservers = []
                if len(retdata.additional) > 0:
                    for tld in retdata.additional:
                        if tld.items[0].rdtype == dns.rdatatype.A:
                            tldservers.append(str(tld.items[0]))
                    if len(tldservers) > 0:
                        return fetch_records(str(domain), oftype, tldservers, inrecur + 1, rvdomain)
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
                            set_key_record(None)
                            set_ds_algo(2)
                            set_ds_record(root_record)
                            datanew = fetch_records(str(nsdomain), dns.rdatatype.A, ROOT, 1,
                                                    split_reverse(str(nsdomain)))
                            set_error_code(3)
                            if datanew is not None:
                                if len(datanew.answer) > 0:
                                    if datanew.answer[0].items[0].rdtype == dns.rdatatype.NS:
                                        return datanew

                                servernew = []
                                for newserver in datanew.answer:
                                    if newserver.items[0].rdtype == dns.rdatatype.A:
                                        servernew.append(str(newserver.items[0]))
                                if len(servernew) > 0:
                                    return fetch_records(domain, oftype, servernew, inrecur + 1,
                                                         split_reverse(str(domain)))
                    return None
            else:
                """check if cname present"""
                if retdata.answer[0].items[0].rdtype == dns.rdatatype.CNAME:
                    cdomain = retdata.answer[0].items[0]
                    print("CNAME FOR DOMAIN {} is {}".format(domain, cdomain))
                    set_key_record(None)
                    set_ds_algo(2)
                    set_ds_record(root_record)
                    return fetch_records(str(cdomain), oftype, ROOT, 1, split_reverse(str(cdomain)))
                else:
                    if not validate_arrset(retdata.answer):
                        return None
                    return retdata


reqdomain, rtype = get_user_input()
ROOT = populate_root_servers()
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

records = fetch_records(reqdomain, reqtype, ROOT, 1, split_reverse(reqdomain))

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
    message_out("DNSSEC supported")
else:
    if error_code == 1:
        message_out("DNSSEC NOT SUPPORTED")
    elif error_code == 2:
        message_out("VALIDATION FALIURE")
    elif error_code == 3:
        message_out("RESOLVED TO NS RECORDS, FURTHER RESOLUTION REQUIRED")
print("-----------------------------------------------------------------")
print("-----------------------------------------------------------------")
