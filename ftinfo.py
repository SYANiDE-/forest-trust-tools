#!/usr/bin/env python
#
# Convert FOREST_TRUST_INFO structs into readable format
#
# Author:
#  Dirk-jan Mollema (@_dirkjan)
#
import binascii, argparse, sys, base64
from impacket.structure import Structure
from impacket.ldap.ldaptypes import LDAP_SID
from IPython import embed

EXAMPLE_STRUCT = (
    # Example msDs-TrustForestTrustInfo from Active Directory Users and Computers
    "01 00 00 00 04 00 00 00 1B 00 00 00 00 00 00 00 C2 72 D5 01 4E D9 12 F5 00 "
    "0A 00 00 00 64 6F 6D 64 2E 6C 6F 63 61 6C 48 00 00 00 00 00 00 00 47 76 D5 "
    "01 BF EC A6 77 02 18 00 00 00 01 04 00 00 00 00 00 05 15 00 00 00 9A D8 33 "
    "B7 8C FD 3E 25 EA 68 12 19 11 00 00 00 73 75 62 74 77 6F 2E 64 6F 6D 64 2E "
    "6C 6F 63 61 6C 06 00 00 00 53 55 42 54 57 4F 42 00 00 00 00 00 00 00 D2 72 "
    "D5 01 BF 51 8D 5A 02 18 00 00 00 01 04 00 00 00 00 00 05 15 00 00 00 35 E3 "
    "41 33 E4 64 F7 57 72 08 79 06 0E 00 00 00 73 75 62 2E 64 6F 6D 64 2E 6C 6F "
    "63 61 6C 03 00 00 00 53 55 42 3F 00 00 00 00 00 00 00 C2 72 D5 01 4E D9 12 "
    "F5 02 18 00 00 00 01 04 00 00 00 00 00 05 15 00 00 00 50 58 04 7A 06 B4 A7 "
    "5C 1D 99 68 A2 0A 00 00 00 64 6F 6D 64 2E 6C 6F 63 61 6C 04 00 00 00 64 6F "
    "6D 64"
    "\nOR\n"
    # Example msDs-TrustForestTrustInfo from powerview.py (https://github.com/aniqfakhrul/powerview.py.git)
    # Get-DomainObject -LDAPFilter "(&(objectClass=trustedDomain))" -Server dc02.logistics.ad -Identity inlanefreight.ad -Properties 'msDS-TrustForestTrustInfo' -Raw
    "AQAAAAMAAAAhAAAAAAAAABg42gEG/iB2ABAAAABpbmxhbmVmcmVpZ2h0LmFkTAAAAAAAAABGddo"
    "BfQJrvQIYAAAAAQQAAAAAAAUVAAAAHhAx5zpJugN1C+wmFgAAAGNoaWxkLmlubGFuZWZyZWlnaH"
    "QuYWQFAAAAQ0hJTEROAAAAAAAAABg42gEG/iB2AhgAAAABBAAAAAAABRUAAAA7T/yQYZ1WCt9dN"
    "ckQAAAAaW5sYW5lZnJlaWdodC5hZA0AAABJTkxBTkVGUkVJR0hU" ## base64
)


def get_args():
    parser = argparse.ArgumentParser(description="msDS-TrustForestTrustInfo struct parser")
    meg = parser.add_mutually_exclusive_group(required=True)
    meg.add_argument("-s", "--struct", type=str, default=None,help="The msDS-TrustForestTrustInfo struct to parse")
    meg.add_argument("-e", "--example", action='store_true', help="Show an example struct for demo use")
    ar,trash = parser.parse_known_args()
    args = vars(ar)
    if args['example']:
        print(f"[+] Example msDs-TrustForestTrustInfo struct:\n{EXAMPLE_STRUCT}")
        sys.exit()
    return args


class FOREST_TRUST_INFO_RECORD(Structure):
    structure = (
        ('RecordLen','<I'),
        ('Flags','<I'),
        ('Timestamp','<Q'),
        ('RecordType','B'),
        ('DataLen','_-Data','self["RecordLen"]-13'),
        ('Data',':')
    )
    def fromString(self, data):
        Structure.fromString(self, data)
        if self['RecordType'] == 2:
            self['Data'] = FOREST_TRUST_RECORD_DOMAININFO(self['Data'])
        else:
            # 1 or 0 means FOREST_TRUST_RECORD_TOPLEVELNAME or FOREST_TRUST_RECORD_TOPLEVELNAME_EX
            self['Data'] = FOREST_TRUST_RECORD_TOPLEVELNAME(self['Data'])


class FOREST_TRUST_RECORD_TOPLEVELNAME(Structure):
    structure = (
        ('NameLen','<I-Name'),
        ('Name',':')
    )


class FOREST_TRUST_RECORD_TOPLEVELNAME_EX(FOREST_TRUST_RECORD_TOPLEVELNAME):
    pass


class FOREST_TRUST_RECORD_DOMAININFO(Structure):
    structure = (
        ('SidLen','<I-Sid'),
        ('Sid', ':', LDAP_SID),
        ('DnsNameLen','<I-DnsName'),
        ('DnsName',':'),
        ('NetbiosNameLen','<I-NetbiosName'),
        ('NetbiosName',':')
    )


class FOREST_TRUST_INFO(Structure):
    structure = (
        ('Version','<I'),
        ('Recordcount','<I'),
        ('Records',':')
    )
    def fromString(self, data):
        Structure.fromString(self, data)
        rdata = self['Records']
        self['Records'] = []
        for i in range(self['Recordcount']):
            self['Records'].append(FOREST_TRUST_INFO_RECORD(rdata))
            rdata = rdata[len(self['Records'][-1]):]


class NORMALIZER():
    def __init__(self,structarg):
        self.holder = structarg
        self.runtime()
    
    def unhexlify(self):
        didit = False
        try:
            tmp = binascii.unhexlify(self.holder.replace(' ',''))
            didit = True
        except:
            tmp = self.holder
        return tmp, didit

    def base64decode(self):
        didit = False
        try:
            base64.b64decode(self.holder,validate=True)
            tmp = base64.b64decode(self.holder)
            didit = True
        except:
            tmp = self.holder
        return tmp, didit

    def runtime(self):
        trials = [self.unhexlify,self.base64decode]
        converted = False
        for func in trials:
            try:
                if converted == False:
                    self.holder, didit = func()
                    if didit == True:
                        converted == True
            except:
                pass


def main():
    args = get_args()
    struct_dat = NORMALIZER(args['struct']).holder
    fi = FOREST_TRUST_INFO(struct_dat)
    fi.dump()
    for record in fi['Records']:
        # record.dump()
        try:
            dnsName = record['Data']['DnsName']
            sid =     record['Data']['Sid']        
            print(f'Domain {dnsName} has SID {sid.formatCanonical()}')
            print(f'Domain {dnsName} has SID {sid.getData()}')
        except KeyError:
            pass


if __name__=="__main__":
    main()