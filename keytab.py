#!/usr/bin/python3

import argparse
from struct import unpack, pack
from impacket.structure import Structure
import binascii
import sys

# Keytab structure from http://www.ioplex.com/utilities/keytab.txt
# keytab {
#     uint16_t file_format_version;                    /* 0x502 */
#     keytab_entry entries[*];
# };

# keytab_entry {
#     int32_t size;
#     uint16_t num_components;    /* sub 1 if version 0x501 */
#     counted_octet_string realm;
#     counted_octet_string components[num_components];
#     uint32_t name_type;   /* not present if version 0x501 */
#     uint32_t timestamp;
#     uint8_t vno8;
#     keyblock key;
#     uint32_t vno; /* only present if >= 4 bytes left in entry */
# };

# counted_octet_string {
#     uint16_t length;
#     uint8_t data[length];
# };

# keyblock {
#     uint16_t type;
#     counted_octet_string;
# };


class KeyTab(Structure):
    structure = (("file_format_version", "H=517"), ("keytab_entry", ":"))

    def __init__(self):
        super().__init__()
        self.entries = []

    def fromString(self, data):
        Structure.fromString(self, data)
        data = self["keytab_entry"]
        while len(data) != 0:
            ktentry = KeyTabEntry(data)

            data = data[len(ktentry.getData()) :]
            self.entries.append(ktentry)

    def getData(self):
        self["keytab_entry"] = b"".join([entry.getData() for entry in self.entries])
        data = Structure.getData(self)
        return data

    def append_entry(self, domain, username, etype, secret):
        ktcr = KeyTabContentRest()
        ktcr["keytype"] = etype
        ktcr["key"] = binascii.unhexlify(secret)
        nktcontent = KeyTabContent()
        nktcontent.restfields = ktcr
        # The realm here doesn't matter for wireshark but does of course for a real keytab
        nktcontent["realm"] = domain
        user = OctetString()
        user["value"] = username
        nktcontent.components = [user]
        nktentry = KeyTabEntry()
        nktentry["content"] = nktcontent
        self.entries.append(nktentry)


class OctetString(Structure):
    structure = (("len", ">H-value"), ("value", ":"))


class KeyTabContentRest(Structure):
    structure = (
        ("name_type", ">I=1"),
        ("timestamp", ">I=0"),
        ("vno8", "B=2"),
        ("keytype", ">H"),
        ("keylen", ">H-key"),
        ("key", ":"),
    )


class KeyTabContent(Structure):
    structure = (
        ("num_components", ">h"),
        ("realmlen", ">h-realm"),
        ("realm", ":"),
        ("components", ":"),
        ("restdata", ":"),
    )

    def fromString(self, data):
        self.components = []
        Structure.fromString(self, data)
        data = self["components"]
        for i in range(self["num_components"]):
            ktentry = OctetString(data)

            data = data[ktentry["len"] + 2 :]
            self.components.append(ktentry)
        self.restfields = KeyTabContentRest(data)

    def getData(self):
        self["num_components"] = len(self.components)
        # We modify the data field to be able to use the
        # parent class parsing
        self["components"] = b"".join(
            [component.getData() for component in self.components]
        )
        self["restdata"] = self.restfields.getData()
        data = Structure.getData(self)
        return data


class KeyTabEntry(Structure):
    structure = (("size", ">I-content"), ("content", ":", KeyTabContent))


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Convert impacket's secretsdump.py Kerberos secrets into keytab file format "
            + "suitable for loading into Wireshark for ticket decryption."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "infile",
        help=(
            'NTDS dump obtained with impacket; for example "hashes.ntds.kerberos" when dumping hashes with: '
            + 'secretsdump.py "$DOMAIN/$USR:$PASS@$DC" -outputfile hashes'
        ),
    )

    parser.add_argument("outfile", help="Name of the output keytab file")

    parser.add_argument(
        "-d",
        "--domain",
        help=(
            "Active Directory domain (e.g. mydomain.local); "
            + "this name should not matter in most cases."
        ),
        default="TESTSEGMENT.LOCAL",
    )

    args = parser.parse_args()
    args.domain = args.domain.upper().encode("utf8")
    return args


# https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml
def get_etype_number(s):
    if s.startswith("0x"):
        return int(s, 16)
    elif s == "des-cbc-crc":
        return 1
    elif s == "des-cbc-md4":
        return 2
    elif s == "des-cbc-md5":
        return 3
    elif s == "des3-cbc-md5":
        return 5
    elif s == "des3-cbc-sha1":
        return 7
    elif s == "dsaWithSHA1-CmsOID":
        return 9
    elif s == "md5WithRSAEncryption-CmsOID":
        return 10
    elif s == "sha1WithRSAEncryption-CmsOID":
        return 11
    elif s == "rc2CBC-EnvOID":
        return 12
    elif s == "rsaEncryption-EnvOID":
        return 13
    elif s == "rsaES-OAEP-ENV-OID":
        return 14
    elif s == "des-ede3-cbc-Env-OID":
        return 15
    elif s == "des3-cbc-sha1-kd":
        return 16
    elif s == "aes128-cts-hmac-sha1-96":
        return 17
    elif s == "aes256-cts-hmac-sha1-96":
        return 18
    elif s == "aes128-cts-hmac-sha256-128":
        return 19
    elif s == "aes256-cts-hmac-sha384-192":
        return 20
    elif s == "rc4-hmac":
        return 23
    elif s == "rc4-hmac-exp":
        return 24
    elif s == "camellia128-cts-cmac":
        return 25
    elif s == "camellia256-cts-cmac":
        return 26


def main():
    args = parse_args()

    nkt = KeyTab()

    with open(args.infile, "r") as f:
        for line in f:
            username, etype, secret = line.strip().split(":")
            etype = get_etype_number(etype)
            nkt.append_entry(args.domain, username, etype, secret)

    data = nkt.getData()
    with open(args.outfile, "wb") as outfile:
        outfile.write(data)


if __name__ == "__main__":
    main()
