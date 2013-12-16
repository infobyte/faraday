'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import re
def c(x,y):
    return (x<<4)+y

ESC=chr(c(1,11))

C0  = "[00/00-01/15]"
C1  = "01/11,[04/00-05/15]"
CSI = "01/11,05/11,[03/00-03/15]*,[02/00-02/15]*,[04/00-07/14]"

##
## Compile single definition to regular expression
##

rx_char=re.compile(r"^(\d\d)/(\d\d)$")
rx_range=re.compile(r"^\[(\d\d)/(\d\d)-(\d\d)/(\d\d)\](\*?)$")

def compile_ecma_def(s):
    r=[]
    for token in s.split(","):
        match=rx_range.match(token)
        if match:
            c1=c(int(match.group(1)),int(match.group(2)))
            c2=c(int(match.group(3)),int(match.group(4)))
            if c1==c2:
                x=[r"\x%02x"%c1]
            elif c1<c2:
                rr=[r"\x%02x"%x for x in range(c1,c2+1)]
                x=["[%s]"%"".join(rr)]
            else:
                rr=[r"\x%02x"%x for x in range(c2,c1+1)]
                x=["[%s]"%"".join(rr)]
            if match.group(5):
                x+="*"
            r+=x
            continue
        match=rx_char.match(token)
        if match:
            r+=[r"\x%02x"%c(int(match.group(1)),int(match.group(2)))]
            continue
        raise Exception("Invalid token: <%s>"%token)
    return "".join(r)
##
## Compile ECMA-48 definitions to regular expression
##
def get_ecma_re():
    re_csi=compile_ecma_def(CSI)
    re_c1=compile_ecma_def(C1).replace("\\x5b","")
    re_c0=compile_ecma_def(C0)

    for xc in ["\\x08","\\x09","\\x0a","\\x0d","\\x1b"]:
        re_c0=re_c0.replace(xc,"")

    re_vt100="\\x1b[c()78]" # VT100
    re_other="\\x1b[^[]"       # Last resort. Skip all ESC+char
    return "|".join(["(%s)"%r for r in (re_csi,re_c1,re_c0,re_vt100,re_other)])
##
## Backspace pattern
##
rx_bs=re.compile("[^\x08]\x08")
##
## \r<spaces>\r should be cut
##
rx_lf_spaces=re.compile(r"\r\s+\r")
##
## ESC sequence to go to the bottom-left corner of the screen
##
rx_esc_pager=re.compile("(^.*?\x1b\\[24;1H)|((?<=\n).*?\x1b\\[24;1H)",re.MULTILINE)
##
## Remove ECMA-48 Control Sequences from a string
##
rx_ecma=re.compile(get_ecma_re())
def strip_control_sequences(s):
    def strip_while(s,rx):
        while True:
            ss=rx.sub("",s)
            if ss==s:
                return s
            s=ss
    
    # Remove pager trash
    s=strip_while(s,rx_esc_pager)
    # Process backspaces
    s=strip_while(s,rx_bs)
    # Process LFs
    s=rx_lf_spaces.sub("",s)
    # Remove escape sequences
    return rx_ecma.sub("",s)
