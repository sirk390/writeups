## new-authent (INS'hAck 2019)

This challenge provided two pdf files containing TOTP codes (Time based One Time Passwords) named by their timestamp. These are similar to google authenticator (or authenticator plus which I prefer ).

From the description, we understood that the seed is an 8 digit number ('the same 8 digit number as the safe code')

Some algorithm parameters were given like "param HMAC-SHA1, 30s steps, 10 bytes secrets", however
the 10 bytes secret was confusing as it was in conflict with the previous information an 8 digit number.

After trying a few variations on the key encoding, the below program returned pretty quickly with a result *83427324*:

```python
import multiprocessing
import hashlib
import hmac
import base64
import struct

T1 = 1556512424 // 30
T2 = 1556565272 // 30

V1 = 240632
V2 = 123325


def get_token(nb, intervals_no=None):
    key = str(nb).encode()# base64.b32encode(str(nb).encode())
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


def bfproc(idx):
    start = idx * 10000000
    for seed in range(9999999):
        if get_token(start+seed, T1) == V1:
            print (start+seed)
            if get_token(start+seed, T2) == V2:
                print ("***", start+seed)

if __name__ == '__main__':       
    pool = multiprocessing.Pool(10)
    pool.map(bfproc, range(10))
        
```

I computed that I would get a working but incorrect seed 1 out of 148 times, so I was quite confident that "83427324" was the correct seed.

Now, we only needed to use this to generate an image with a TOTP code containing "Document Colour Tracking Dots". These are invisible dots used by printers to allow for the identification of printer manufacturer and the serial number of a printed document.

After some searches, I decided to use the **reportlab** to generate the PDF file, **libdeda**  to generate the tracking dots, and **pdf2image** to convert the document to an image, as the validation website required that we uploaded an image. **libdeda** is pretty slow so I generated the PDF with a timestamp of +30 seconds in the future, giving me also some time to upload it on the website.

It still complained by saying "You are not using my printer". I needed to put the correct manufacturer and serial number in the tracking dots. After some thoughts, I realized that maybe we can extract this information from one of the input PDF, and indeed I found the manufacturer was Epson and the serial number 324.

After setting this information correctly and uploading the document, the website welcomes us with a nice flag:

```
INSA{S0rry_4_Th3_B4d_0cR}
```

The code for generating the PNG including tracking dots is below:

```python
import time
import struct
import hmac
import hashlib
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from libdeda.privacy import AnonmaskApplierTdm
from libdeda.pattern_handler import Pattern4, TDM
import argparse
from pdf2image import convert_from_path, convert_from_bytes
from reportlab.pdfgen import canvas


def get_token(nb, intervals_no=None):
    key = str(nb).encode()
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


def main():
    pdfmetrics.registerFont(TTFont('Verdana', 'verdana.ttf'))
    token = get_token(83427324, int(time.time()+20)//30)
     
    c = canvas.Canvas("newauth.pdf")
    c.setFont('Verdana', 96)
    c.setFillColorRGB(0,0,0)
    c.drawString(50,700, str(token))
    c.save()

    parser = argparse.ArgumentParser(
        description='Create a custom TDM')
    parser.add_argument("--serial", type=int, metavar="NNNNNN", default=324)
    parser.add_argument("--manufacturer", type=str, default="Epson", help=', '.join(set(Pattern4.manufacturers.values())))
    parser.add_argument("--year", type=int, metavar="NN", default=18)
    parser.add_argument("--month", type=int, metavar="NN", default=11)
    parser.add_argument("--day", type=int, metavar="NN", default=11)
    parser.add_argument("--hour", type=int, metavar="NN", default=11)
    parser.add_argument("--minutes", type=int, metavar="NN", default=11)
    parser.add_argument("--dotradius", type=float, metavar="INCHES", default=None, help='default=%f'%AnonmaskApplierTdm.dotRadius)
    args = parser.parse_args()

    tdm = TDM(Pattern4, content=dict(
        serial=args.serial,
        hour=args.hour,
        minutes=args.minutes,
        day=args.day,
        month=args.month,
        year=args.year,
        manufacturer=args.manufacturer,
    ))
    aa = AnonmaskApplierTdm(tdm, dotRadius=args.dotradius)
    with open("newauth.pdf","rb") as pdfin:
        data = aa.apply(pdfin.read())
    images = convert_from_bytes(data, dpi=300)
    images[0].save("newauth.png")
```






