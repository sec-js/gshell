from urllib.parse import quote_plus
from binascii import hexlify
import base64
import io

sep = "\n----------------NEXT CODE BLOCK----------------\n"

def url_encode(data):
    """
    URL-encode a byte stream and a few other characters
    """
    for line in io.StringIO(data):
        url_encoded = quote_plus(line)
        print(url_encoded.strip("\n"))
        print(sep)

def base64_encode(data):
    """
    base64 encode a byte stream
    """
    for line in io.StringIO(data):
        base64_encode = line
        encoding_bytes = base64_encode.encode('ascii')
        base64_bytes = base64.b64encode(encoding_bytes)
        print(base64_bytes.decode().strip("\n"))
        print(sep)

def base32_encode(data):
    """
    base32 encode a byte stream

    Some systems don't have base64 installed
    but do have base32 installed
    """
    for line in io.StringIO(data):
        base32_encode = line
        encoding_bytes = base32_encode.encode('ascii')
        base32_bytes = base64.b32encode(encoding_bytes)
        print(base32_bytes.decode().strip("\n"))
        print(sep)

def base16_encode(data):
    """
    base16 encode a byte stream

    Usually used to encode small bytes
    """
    for line in io.StringIO(data):
        base16_encode = line
        encoding_bytes = base16_encode.encode('ascii')
        base16_bytes = base64.b16encode(encoding_bytes)
        print(base16_bytes.decode().strip("\n"))
        print(sep)

def windows_base64(data):
    """
    Windows uses UTF16-LE Unicode strings to byte sequences
    """
    for line in io.StringIO(data):
        base64_encode = line
        encoding_bytes = base64_encode.encode('utf-16-le')
        base64_bytes = base64.b64encode(encoding_bytes)
        print(base64_bytes.decode().strip("\n"))
        print(sep)