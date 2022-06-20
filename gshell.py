#!/usr/bin/python3

"""
Author: nozerobit
Twitter: @nozerobit

Description:
GShell is a program to assist penetration testers by generating bind/reverse shells
It also provides them easy access to the bind_shells and reverse_shells markdown files
This allows them to write their own bind/reverse shells with ease using code blocks
"""

from evasion import encoders
from mdextract import CodeBlock
from mdextract import parse
from argparse import RawTextHelpFormatter
from colorama import Fore, Style, init, AnsiToWin32
from pprint import pprint
import os
import sys
import argparse
import ipaddress
import signal
import re


"""
Globals

This variables are used in different functions.

init: Automatically resets the colors (less code)
stream: Windows 32 compatible

colors:
green
yellow
red
blue
cyan
magenta

shells:
bind_shells
reverse_shells
"""

init(autoreset=True)
stream = AnsiToWin32(sys.stderr).stream

green = Style.BRIGHT + Fore.GREEN
yellow = Style.BRIGHT + Fore.YELLOW
red = Style.BRIGHT + Fore.RED
blue = Style.BRIGHT + Fore.BLUE
cyan = Style.BRIGHT + Fore.CYAN
magenta = Style.BRIGHT + Fore.MAGENTA

# For local regex
sbind_shells = open(sys.path[0] + '/shells/' + 'bind_shells.md')
sreverse_shells = open(sys.path[0] + '/shells/' + 'reverse_shells.md')
shollowing_snippets = open(sys.path[0] + '/snippets/' + 'process-hollowing.md')
sinjectors_snippets = open(sys.path[0] + '/snippets/' + 'process-hollowing.md')
# For markdown code extractions
bind_shells = [sys.path[0] + '/shells/' + 'bind_shells.md']
reverse_shells = [sys.path[0] + '/shells/' + 'reverse_shells.md']
hollowing_snippets = [sys.path[0] + '/snippets/' + 'process-hollowing.md']
injectors_snippets = [sys.path[0] + '/snippets/' + 'process-hollowing.md']


def handler(signum, frame):
    """
    Closes the program on Ctrl+C

    This might be used when prompted for questions
    """
    exit(1)

signal.signal(signal.SIGINT, handler)

def verify_ip(ip):
    """
    Verifies that the IP address is valid (IPv4 or IPv6)

    If the IP address is invalid it will exit the process with the return value 1
    """

    try:
        ip = ipaddress.ip_address(ip)
        print(green + '[+] The IPv{1} address: {0} is valid.'.format(ip, ip.version), file=stream)
    except ValueError:
        print(red + '[-] The address/netmask: {0} is invalid.'.format(ip), file=stream)
        exit(1)

def verify_port(port):
    """
    Verifies that the port number is valid

    If the port number is invalid it will exit the process with the return value 1
    """

    try:
        if 1 <= port <= 65535:
            print(green + '[+] The port number: {0} is valid.'.format(port), file=stream)
        else:
            raise ValueError
    except ValueError:
        print(red + '[-] The port number: {0} is invalid.'.format(port), file=stream)
        exit(1)


def list_shells():
    """
    Prints the available shells (names only)

    Detect and filter the names in the markdown code blocks

    Example:
    ```python
    ```
    Filters only 'python'.
    """

    pattern = re.compile(r'^```.*[^\n]')

    try:
        print(green + "[+] These are the available bind shells", file=stream)
        for line in set(sbind_shells):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))
        
        print(green + "[+] These are the available reverse shells", file=stream)
        for line in set(sreverse_shells):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))

        print(green + "[+] These are the available process hollowing code snippets", file=stream)
        for line in set(shollowing_snippets):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))
        
        print(green + "[+] These are the available process injectors code snippets", file=stream)
        for line in set(sinjectors_snippets):
            for match in re.finditer(pattern, line):
                print('- ' '%s' % (match.group().replace('`','')))
    except Exception as e: 
        print(e)
        exit(1)

def find_shell(shell_type, bind, reverse, hollowing, injectors):
    """
    Finds and returns the shell type
    """

    pattern = re.compile(r'^```'+shell_type+r"$")

    if bind is True:
        for line in sbind_shells:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type
    
    if reverse is True:
        for line in sreverse_shells:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type

    if hollowing is True:
        for line in shollowing_snippets:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type

    if injectors is True:       
        for line in sinjectors_snippets:
            for match in re.finditer(pattern, line):
                #name = print('%s' % (match.group().replace('`','')))
                return shell_type

def generate_shells(payload, ip, port, block, language, encoding):
    """
    Generates the shells

    - Filename: bind_shells
    - Filename: reverse_shells

    The placeholder in these files are $ip and $port

    Easy, dynamic, scalable, future-proof, and flexible approach:

    - Detect markdown code blocks and print the code that's inside

    encoding: [url_encoding, 
    base64_encoding,
    base32_encoding,
    base16_encoding]
    """

    if language != "":
        print(green + "[+] Generating "+language+" shells")
    else:
        print(green + "[+] Generating shells")

    for md_filename in payload:
        code_blocks = parse.parse_file(
            md_filename,
            ip = ip,
            port = port,
            parse_blocks = block,
            language = language
        )

        # Print a separator between code blocks
        # Separate each code block with a new line hence ("\n\n")
        cmd = ("\n\n----------------NEXT CODE BLOCK----------------\n\n"
        .join([cb.code for cb in code_blocks]))

        cmd_encode = ("\n".join([cb.code for cb in code_blocks]))

        if encoding[0] is True:
            print(blue + "[+] Adding URL Encoding", file=stream)
            encoders.url_encode(cmd_encode)
        elif encoding[1] is True:
            print(cyan + "[+] Answer with: Windows or Nix", file=stream)
            question = input("[!] Do you want to base64 encode for Windows or Nix? ")
            if question == ("Windows"):
                print(blue + "[+] Adding Windows UTF-16LE base64 Encoding", file=stream)
                print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one-by-one.", file=stream)
                encoders.windows_base64(cmd_encode)
            elif question == ("Nix"):
                print(blue + "[+] Adding Nix base64 Encoding", file=stream)
                print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one-by-one.", file=stream)
                encoders.base64_encode(cmd_encode)
            else:
                print(red + "[-] Error: The answer must be either Windows or Nix", file=stream)
                exit(0)
        elif encoding[2] is True:
            print(blue + "[+] Adding base32 Encoding", file=stream)
            print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one-by-one.", file=stream)
            encoders.base32_encode(cmd_encode)
        elif encoding[3] is True:
            print(blue + "[+] Adding base16 Encoding", file=stream) 
            print(magenta + "[!] Warning: If the code contains multiple lines, decode each line one-by-one.", file=stream)
            encoders.base16_encode(cmd_encode)
        else:
            print(cmd)

def print_snippets(snippets, ip, port, block, language):
    """
    Print code snippets

    Replace $ip and $port placeholders
    """

    for md_filename in snippets:
        code_blocks = parse.parse_file(
            md_filename,
            ip = ip,
            port = port,
            parse_blocks = block,
            language = language
        )
        # Separate each code block with a new line hence ("\n\n")
        cmd = ("\n\n----------------NEXT CODE BLOCK----------------\n\n"
        .join([cb.code for cb in code_blocks]))
        print(cmd)


def main():
    """
    Parse the arguments and decides the program flow

    This is also the help menu

    store_true = Boolean ( True (used) or False (not used) )

    Generate bind shells and/or reverse shells.
    """
    parser = argparse.ArgumentParser(description=f"""

 ██████  ███████ ██   ██ ███████ ██      ██      
██       ██      ██   ██ ██      ██      ██      
██   ███ ███████ ███████ █████   ██      ██      
██    ██      ██ ██   ██ ██      ██      ██      
 ██████  ███████ ██   ██ ███████ ███████ ███████ 


Generate bind shells and/or reverse shells with style

            Version: 1.1
            Author: nozerobit
            Twitter: @nozerobit
""", 
    formatter_class=RawTextHelpFormatter, add_help=False)
    parser._optionals.title = "Options"
    parser.add_argument('-i', '--ip', metavar="<IP ADDRESS>", action='store', dest='ip', type=str, help='Specify the IP address')
    parser.add_argument('-p', '--port', metavar="<PORT NUMBER>", action='store', dest='port', type=int, help='Specify the port number')
    parser.add_argument('-s', '--shell',  metavar="<SHELL TYPE>", action='store', default='', dest='shell', type=str, help='Specify a shell type (python, nc, bash, etc)')

    # Payload Type
    payload_arg = parser.add_argument_group('Payload Types')
    payload_arg.add_argument("-r", "--reverse", action="store_true", dest='reverse',
                             help="Victim communicates back to the attacking machine")
    payload_arg.add_argument("-b", "--bind", action="store_true", dest='bind', help="Open up a listener on the victim machine")

    # Snippets Type
    snippets_arg = parser.add_argument_group('Snippets Types')
    snippets_arg.add_argument("--hollowing", action="store_true", dest='hollowing',
                             help="Print process hollowing code snippets")
    snippets_arg.add_argument("--injector", action="store_true", dest='injector', help="Print process injector code snippets")
    
    # Encodings Options
    encodings = parser.add_argument_group('Encoding Options')
    encodings.add_argument("--base64", action="store_true", required=False, help="Add base64 encoding")
    encodings.add_argument("--base32", action="store_true", required=False, help="Add base32 encoding")
    encodings.add_argument("--base16", action="store_true", required=False, help="Add base16 encoding")
    encodings.add_argument("--url", action="store_true", required=False, help="Add URL encoding")

    # Obfuscation Options
    #obfuscation = parser.add_argument_group("Obfuscation Options")
    #obfuscation.add_argument("--ipfuscate", action="store_true", required=False, help="Obfuscate IP address")
    #obfuscation.add_argument("--obfuscatel", action="store_true", default=False, required=False, help="Obfuscate very little")

    # Markdown Options
    markdown = parser.add_argument_group("Markdown Options")
    markdown.add_argument("--no-block", action="store_true", default = False, help="Skip ```\ncode\nblocks\n``` while parsing")
    #markdown.add_argument("--language", "-l", default="", help="Filter the blocks by ```language\ncode\ncode\n```")
    #markdown.add_argument("--debug", default=False, action="store_true", help="Show debug output")

    # Assistance / Help
    help_arg = parser.add_argument_group('Help Options')
    help_arg.add_argument('-l', '--list', action='store_true', help='List the available shell types')
    help_arg.add_argument('-a', '--advice', action='store_true', dest='advice', help='Print advice and tips to get connections')
    help_arg.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit') 

    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    args = parser.parse_args()

    # Options
    ip = args.ip
    port = args.port
    shell = args.shell
    # Payloads
    reverse = args.reverse
    bind = args.bind
    # Code Snippets
    hollowing = args.hollowing
    injectors = args.injector
    # Encodings
    base64_encoding = args.base64
    base32_encoding = args.base32
    base16_encoding = args.base16
    url_encoding = args.url
    # Obfuscation
    #ip_ob = args.ipfuscate
    #little_ob = args.obfuscatel
    # Markdown
    block = not args.no_block
    #language = args.language
    #debug = args.debug
    # Help
    advice = args.advice
    shell_list = args.list

    # Encodings List
    all_encodings = [url_encoding, 
    base64_encoding,
    base32_encoding,
    base16_encoding]

    #if debug:
    #    pprint(args)

    if advice is True:
        print("""
Advice: The obvious things
Tips: The not so obvious things

Before: Verify for defensive mechanism and devices such as:
    - Firewalls (Software & Hardware)
    - IDS/IPS (Software & Hardware)
    - System Rules
    - AVs/EDRs

1. Advice: Make sure that the port is not blocked
2. Advice: Make sure that you're using the correct IP address and that's active/up.
3. Advice: Make sure that you're using the correct port and that's active/listening for connections.
4. Advice: Make sure that the language or tool is installed in the target system.
5. Advice: Make sure that there's an existing shell (bash, sh, zsh, fish, rbash, etc).
6. Tip: When using a reverse shell try to specify a listening port that's open externally
    - For example, if you find that port 443 is open but you try to establish a connection on port 9993 and you don't get a connection back,
        then most likely a software/host firewall is blocking it. Therefore, always try ports that are externally open first.
7. Tip: When a reverse shell fails try to encode it to bypass potential filters.
8. Tip: When a bind shell fails, verify that there are no middle devices such as IDS/IPS, hardware/software firewall, or system rules that avoid ports from being in the listening state.
9. Tip: When there's a black list and a white list. Enumerate the black list first and then the white list.
    - After taking notes of the allowed words or characters (white list), try to manually build a command or code. 
10. Tip: If there's an AV/EDR then we should encode, encrypt, and overall try to obfuscate the command/code so that's not detected.
            """)
        exit(0)

    if shell_list is True:
        list_shells()
        exit(0)

    if ip is not None and port is not None:
        verify_ip(ip)
        verify_port(port)
    else:
        print(yellow + "[!] Please specify an IP address and a port number, use the option -h,--help", file=stream)
        exit(1)

    '''
    if bind is False and reverse is False:
        print(red + "[-] Please use either --bind or --reverse options", file=stream)
        exit(1)
    '''

    if bind is True and reverse is True:
        print(red + "[-] Can't use both --bind and --reverse options", file=stream)
        exit(1)

    if ((url_encoding==True and base64_encoding==True) or (url_encoding==True and base32_encoding==True)):
        print(red + "[-] Can't use multiple encodings at the same time", file=stream)
        exit(1)
        
    if ((url_encoding==True and base16_encoding==True) or (base32_encoding==True and base16_encoding==True)):
        print(red + "[-] Can't use multiple encodings at the same time", file=stream)
        exit(1)

    if ((base64_encoding==True and base32_encoding==True) or (base64_encoding==True and base16_encoding==True)):
        print(red + "[-] Can't use multiple encodings at the same time", file=stream)
        exit(1)

    if ((bind==True and hollowing==True) or (bind==True and injectors==True)):
        print(red + "[-] Can't use a payload type and a code snippet type at the same time", file=stream)
        exit(1)

    if ((reverse==True and hollowing==True) or (reverse==True and injectors==True)):
        print(red + "[-] Can't use a payload type and a code snippet type at the same time", file=stream)
        exit(1)

    if shell is not None and shell != "":
        shell_type = find_shell(shell, bind, reverse, hollowing, injectors)
        #print(f'{shell_type}')
        if shell_type is not None and shell_type != "":
            print(green + "[+] Shell type is valid", file=stream)
        else:
            print(red + "[-] Shell type doesn't exists", file=stream)
            exit(1)

    if bind is True:
        print(green + "[+] Preparing bind shells", file=stream)
        generate_shells(bind_shells, ip, port, block, shell, all_encodings)

    if reverse is True:
        print(green + "[+] Preparing reverse shells", file=stream)
        generate_shells(reverse_shells, ip, port, block, shell, all_encodings)

    if hollowing is True:
        print(green + "[+] Preparing process hollowing code snippets", file=stream)
        print_snippets(hollowing_snippets, ip, port, block, shell)
    
    if injectors is True:
        print(green + "[+] Preparing process injectors code snippets", file=stream)
        print_snippets(injectors_snippets, ip, port, block, shell)

if __name__ == "__main__":
    main()
