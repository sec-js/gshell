# Change string name
# Change variables names
# Change function names
# Change to hexadecimal
# Remove comments

def ipfuscate(ipv4):
    """
    Obfuscate an IPv4 address by converting it to decimal, hex, 
    octal, or a combination of the three.
    Code borrowed from @vysecurity (https://github.com/vysec/IPFuscator)
    """
    random_generator = random.SystemRandom()

    parts = ip.split('.')
        
    type = random_generator.randint(0, 3)
    decimal = int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])

    if type == 0:
        ip = decimal
    elif type == 1:
        ip = hex(decimal)
    elif type == 2:
        ip = oct(decimal)
    else:
        ip = random_base_ip_gen(parts)

    return str(ip)

def gen_random_var(svars, lang):
    """
    Returns a randomly named variable.
    Author: @capnspacehook
    """
    random_generator = random.SystemRandom()

    if svars:
        minVarLen = 3
        maxVarLen = 6
    else:
        minVarLen = 6
        maxVarLen = 15
    
    randVarLen = random_generator.randint(minVarLen, maxVarLen)
    randomVar = "".join(random_generator.choice(string.ascii_letters) for x in range(randVarLen))

    # Ruby requires that variables start with a lowercase letter
    if lang == "ruby":
        randomVar =  randomVar[0].lower() + randomVar[1:]

    return randomVar

