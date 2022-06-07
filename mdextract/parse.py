import re
from string import Template
from . import CodeBlock


CODE_BLOCK_REGEX = r"""(^```)([\S]+)?\s*
([\s\S]+?)
(^```)"""
"Regex to capture code blocks in the document"

def search_code_block(md_text):
    """Searches md_text with CODE_BLOCK_REGEX"""
    search_regex = CODE_BLOCK_REGEX
    current_pos = 0
    match = True
    code_blocks = []
    while match:
        match = re.search(search_regex, md_text[current_pos:], re.MULTILINE)
        if match:
            cb = CodeBlock(code = match.group(3),
                           start_pos = current_pos + match.start(0),
                           end_pos = current_pos + match.end(0),
                           delim = match.group(1),
                           language = match.group(2))
            current_pos += match.end(0)
            code_blocks.append(cb)
    return code_blocks


def parse_text(md_text, parse_blocks=True, language="") :
    """
    Parses the given text and returns the code blocks delimited by

    ```
    code
    ```

    or

    `code`

    The result is list of CodeBlock objects.

    """

    code_blocks = []

    if parse_blocks:
        code_blocks += search_code_block(md_text)

    if len(language) > 0:
        code_blocks = [cb for cb in code_blocks if cb.language == language]

    code_blocks = sorted(code_blocks, key=lambda cb: cb.start_pos)

    return code_blocks



def parse_file(filename, ip, port, parse_blocks=True, language=""):
    """Reads the file and returns the code blocks"""

    with open(filename) as payload:
        code_blocks = parse_text(Template(payload.read()).safe_substitute(ip=ip, port=port),
         parse_blocks=parse_blocks, language=language)

    return code_blocks

