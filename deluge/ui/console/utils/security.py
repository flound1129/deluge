#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

"""Safety helpers for displaying daemon-controlled text in a terminal."""

_NAMED_CONTROLS = {
    '\b': r'\b',
    '\t': r'\t',
    '\n': r'\n',
    '\f': r'\f',
    '\r': r'\r',
}

_BIDI_CONTROLS = frozenset(
    {
        '\u202a',  # LEFT-TO-RIGHT EMBEDDING
        '\u202b',  # RIGHT-TO-LEFT EMBEDDING
        '\u202c',  # POP DIRECTIONAL FORMATTING
        '\u202d',  # LEFT-TO-RIGHT OVERRIDE
        '\u202e',  # RIGHT-TO-LEFT OVERRIDE
        '\u2066',  # LEFT-TO-RIGHT ISOLATE
        '\u2067',  # RIGHT-TO-LEFT ISOLATE
        '\u2068',  # FIRST STRONG ISOLATE
        '\u2069',  # POP DIRECTIONAL ISOLATE
    }
)


def sanitize_console_text(value) -> str:
    """Return terminal-safe text while preserving ordinary Unicode.

    C0/C1 controls, ANSI escape introducers and bidirectional overrides are
    rendered visibly. Squall color tags in untrusted input are neutralized;
    callers may safely interpolate the result into strings containing trusted
    ``{!color!}`` markup.
    """

    text = str(value)
    safe = []
    for char in text:
        codepoint = ord(char)
        if char in _NAMED_CONTROLS:
            safe.append(_NAMED_CONTROLS[char])
        elif codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            safe.append(f'\\x{codepoint:02x}')
        elif char in _BIDI_CONTROLS:
            safe.append(f'\\u{codepoint:04x}')
        else:
            safe.append(char)

    return ''.join(safe).replace('{!', r'{\!').replace('!}', r'!\}')
