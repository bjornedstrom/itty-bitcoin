# -*- coding: utf-8 -*-
#
# Copyright (c) 2011 Björn Edström <be@bjrn.se>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Base58 as implemented in BitCoin."""

import hashlib


__version__ = '0.0.1'
__author__ = 'Bjorn Edstrom <be@bjrn.se>'


__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(value):
    """Encode a string using Base58, as implemented in bitcoin.
    """

    if value == '':
        return ''

    encoded = ''

    leading_zeroes = 0
    for c in value:
        if c == '\x00':
            leading_zeroes += 1
        else:
            break

    integer = 0
    for c in value:
        integer <<= 8
        integer |= ord(c)

    if integer:
        value = integer
        while value >= 58:
            div, mod = divmod(value, 58)
            encoded = encoded + __b58chars[mod]
            value = div
        encoded = encoded + __b58chars[value]

    return '1' * leading_zeroes + ''.join(reversed(encoded))


def b58decode(coded):
    """Decode a Base58 encoded string.
    """

    if coded == '':
        return ''

    integer = 0
    for c in coded:
        i = __b58chars.index(c)
        integer *= 58
        integer += i

    value = integer
    decoded = ''

    if value:
        while value >= 256:
            div, mod = divmod(value, 256)
            decoded = chr(mod) + decoded
            value = div
        decoded = chr(value) + decoded

    leading_zeroes = 0
    for c in coded:
        if c == '1':
            leading_zeroes += 1
        else:
            break

    return '\x00' * leading_zeroes + decoded


def double_sha256(s):
    a = hashlib.sha256(s).digest()
    b = hashlib.sha256(a).digest()
    return b


def b58encode_check(value):
    """Encode a string using Base58, with a checksum. See
    b58decode_check for more information.
    """

    h = double_sha256(value)[0:4]
    return b58encode(value + h)


def b58decode_check(value):
    """Decode a Base58 encoded string that has a checksum. If the
    checksum fails, it throws ValueError.

    Returns the encoded string, minus the checksum, on success.
    """

    data_with_hash = b58decode(value)
    data, hash = data_with_hash[:-4], data_with_hash[-4:]
    if double_sha256(data)[0:4] != hash:
        raise ValueError('checksum failed')
    return data


if __name__ == '__main__':
    # encode
    assert b58encode('') == ''
    assert b58encode('\x00') == '1'
    assert b58encode('\x00\x00') == '11'
    assert b58encode('\xff') == '5Q'
    assert b58encode('\x00\xff') == '15Q'
    assert b58encode('\xff\x00') == 'LQX'
    assert b58encode('\x00\x00\xff') == '115Q'
    assert b58encode('abcd') == '3VNr6P'

    # decode
    assert b58decode('3VNr6P') == 'abcd'
    assert b58decode('115Q') == '\x00\x00\xff'
    assert b58decode('LQX') == '\xff\x00'
    assert b58decode('15Q') == '\x00\xff'
    assert b58decode('5Q') == '\xff'
    assert b58decode('11') == '\x00\x00'
    assert b58decode('1') == '\x00'
    assert b58encode('') == ''

    # encode_hash
    assert b58encode_check('') == '3QJmnh'
    assert b58encode_check('\x00') == '1Wh4bh'

    # decode_hash
    assert b58decode_check('3QJmnh') == ''
    assert b58decode_check('1Wh4bh') == '\x00'

    try:
        assert b58decode_check('1W') == '\x00'
    except ValueError:
        pass
    except:
        raise
