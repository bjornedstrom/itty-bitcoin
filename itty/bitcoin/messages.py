#!/usr/bin/env python
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

import hashlib
import struct

__version__ = '0.0.1'
__author__ = 'Bjorn Edstrom <be@bjrn.se>'


class Stream(object):
    """Simple class that represents an unending stream of bytes.
    """

    def __init__(self, buf=''):
        self.buf = buf

    def push(self, bytes):
        self.buf += bytes

    def pop(self, num):
        buf = self.buf[:num]
        self.buf = self.buf[num:]
        return buf


class StreamReader(object):
    """Read various types from a Stream.
    """

    def __init__(self, stream):
        self.stream = stream
        self.n = 0

    def _buf(self, n):
        data = self.stream.buf[self.n:self.n+n]
        self.n += n
        return data

    def uint8_t(self):
        return ord(self._buf(1))

    # TODO: Handle failure (even if below doesn't parse, we still
    # advance the pointer)
    def uint16_t(self):
        return struct.unpack('<H', self._buf(2))[0]

    def uint32_t(self):
        return struct.unpack('<L', self._buf(4))[0]

    def uint64_t(self):
        return struct.unpack('<Q', self._buf(8))[0]

    def var_int(self):
        pre = ord(self.stream.buf[self.n:self.n+1])
        if pre < 0xfd:
            self.n += 1
            return pre
        elif pre == 0xfd:
            self.n += 1
            return self.uint16_t()
        elif pre == 0xfe:
            self.n += 1
            return self.uint32_t()
        elif pre == 0xff:
            self.n += 1
            return self.uint64_t()

    def net_addr(self):
        services = self.uint64_t()
        ip = self.char(16)
        port = self.uint16_t()
        ipv4 = ip[-4:]
        ip = '%d.%d.%d.%d' % tuple(map(ord, ipv4))
        return (ip, port)

    def string(self):
        return self.char(self.var_int())

    def char(self, n):
        return self._buf(n)

    def commit(self):
        """Commit the reads, advancing the buffer in the underlying
           Stream.
        """

        self.stream.pop(self.n)


class StreamWriter(object):
    """Write types to a stream.
    """

    def __init__(self, stream):
        self.stream = stream
        self.buf = ''

    def uint8_t(self, n):
        assert 0 <= n <= 255
        self.buf += chr(n)

    def uint16_t(self, n):
        assert 0 <= n <= 0xffff
        self.buf += struct.pack('<H', n)

    def uint32_t(self, n):
        assert 0 <= n <= 0xffffffff
        self.buf += struct.pack('<L', n)

    def uint64_t(self, n):
        assert 0 <= n <= 2**64-1
        self.buf += struct.pack('<Q', n)

    def var_int(self, n):
        if n < 0xfd:
            self.uint8_t(n)
        elif n < 0xffff:
            self.uint8_t(0xfd)
            self.uint16_t(n)
        elif n < 0xffffffff:
            self.uint8_t(0xfe)
            self.uint32_t(n)
        elif n < 2**64-1:
            self.uint8_t(0xff)
            self.uint64_t(n)

    def net_addr(self, (ip, port)):
        self.uint64_t(1) # TODO: Services other than 1?
        self.char('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff')
        octets = map(int, ip.split('.'))
        for i in range(4):
            self.uint8_t(octets[i])
        self.uint16_t(port)

    def string(self, s):
        self.var_int(len(s))
        self.buf += s

    def char(self, s):
        self.buf += s

    def commit(self):
        """Commit (actually write out) the written data to the stream.
        """

        self.stream.push(self.buf)


class Message(object):
    """Base class for BitCoin protocol messages.
    """

    def __init__(self, name, *args, **kwargs):
        """TODO: Document me!
        """

        self.name = name
        self.test = kwargs.get('test', None)

    @staticmethod
    def parse(stream):
        """Parse out the next message from Stream.
        """

        ctx = StreamReader(stream)

        magic = ctx.char(4)

        assert magic in ('\xfa\xbf\xb5\xda', '\xF9\xBE\xB4\xD9')

        name = ctx.char(12)
        name = name.strip('\x00')
        length = ctx.uint32_t()
        checksum = None
        if name not in ('version', 'verack'):
            checksum = ctx.char(4)
        payload = ctx.char(length)

        if checksum is not None:
            H = lambda s: hashlib.sha256(s).digest()
            if checksum != H(H(payload))[:4]:
                raise ValueError('checksum failure')

        #print repr(magic)
        #print repr(name)
        #print length
        #print repr(payload)

        msg = MESSAGES.get(name).parse(Stream(payload))

        ctx.commit()

        return msg

    def payload(self):
        raise NotImplementedError('payload not implemented for message')

    def pack(self):
        """Pack the message to a byte string.
        """

        stream = Stream()
        ctx = StreamWriter(stream)

        if self.test:
            ctx.char('\xFA\xBF\xB5\xDA')
        else:
            ctx.char('\xF9\xBE\xB4\xD9')

        ctx.char(self.name)
        ctx.char('\x00' * (12 - len(self.name)))

        payload = self.payload()

        #print repr(payload)

        ctx.uint32_t(len(payload))

        if self.name not in ('version', 'verack'):
            H = lambda s: hashlib.sha256(s).digest()
            ctx.char(H(H(payload))[:4]) # TODO: Checksum

        ctx.char(payload)

        ctx.commit()

        return ctx.buf


# Messages implemented below

class VersionMessage(Message):
    def __init__(self, *args, **kwargs):
        Message.__init__(self, 'version', *args, **kwargs)

    @staticmethod
    def parse(stream):
        ctx = StreamReader(stream)

        msg = VersionMessage()
        msg.version = ctx.uint32_t()
        msg.services = ctx.uint64_t()
        msg.timestamp = ctx.uint64_t()
        msg.addr_me = ctx.net_addr()
        msg.addr_you = ctx.net_addr()
        msg.nonce = ctx.uint64_t()
        msg.sub_version_num = ctx.string()
        msg.start_height = ctx.uint32_t()

        return msg

    def payload(self):
        stream = Stream()
        ctx = StreamWriter(stream)

        ctx.uint32_t(self.version)
        ctx.uint64_t(self.services)
        ctx.uint64_t(self.timestamp)
        ctx.net_addr(self.addr_me)
        ctx.net_addr(self.addr_you)
        ctx.uint64_t(self.nonce)
        ctx.string(self.sub_version_num)
        ctx.uint32_t(self.start_height)
        ctx.commit()

        return stream.buf

    def __repr__(self):
        return '<VersionMessage version=%d services=%d timestamp=%d addr_me=%s addr_you=%s, nonce=%d, sub_version_num=%r, start_height=%d>' % (self.version, self.services, self.timestamp, self.addr_me, self.addr_you, self.nonce, self.sub_version_num, self.start_height)


class VerAckMessage(Message):
    def __init__(self, *args, **kwargs):
        Message.__init__(self, 'verack', *args, **kwargs)

    @staticmethod
    def parse(stream):
        ctx = StreamReader(stream)

        msg = VerAckMessage()

        return msg

    def payload(self):
        return ''

    def __repr__(self):
        return '<VerAckMessage>'


# Mapping from message name to classes.
MESSAGES = {
    'version': VersionMessage,
    'verack': VerAckMessage,
}



if __name__ == '__main__':

    # Some test messages...
    s0 = '\xfa\xbf\xb5\xdaversion\x00\x00\x00\x00\x00U\x00\x00\x00d}\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xc6\xe4\xe3M\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xffYYYY\xa2\x82\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xffX\xbe\xbe\xbeG\x9d\xb7\xf0i\xbc\x14\xb2\x816\x00\xf5V\x00\x00'
    s1 = '\xfa\xbf\xb5\xdaverack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    stream = Stream(s0 + s1)

    msg1 = Message.parse(stream)
    msg2 = Message.parse(stream)

    msg1.test = True
    assert msg1.pack() == s0
    msg2.test = True
    assert msg2.pack() == s1
