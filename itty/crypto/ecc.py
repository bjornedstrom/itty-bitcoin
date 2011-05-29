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

"""Elliptic Curve cryptography."""

# TODO: This code is using ctypes and is not very portable. The two
# crypto libraries for Python (that I'm aware of, M2Crypto and
# pyOpenSSL) based on OpenSSL lack functionality needed for key
# management, so this will do for now.
import ctypes
import ctypes.util
libcrypto_path = ctypes.util.find_library('crypto')
if libcrypto_path is None:
    raise ImportError('this software requires OpenSSL libcrypto')
libcrypto = ctypes.CDLL(libcrypto_path)


__version__ = '0.0.1'
__author__ = 'Bjorn Edstrom <be@bjrn.se>'


# From openssl/obj_mac.h
CURVES = {
    'secp112r1': 704,
    'secp112r2': 705,
    'secp128r1': 706,
    'secp128r2': 707,
    'secp160k1': 708,
    'secp160r1': 709,
    'secp160r2': 710,
    'secp192k1': 711,
    'secp224k1': 712,
    'secp224r1': 713,
    'secp256k1': 714,
    'secp384r1': 715,
    'secp521r1': 716,
    'sect113r1': 717,
    'sect113r2': 718,
    'sect131r1': 719,
    'sect131r2': 720,
    'sect163k1': 721,
    'sect163r1': 722,
    'sect163r2': 723,
    'sect193r1': 724,
    'sect193r2': 725,
    'sect233k1': 726,
    'sect233r1': 727,
    'sect239k1': 728,
    'sect283k1': 729,
    'sect283r1': 730,
    'sect409k1': 731,
    'sect409r1': 732,
    'sect571k1': 733,
    'sect571r1': 734
    }


class ECKey(object):
    """A public/private key pair for ECC."""

    def __init__(self, curve, public=None, private=None):
        """Create the elliptic curve by name.

           public and private conveniently call set_public and
           set_private respectively.
        """

        self.pkey = ctypes.c_void_p(libcrypto.EC_KEY_new_by_curve_name(CURVES[curve]))

        self.public = None
        if public:
            self.set_public(public)

        self.private = None
        if private:
            self.set_private(private)

    def generate(self):
        """Generate keys. Does not return anything, just sets the keys
           in the current instance.
        """

        # TODO: Disabled until I've looked into whether or not the
        # openssl random number generator is actually correctly
        # seeded.
        raise NotImplementedError('method disabled - see code for details')

        libcrypto.EC_KEY_generate_key(self.pkey)
        self.public = self.get_public()
        self.private = self.get_private()

    def set_public(self, public):
        """Sets the public key. public is a byte string.
        """

        pbegin = ctypes.create_string_buffer(public)
        ptr = ctypes.pointer(pbegin)
        libcrypto.o2i_ECPublicKey(ctypes.byref(self.pkey), ctypes.byref(ptr), len(public))
        self.public = public

    def get_public(self):
        """Gets the public key as a byte string.
        """

        nSize = libcrypto.i2o_ECPublicKey(self.pkey, None)
        pbegin = ctypes.create_string_buffer(nSize)
        ptr = ctypes.pointer(pbegin)
        assert nSize == libcrypto.i2o_ECPublicKey(self.pkey, ctypes.byref(ptr))
        return pbegin.raw

    def set_private(self, private):
        """Sets the private key. private is a byte string.
        """

        pbegin = ctypes.create_string_buffer(private)
        ptr = ctypes.pointer(pbegin)
        libcrypto.d2i_ECPrivateKey(ctypes.byref(self.pkey), ctypes.byref(ptr), len(private))
        self.private = private

    def get_private(self):
        """Gets the private key as a byte string.
        """

        nSize = libcrypto.i2d_ECPrivateKey(self.pkey, None)
        pbegin = ctypes.create_string_buffer(nSize)
        ptr = ctypes.pointer(pbegin)
        assert nSize == libcrypto.i2d_ECPrivateKey(self.pkey, ctypes.byref(ptr))
        return pbegin.raw


class ECDSA(ECKey):
    """Elliptic Curve DSA.
    """

    def sign(self, buf):
        """Signs the byte string buf using EC DSA.

           Note that buf may be an arbitrary string, it is up to the
           caller to make this be suitable for signing (such as a
           hash).

           Returns the signature.
        """

        if self.public is None or self.private is None:
            raise ValueError('keys must be set')

        pchSig = ctypes.create_string_buffer(1024)
        nSize = ctypes.c_int(0)

        hb = ctypes.create_string_buffer(buf)
        assert 1 == libcrypto.ECDSA_sign(0, ctypes.byref(hb), len(buf), pchSig, ctypes.byref(nSize), self.pkey)
        return pchSig.raw[0:nSize.value]

    def verify(self, buf, sig):
        """Verifies the byte string buf against the signature sig.

           Returns True if the signature verifies, False otherwise.
        """

        if self.public is None or self.private is None:
            raise ValueError('keys must be set')

        hb = ctypes.create_string_buffer(buf)
        sigb = ctypes.create_string_buffer(sig)
        return libcrypto.ECDSA_verify(0, ctypes.byref(hb), len(buf), ctypes.byref(sigb), len(sig), self.pkey) == 1


if __name__ == '__main__':
    k = ECDSA('secp256k1')
    test_pub = [0x04,0x26,0x88,0x89,0x2b,0xd4,0x77,0xca,0x9a,0x96,0xd8,0x8e,0x3c,0xca,0x15,0xdb,0xde,0x65,0xf7,0x92,0xa6,0x3c,0x3b,0x38,0xdd,0xe4,0xf1,0xf8,0x97,0xec,0x8e,0x06,0x98,0xc2,0x6a,0x3c,0x22,0xcc,0x25,0x0c,0x41,0x1d,0xc0,0x0d,0xfc,0x18,0x40,0xcd,0x15,0xa9,0x17,0x16,0xb5,0xb8,0x4e,0xc1,0xa6,0xec,0x7e,0x3e,0x43,0x1c,0xdb,0x93,0xa6]
    test_pub = ''.join(map(chr, test_pub))
    test_priv = [0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20,0x14,0x2d,0x7e,0x95,0xd0,0x1b,0x3c,0x43,0x1d,0x89,0xbd,0xc0,0x81,0x6d,0x3a,0xc6,0x69,0x15,0xc7,0xb5,0x4d,0x86,0xc0,0x44,0xb3,0xf2,0x8c,0x40,0x12,0x0a,0x2f,0xc6,0xa0,0x81,0xa5,0x30,0x81,0xa2,0x02,0x01,0x01,0x30,0x2c,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x01,0x01,0x02,0x21,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xfc,0x2f,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,0x41,0x04,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,0xfb,0xfc,0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,0xa6,0x85,0x54,0x19,0x9c,0x47,0xd0,0x8f,0xfb,0x10,0xd4,0xb8,0x02,0x21,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41,0x02,0x01,0x01,0xa1,0x44,0x03,0x42,0x00,0x04,0x26,0x88,0x89,0x2b,0xd4,0x77,0xca,0x9a,0x96,0xd8,0x8e,0x3c,0xca,0x15,0xdb,0xde,0x65,0xf7,0x92,0xa6,0x3c,0x3b,0x38,0xdd,0xe4,0xf1,0xf8,0x97,0xec,0x8e,0x06,0x98,0xc2,0x6a,0x3c,0x22,0xcc,0x25,0x0c,0x41,0x1d,0xc0,0x0d,0xfc,0x18,0x40,0xcd,0x15,0xa9,0x17,0x16,0xb5,0xb8,0x4e,0xc1,0xa6,0xec,0x7e,0x3e,0x43,0x1c,0xdb,0x93,0xa6]
    test_priv = ''.join(map(chr, test_priv))
    test_tosign = [0x18,0x0a,0xfc,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x1f,0xf1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
    assert len(test_tosign) == 32
    test_tosign = ''.join(map(chr, test_tosign))

    k.set_public(test_pub)
    k.set_private(test_priv)

    assert k.get_public() == test_pub
    assert k.get_private() == test_priv

    sig = k.sign(test_tosign)

    assert k.verify(test_tosign, sig)


    #k2 = ECDSA('secp256k1')
    #k2.generate()
    #sig = k2.sign('abc')
    #assert k2.verify('abc', sig)
