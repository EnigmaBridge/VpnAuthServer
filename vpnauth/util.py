#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import stat
import json
import hashlib
import base64
import collections
import datetime

import errno
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import errors


PAYLOAD_ENC_TYPE = 'AES-256-GCM-SHA256'


def protect_payload(payload, config):
    """
    Builds a new JSON payload
    :param payload:
    :param config:
    :return:
    """
    js = json.dumps(payload)
    key = make_key(config.enc_password)

    iv, ciphertext, tag = encrypt(key, plaintext=js)

    ret = collections.OrderedDict()
    ret['enctype'] = PAYLOAD_ENC_TYPE
    ret['iv'] = base64.b64encode(iv)
    ret['tag'] = base64.b64encode(tag)
    ret['payload'] = base64.b64encode(ciphertext)
    return ret


def unprotect_payload(payload, config):
    """
    Processes protected request payload
    :param payload:
    :param config:
    :return:
    """
    if payload is None:
        raise ValueError('payload is None')
    if 'enctype' not in payload:
        raise ValueError('Enctype not in payload')
    if payload['enctype'] != PAYLOAD_ENC_TYPE:
        raise ValueError('Unknown payload protection: %s' % payload['enctype'])

    key = make_key(config.enc_password)
    iv = base64.b64decode(payload['iv'])
    tag = base64.b64decode(payload['tag'])
    ciphertext = base64.b64decode(payload['payload'])
    plaintext = decrypt(key=key, iv=iv, ciphertext=ciphertext, tag=tag)

    js = json.loads(plaintext)
    return js


def make_or_verify_dir(directory, mode=0o755, uid=0, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not check_permissions(directory, mode, uid):
                raise errors.Error(
                    "%s exists, but it should be owned by user %d with"
                    "permissions %s" % (directory, uid, oct(mode)))
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def make_key(key):
    """
    Returns SHA256 key
    :param key:
    :return:
    """
    h = hashlib.sha256()
    h.update(key)
    return h.digest()


def encrypt(key, plaintext, associated_data=None):
    """
    Uses AES-GCM for encryption
    :param key:
    :param plaintext:
    :param associated_data:
    :return: iv, ciphertext, tag
    """

    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)


def decrypt(key, iv, ciphertext, tag, associated_data=None):
    """
    AES-GCM decryption
    :param key:
    :param associated_data:
    :param iv:
    :param ciphertext:
    :param tag:
    :return:
    """
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    if associated_data is not None:
        decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


def silent_close(c):
    # noinspection PyBroadException
    try:
        if c is not None:
            c.close()
    except:
        pass


def unix_time_millis(dt):
    if dt is None:
        return None
    return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds()


