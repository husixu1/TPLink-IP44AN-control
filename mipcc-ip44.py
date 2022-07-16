#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import tty
import argparse
from functools import partial

import base64
import json
import sys

import requests
import rsa
import logging

log = logging.getLogger(__name__)


# ref https://github.com/gyje/tplink_encrypt/blob/9d93c2853169038e25f4e99ba6c4c7b833d5957f/tpencrypt.py
def tp_encrypt(password):
    a = 'RDpbLfCPsJZ7fiv'
    c = 'yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW '
    b = password
    e = ''
    f, g, h, k, l = 187, 187, 187, 187, 187
    n = 187
    g = len(a)
    h = len(b)
    k = len(c)
    if g > h:
        f = g
    else:
        f = h
    for p in list(range(0, f)):
        n = l = 187
        if p >= g:
            n = ord(b[p])
        else:
            if p >= h:
                l = ord(a[p])
            else:
                l = ord(a[p])
                n = ord(b[p])
        e += c[(l ^ n) % k]
    return e


# ref https://www.cnblogs.com/masako/p/7660418.html
def convert_rsa_key(s):
    b_str = base64.b64decode(s)
    if len(b_str) < 162:
        return False
    hex_str = b_str.hex()
    m_start = 29 * 2
    e_start = 159 * 2
    m_len = 128 * 2
    e_len = 3 * 2
    modulus = hex_str[m_start:m_start + m_len]
    exponent = hex_str[e_start:e_start + e_len]
    return modulus, exponent


def rsa_encrypt(string, pubkey):
    key = convert_rsa_key(pubkey)
    modulus = int(key[0], 16)
    exponent = int(key[1], 16)
    rsa_pubkey = rsa.PublicKey(modulus, exponent)
    crypto = rsa.encrypt(string.encode(), rsa_pubkey)
    return base64.b64encode(crypto)


def get_stok(url, username, password):
    # encrypt tp
    log.debug("--encrypt password by tp")
    tp_password = tp_encrypt(password)
    log.debug("tp_password: %s", tp_password)

    # login
    d = {
        "method": "do",
        "login": {
            "username": username,
            "password": tp_password
        }
    }
    log.debug("--login")
    j = post_data(url, json.dumps(d))
    stok = j["stok"]
    return stok


def post_data(base_url, data, stok=""):
    url = base_url + (("/stok=" + stok + "/ds") if stok else "")
    log.debug("post: %s data: %s", url,  data)
    r = requests.post(url, data)
    log.debug("response: %s %s", str(r.status_code), str(r.json()))
    return r.json()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-u', '--username', type=str, default='admin', help="Username")
    parser.add_argument(
        '-p', '--password', type=str, default='admin', help="Password")
    parser.add_argument(
        '-a', '--addr', type=str, default='http://192.168.1.10:80', help="Address")
    parser.add_argument(
        '-d', '--data', help="data to post")
    parser.add_argument(
        '-i', '--interactive', action='store_true',  help="Interative PTZ mode")
    parser.add_argument(
        '-v', '--verbose', action='store_true',  help="Debug mode")
    args = parser.parse_args()

    print(f"username: {args.username}")
    print(f"password: {args.password}")
    print(f"address: {args.addr}")
    print(f"data: {args.data}")

    if args.verbose:
        logging.basicConfig(level='DEBUG')

    def send(data):
        post_data(args.addr, data, get_stok(
            args.addr, args.username, args.password))

    key_mappings = {
        'q': (partial(exit, 0), "quit"),
        'w': (partial(send, '{"method":"do","ptz":{"continuous_move":{"velocity_tilt":"1.0000000","timeout":"500"}}}'), "up"),
        's': (partial(send, '{"method":"do","ptz":{"continuous_move":{"velocity_tilt":"-1.0000000","timeout":"500"}}}'), "down"),
        'a': (partial(send, '{"method":"do","ptz":{"continuous_move":{"velocity_pan":"-1.0000000","timeout":"500"}}}'), "left"),
        'd': (partial(send, '{"method":"do","ptz":{"continuous_move":{"velocity_pan":"1.0000000","timeout":"500"}}}'), "right"),
        'x': (partial(send, '{"method":"do","ptz":{"stop":{"pan":"1","tilt":"1","zoom":"1"}}}'), "stop"),
    }

    if args.interactive:
        tty.setcbreak(sys.stdin)
        while True:
            for key, val in key_mappings.items():
                print(f"[{key}]: {val[1]}  ", end='')
            print("[1-9]: go to preset point 1-9")

            key = sys.stdin.read(1)
            if key in key_mappings:
                key_mappings[key][0]()
            elif '1' <= key <= '9':
                send('{"method":"do","preset":{"goto_preset": {"id": "' + key + '"}}}')
            else:
                print(f"Unknown key {key}")
    else:
        send(args.data)
