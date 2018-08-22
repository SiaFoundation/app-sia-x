#!/usr/bin/env python
"""
*******************************************************************************
*
*  (c) 2016 Ledger
*  (c) 2018 Nebulous
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import base64
import struct
import sys

parser = argparse.ArgumentParser()
parser.add_argument('txn', type=str, help="path to binary-encoded transaction")
parser.add_argument('sigIndex', type=int, help="index of signature to calculate")
parser.add_argument('--index', type=int, help="key index to sign with (if not provided, hash will be displayed but not signed)")
args = parser.parse_args()

signing = args.index != None

if signing:
	p2 = 0x01
else:
	p2 = 0x00
	args.index = 0

with open(args.txn, 'r') as txn_file:
    msg = txn_file.read()

msg = struct.pack("<I", int(args.index)) + struct.pack("<H", int(args.sigIndex)) + msg

try:
	dongle = getDongle(True)
	offset = 0
	while offset <> len(msg):
		if (len(msg) - offset) > 255:
			chunk = msg[offset : offset + 255]
		else:
			chunk = msg[offset:]
		if (offset == 0):
			p1 = 0x00
		else:
			p1 = 0x80
		apdu = "e004".decode('hex') + chr(p1) + chr(p2) + chr(len(chunk)) + chunk
		result = dongle.exchange(bytes(apdu))
		offset += len(chunk)
except CommException as e:
	if (e.sw == 0x6985):
		print "User refused to sign"
	else:
		print hex(e.sw)
		print "Unknown exception -- Is the Sia wallet app is running?"
	sys.exit(1)
except Exception as e:
	print e, type(e)
	print "I/O error -- Is your Nano S connected?"
	sys.exit(1)

if signing:
	print "Signature: " + base64.standard_b64encode(result[:64])
else:
	print "Hash: " + str(result[:32]).encode('hex')
