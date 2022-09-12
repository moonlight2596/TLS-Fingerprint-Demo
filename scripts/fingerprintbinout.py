#!/usr/bin/env python2

# XXX Recalculate the sizes for int's instead of char arrays
# XXX Work out how to pre-populate as ints instead of char arrays

import argparse
import json
import sys
import re
import binascii			# Needed for the binary option


def read_file(filename):
	jfile = []
	with open(filename) as f:
		for line in f:
			jfile.append(json.loads(line))
	return jfile

# Take Single or multi byte strings or mixed: "0x00 0x0000 0x00"
# and return entirely single byte version: "0x00 0x00 0x00 0x00" in binary format
def byte_to_bin(in_string):
	in_string = in_string.replace(' ', '')
	in_string = in_string.replace('0x', '')
	out_string = binascii.a2b_hex(in_string)
	return out_string


def binary(filename):

	# XXX accounted for 0x00 where 0x0000 is needed, have not looked at 0x0 yet... check this!!

	# XXX Check the mutt signature with the oddly formed compression len to compression thing

	# Build a binary "database", which is actually a pre-compiled'ish struct linked list for use in peoples code
	# Much like the "struct" option but allows more room for indexing/searching and growing as there is no need
	# to parse strings from some flatfile which C is soooooo good at.  Yes yes, this is still file parsing....
	# but (from a C perspective) it's easier file parsing, and this isn't so hard in python to output either.

	# Documenting the file format here, in lieu of proper documentation

	# Byte 0			: binary format version
	# Per fingerprint.....
	# uint16_t			: Fingerprint ID
	# uint16_t		 	: Desc Length
	# Bytes <above>		: Desc
	# uint16_t <next>	: record_tls_version;
	# uint16_t <next>	: tls_version;
	# etc etc etc
	# uint16_t ciphersuite_length
	# uint8_t ciphersuite....
	# uint8_t compression_length
	# uint8_t compression....
	# uint16_t extensions_length
	# uint8_t extensions....
	# uint16_t e_curves_length
	# uint8_t e_curves.....
	# uint16_t sig_alg_length
	# uint8_t sig_alg.....
	# uint16_t ec_point_fmt_length
	# uint8_t ec_point_fmt....


	# Write the version before we itterate through the fingerprints
	outfile = open("tlsfp3.db","w+")
	outfile.write(byte_to_bin("0x00"))

	# Open the JSON file and process each entry (line)
	jfile = read_file(filename)
	objcount = len(jfile)

	for i in jfile:
		# Need to add the ID once this is working XXX
		print "Processing: "+i["desc"]
		# Initialise all the lengths to stop things complaining later.  Oh and other random
		# weirdness.
		desc_len = tls_version_len = ciphersuite_len = compression_len = 0
		extensions_len = e_curves_len = sig_alg_len = ec_point_fmt_len = server_name_len = 0
		record_tls_version_len = 0

		# Start correctly encoding things and writing them to outfile
		temp_data = format(i["id"], '#06x')
		outfile.write(byte_to_bin(temp_data))

		temp_data = len(i["desc"])
		temp_data = format(temp_data, '#06x')
		outfile.write(byte_to_bin(temp_data))

		outfile.write(i["desc"])
		outfile.write(byte_to_bin(i["record_tls_version"]))
		outfile.write(byte_to_bin(i["tls_version"]))
		outfile.write(byte_to_bin(i["ciphersuite_length"]))
		outfile.write(byte_to_bin(i["ciphersuite"]))

		# Compression Length is stored as decimal for some reason (go team)
		# But it's only a one byte value... ccccoooonnnnvvveeeerrrrttttt
		temp_data = len(byte_to_bin(i["compression"].zfill(2)))
		temp_data = format(temp_data, '#04x')
		outfile.write(byte_to_bin(temp_data))

		# OK, carry on as we were...
		outfile.write(byte_to_bin(i["compression"]))

		# We need to calculate extensions_length, because it's not in the JSON file
		# so switcharoo, encode extensions first, then length it, then write... *BOOM*
		temp_data = len(byte_to_bin(i["extensions"]))
		temp_data = format(temp_data, '#06x')
		outfile.write(byte_to_bin(temp_data))
		outfile.write(byte_to_bin(i["extensions"]))

		# And again for the optionals
		if "e_curves" in i:
			temp_data = len(byte_to_bin(i["e_curves"]))
			temp_data = format(temp_data, '#06x')
			outfile.write(byte_to_bin(temp_data))
			outfile.write(byte_to_bin(i["e_curves"]))
		else:
			# Still need to set zero length
			outfile.write(byte_to_bin("0x0000"))

		if "sig_alg" in i:
			temp_data = len(byte_to_bin(i["sig_alg"]))
			temp_data = format(temp_data, '#06x')
			outfile.write(byte_to_bin(temp_data))
			outfile.write(byte_to_bin(i["sig_alg"]))
		else:
			# Still need to set zero length
			outfile.write(byte_to_bin("0x0000"))

		if "ec_point_fmt" in i:
			temp_data = len(byte_to_bin(i["ec_point_fmt"]))
			temp_data = format(temp_data, '#06x')
			outfile.write(byte_to_bin(temp_data))
			outfile.write(byte_to_bin(i["ec_point_fmt"]))
		else:
			# Still need to set zero length
			outfile.write(byte_to_bin("0x0000"))

	# Close the file before the script terminates
	outfile.close()

binary("fingerprints.json")