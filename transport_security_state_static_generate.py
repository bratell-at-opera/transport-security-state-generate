#!/usr/bin/env python

"""This program converts the information
transport_security_state_static.json and
transport_security_state_static.certs into
transport_security_state_static.h. The input files contain information about
public key pinning and HTTPS-only sites that is compiled into Chromium.

Run as:
% go run transport_security_state_static_generate.go transport_security_state_static.json transport_security_state_static.certs

It will write transport_security_state_static.h"""

from __future__ import print_function

import base64
import hashlib
import json
import os
import re
import sys

import pyx509.x509_parse as x509_parse
from pyasn1.codec.der import encoder as der_encoder

class GenerateException(Exception):
    pass

def main():
    """The main entry point. Processes arguments and returns 0 if
    successful or 1 if failed."""
    if len(sys.argv) != 3:
        print("Usage: %s <json file> <certificates file>" % sys.argv[0],
              file=sys.stderr)
        return 1

    try:
        process(sys.argv[1], sys.argv[2])
    except GenerateException as e:
        print("Conversion failed: %s" % str(e), file=sys.stderr)
        return 1

    return 0

def process(jsonFileName, certsFileName):
    with open(jsonFileName) as jsonFile:
        jsonLines = []
        for pseudoJsonLine in jsonFile: # Includes C++ style comments.
            if not pseudoJsonLine.strip().startswith("//"):
                jsonLines.append(pseudoJsonLine)
        jsonBytes = "".join(jsonLines)

    preloaded = json.loads(jsonBytes)

    with open(certsFileName) as certsFile:
        pins = parseCertsFile(certsFile)
    checkDuplicatePins(pins)
    checkCertsInPinsets(preloaded["pinsets"], pins)
    checkNoopEntries(preloaded["entries"])
    checkDuplicateEntries(preloaded["entries"])

    with open("transport_security_state_static.h", "w") as out:
        writeHeader(out)
        writeCertsOutput(out, pins)
        writeHSTSOutput(out, preloaded)
        writeFooter(out)

startOfCert = "-----BEGIN CERTIFICATE"
endOfCert = "-----END CERTIFICATE"
startOfSHA1 = "sha1/"

# nameRegexp matches valid pin names: an uppercase letter followed by zero or
# more letters and digits.
nameRegexp = re.compile("[A-Z][a-zA-Z0-9_]*")

def pemDecode(lines):
    """Decodes a certificate block, assuming it's of the simplest
    possible kind with no headers."""
    result = base64.b64decode("\n".join(lines[1:-1]))
    return result

def parseCertsFile(inFile):
    """parseCertsFile parses |inFile|, in the format of
    transport_security_state_static.certs. See the comments at the top of
    file for details of the format."""

    # States
    PRENAME = 0
    POSTNAME = 1
    INCERT = 2

    lineNo = 0
    pemCert = None
    state = PRENAME
    name = None # String
    pins = []

    for line in inFile:
        line = line.replace("\n", "")
        lineNo += 1
        if not line or line[0] == '#':
            continue

        if state == PRENAME:
            name = line
            if not nameRegexp.match(name):
                raise GenerateException("invalid name on line %d" % lineNo)
            state = POSTNAME
        elif state == POSTNAME:
            if line.startswith(startOfSHA1):
                try:
                    hash = base64.b64decode(line[len(startOfSHA1):])
                except TypeError:
                    raise GenerateException("failed to decode hash on line %d." %
                                    lineNo)
                if len(hash) != 20:
                    raise GenerateException("bad SHA1 hash length on line %d." % lineNo)
                pins.append({"name": name,
                             "spkiHashFunc": "sha1",
                             "spkiHash": hash})
                state = PRENAME
                continue
            if line.startswith(startOfCert):
                pemCert = []
                pemCert.append(line)
                state = INCERT
                continue
            raise GenerateException("line %d, after a name, is not a hash nor a certificate" % lineNo)
        else:
            assert state == INCERT
            pemCert.append(line)
            if not line.startswith(endOfCert):
                continue

            block = pemDecode(pemCert)
            cert = x509_parse.x509_parse(block)
            tbs = cert.tbsCertificate
            subject = tbs.subject
            certName = None
            subj_attrs = subject.get_attributes()
            if "CN" in subj_attrs:
                certName = subj_attrs["CN"][0]
            if not certName:
                certName = subj_attrs["O"][0] + " " + subj_attrs["OU"][0]
            if not matchNames(certName, name):
                raise GenerateException("name failure on line %d:\n%s -> %s" % (
                        lineNo, certName, name))
            # Calculate SHA1 hash.
            h = hashlib.sha1()
            rawsubjectpublickeyinfo = der_encoder.encode(tbs.raw_pub_key_info)
            h.update(rawsubjectpublickeyinfo)
            pins.append({"name": name,
                         "cert": cert,
                         "spkiHashFunc": "sha1",
                         "spkiHash": h.digest()})
            state = PRENAME
    return pins

def matchNames(name, v):
    """matchNames returns true if the given pin name is a reasonable
    match for the given CN."""
    words = name.split(" ")
    if not words:
        print("No words in certificate name", file=sys.stderr)
        return False
    firstWord = words[0]
    if firstWord.endswith(","):
        firstWord = firstWord[:-1]

    if firstWord.startswith("*."):
        firstWord = firstWord[2:]

    pos = firstWord.find(".")
    if pos != -1:
        firstWord = firstWord[:pos]

    pos = firstWord.find("-")
    if pos != -1:
        firstWord = firstWord[:pos]

    if not firstWord:
        printf("First word of certificate name is empty", file=sys.stderr)
        return False

    firstWord = firstWord.lower()
    lowerV = v.lower();
    if not lowerV.startswith(firstWord):
        print("The first word (%s) of the certificate name (%s) is not a prefix of the variable name (%s)." % (firstWord, name, lowerV), file=sys.stderr)
        return False

    for i, word in enumerate(words):
        if word == "Class" and i + 1 < len(words):
            if v.find("Class" + words[i + 1]) == -1:
                print("class specification doesn't appear in the variable name",
                      file=sys.stderr)
                return False
        elif len(word) == 1 and '0' <= word[0] <= '9':
            if v.find(word) == -1:
                print("number doesn't appear in the variable name",
                      file=sys.stderr)
                return False
        elif isImportantWordInCertificateName(word):
            if v.find(word) == -1:
                print(word + " doesn't appear in the variable name",
                      file=sys.stderr)
                return False
    return True

def isImportantWordInCertificateName(w):
    """isImportantWordInCertificateName returns true if w must be
    found in corresponding variable name."""
    return w in ["Universal", "Global", "EV", "G1", "G2", "G3", "G4", "G5"]


def checkDuplicatePins(pins):
    """checkDuplicatePins returns an error if any pins have the same name or the same hash."""
    seenNames = set()
    seenHashes = {}
    for pin in pins:
        name = pin["name"]
        if name in seenNames:
            raise GenerateException("duplicate name: %s" % name)
        seenNames.add(name)
        hash = pin["spkiHash"]
        if hash in seenHashes:
            raise GenerateException("duplicate hash for %s and %s: %s" % (
                    name, seenHashes[hash], hash.encode("hex")))
        seenHashes[hash] = name

def checkCertsInPinsets(pinsets, pins):
    """checkCertsInPinsets returns an error if
        a) unknown pins are mentioned in |pinsets|
        b) unused pins are given in |pins|
        c) a pinset name is used twice"""
    pinNames = set([pin["name"] for pin in pins])
    usedPinNames = set()
    pinsetNames = set()

    for pinset in pinsets:
        name = pinset["name"]
        if name in pinsetNames:
            raise GenerateException("duplicate pinset name: %s" % name)
        pinsetNames.add(name)

        allPinNames = pinset.get("static_spki_hashes", []) + pinset.get("bad_static_spki_hashes", [])
        for pinName in allPinNames:
            if not pinName in allPinNames:
                raise GenerateException("unknown pin: %s" % pinName)
            usedPinNames.add(pinName)

    for pinName in pinNames:
        if not pinName in usedPinNames:
            raise GenerateException("unused pin: %s" % pinName)

def checkNoopEntries(entries):
    for e in entries:
        if "mode" not in e and "pins" not in e:
            if e["name"] == "learn.doubleclick.net":
                # This entry is deliberately used as an exclusion.
                continue
            raise GenerateException("Entry for " + e["name"] + " has no mode and no pins")

def checkDuplicateEntries(entries):
    seen = set()
    for e in entries:
        name = e["name"]
        if name in seen:
            raise GenerateException("Duplicate entry for " + name)
        seen.add(name)

def writeHeader(out):
    out.write("""\
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is automatically generated by transport_security_state_static_generate.go

#ifndef NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_
#define NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_

""")

def writeFooter(out):
    out.write("#endif // NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_\n")

def writeCertsOutput(out, pins):
    out.write("""\
// These are SubjectPublicKeyInfo hashes for public key pinning. The
// hashes are SHA1 digests.

""")
    for pin in pins:
        out.write("static const char kSPKIHash_%s[] =\n" % pin["name"])
        s1 = ""
        s2 = ""
        hash = pin["spkiHash"]
        for c in hash[:len(hash) / 2]:
            s1 += "\\x%02x" % ord(c)
        for c in hash[len(hash) / 2:]:
            s2 += "\\x%02x" % ord(c)

        out.write("    \"%s\"\n    \"%s\";\n\n" % (s1, s2))

def uppercaseFirstLetter(s):
    return s[0].upper() + s[1:]

def writeListOfPins(out, name, pinNames):
    out.write("static const char* const %s[] = {\n" % name)
    for pinName in pinNames:
        out.write("  kSPKIHash_%s,\n" % pinName)

    out.write("  NULL,\n};\n")

def toDNS(s):
    """toDNS returns a string converts the domain name |s| into C-escaped,
    length-prefixed form and also returns the length of the interpreted string.
    i.e. for an input "example.com" it will return "\\007" "example" "\\003"
    "com", 13. The octal length bytes are in their own string because Visual
    Studio won't accept a digit after an octal escape otherwise."""
    labels = s.split(".")
    l = 0
    parts = []
    for i, label in enumerate(labels):
        if len(label) > 63:
            raise GenerateException("DNS label too long")
        parts.append('"\\%03o"' % len(label))
        parts.append('"%s"' % label)
        l += len(label) + 1
    l += 1 # For the length of the root label.
    return (" ".join(parts), l)

def domainConstant(s):
    """domainConstant converts the domain name |s| into a string of the form
    "DOMAIN_" + uppercase last two labels."""
    labels = s.split(".")
    gtld = labels[-1].upper()
    domain = labels[-2].upper().replace("-", "_")
    return "DOMAIN_%s_%s" % (domain, gtld)

def writeHSTSEntry(out, entry):
    dnsName, dnsLen = toDNS(entry["name"])
    domain = "DOMAIN_NOT_PINNED"
    pinsetName = "kNoPins"
    if entry.get("pins"):
        pinsetName = "k%sPins" % uppercaseFirstLetter(entry["pins"])
        domain = domainConstant(entry["name"])
    out.write("  {%d, %s, %s, %s, %s, %s },\n" % (dnsLen, str(entry.get("include_subdomains", False)).lower(), dnsName, str(entry.get("mode") == "force-https").lower(), pinsetName, domain))

def writeHSTSOutput(out, hsts):
    out.write("""\
// The following is static data describing the hosts that are hardcoded with
// certificate pins or HSTS information.

// kNoRejectedPublicKeys is a placeholder for when no public keys are rejected.
static const char* const kNoRejectedPublicKeys[] = {
  NULL,
};

""")
    for pinset in hsts["pinsets"]:
        name = uppercaseFirstLetter(pinset["name"])
        acceptableListName = "k%sAcceptableCerts" % name
        writeListOfPins(out, acceptableListName, pinset["static_spki_hashes"])

        rejectedListName = "kNoRejectedPublicKeys"
        if pinset.get("bad_static_spki_hashes"):
            rejectedListName = "k%sRejectedCerts" % name
            writeListOfPins(out, rejectedListName, pinset["bad_static_spki_hashes"])

        out.write("""\
#define k%sPins { \\
  %s, \\
  %s, \\
}

""" % (name, acceptableListName, rejectedListName))

    out.write("""\
#define kNoPins {\\
  NULL, NULL, \\
}

static const struct HSTSPreload kPreloadedSTS[] = {
""")
    for entry in hsts["entries"]:
        writeHSTSEntry(out, entry)

    out.write("""\
};
static const size_t kNumPreloadedSTS = ARRAYSIZE_UNSAFE(kPreloadedSTS);

""")

if __name__ == '__main__':
    sys.exit(main())
