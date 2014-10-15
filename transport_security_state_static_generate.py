#!/usr/bin/env python

"""This program converts the information
transport_security_state_static.json and
transport_security_state_static.certs into
transport_security_state_static.h. The input files contain information about
public key pinning and HTTPS-only sites that is compiled into Chromium.

Run without arguments for usage information."""

from __future__ import print_function

import base64
import hashlib
import json
import os
import re
import sys

# This path change is so that we can bundle pyx509 and pyasn1
# without requiring people to install those libs themselves.
third_party_path = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    'third_party'))
sys.path.append(third_party_path)
import pyx509.x509_parse as x509_parse # pylint: disable=F0401
from pyasn1.codec.der import encoder as der_encoder  # pylint: disable=F0401

class GenerateException(Exception):
    pass

def main():
    """The main entry point. Processes arguments and returns 0 if
    successful or 1 if failed."""
    if len(sys.argv) not in [3, 4]:
        print("Usage: %s <json file> <certificates file> [output file]" %
              sys.argv[0], file=sys.stderr)
        return 1

    try:
        process(sys.argv[1:])
    except GenerateException as e:
        print("Conversion failed: %s" % str(e), file=sys.stderr)
        return 1

    return 0

def process(arguments):
    jsonFileName = arguments[0]
    certsFileName = arguments[1]
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

    outputFile = "transport_security_state_static.h"
    if len(arguments) > 2:
        outputFile = os.path.abspath(arguments[2])
        if not os.path.exists(os.path.dirname(outputFile)):
            os.makedirs(os.path.dirname(outputFile))
    with open(outputFile, "w") as out:
        writeHeader(out)
        writeDomainIds(out, preloaded["domain_ids"])
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
                    raise GenerateException(
                        "failed to decode hash on line %d." % lineNo)
                if len(hash) != 20:
                    raise GenerateException(
                        "bad SHA1 hash length on line %d." % lineNo)
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
            raise GenerateException(
                "line %d, after a name, is not a hash nor a certificate" %
                lineNo)
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
        print("First word of certificate name is empty", file=sys.stderr)
        return False

    firstWord = firstWord.lower()
    lowerV = v.lower();
    if not lowerV.startswith(firstWord):
        print(("The first word (%s) of the certificate name (%s) is not "
               "a prefix of the variable name (%s).") %
              (firstWord, name, lowerV), file=sys.stderr)
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
    """checkDuplicatePins returns an error if any pins have the same
    name or the same hash."""
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

        allPinNames = (pinset.get("static_spki_hashes", []) +
                       pinset.get("bad_static_spki_hashes", []))
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
            raise GenerateException(
                "Entry for " + e["name"] + " has no mode and no pins")

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

// This file is automatically generated by
// transport_security_state_static_generate.py

#ifndef NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_
#define NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_

""")

def writeFooter(out):
    out.write("#endif // NET_HTTP_TRANSPORT_SECURITY_STATE_STATIC_H_\n")

def writeDomainIds(out, domainIds):
    out.write("enum SecondLevelDomainName {\n")

    for id in domainIds:
        out.write("  DOMAIN_" + id + ",\n")

    out.write("""\
  // Boundary value for UMA_HISTOGRAM_ENUMERATION.
  DOMAIN_NUM_EVENTS,
};

""")

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

class pinsetData:
    """index contains the index of the pinset in kPinsets."""
    def __init__(self, index, acceptPinsVar, rejectPinsVar):
        self.index = index
        self.acceptPinsVar = acceptPinsVar
        self.rejectPinsVar = rejectPinsVar

def writeHSTSEntry(out, entry):
    dnsName, dnsLen = toDNS(entry["name"])
    domain = "DOMAIN_NOT_PINNED"
    pinsetName = "kNoPins"
    if entry.get("pins"):
        pinsetName = "k%sPins" % uppercaseFirstLetter(entry["pins"])
        domain = domainConstant(entry["name"])
    out.write("  {%d, %s, %s, %s, %s, %s },\n" %
              (dnsLen,
               str(entry.get("include_subdomains", False)).lower(),
               dnsName,
               str(entry.get("mode") == "force-https").lower(),
               pinsetName,
               domain))

def writeHSTSOutput(out, hsts):
    out.write("""\
// The following is static data describing the hosts that are hardcoded with
// certificate pins or HSTS information.

// kNoRejectedPublicKeys is a placeholder for when no public keys are rejected.
static const char* const kNoRejectedPublicKeys[] = {
  NULL,
};

""")

    pinsets = {}
    pinsetNum = 0

    for pinset in hsts["pinsets"]:
        name = uppercaseFirstLetter(pinset["name"])
        acceptableListName = "k%sAcceptableCerts" % name
        writeListOfPins(out, acceptableListName, pinset["static_spki_hashes"])

        rejectedListName = "kNoRejectedPublicKeys"
        if pinset.get("bad_static_spki_hashes"):
            rejectedListName = "k%sRejectedCerts" % name
            writeListOfPins(out, rejectedListName,
                            pinset["bad_static_spki_hashes"])
        pinsets[pinset["name"]] = pinsetData(pinsetNum, acceptableListName,
                                             rejectedListName)
        pinsetNum += 1

    out.write("""
struct Pinset {
  const char *const *const accepted_pins;
  const char *const *const rejected_pins;
};

static const struct Pinset kPinsets[] = {
""")

    for pinset in hsts["pinsets"]:
        data = pinsets[pinset["name"]]
        out.write("  {%s, %s},\n" % (data.acceptPinsVar, data.rejectPinsVar))

    out.write("};\n")

    # domainIds maps from domainConstant(domain) to an index in kDomainIds.
    domainIds = {}
    for i, id in enumerate(hsts["domain_ids"]):
        domainIds["DOMAIN_" + id] = i


    # First, create a Huffman tree using approximate weights and generate
    # the output using that. During output, the true counts for each
    # character will be collected for use in building the real Huffman
    # tree.
    root = buildHuffman(approximateHuffman(hsts["entries"]))
    huffmanMap = root.toMap()
    devNull = open(os.devnull, "w")
    hstsLiteralWriter = cLiteralWriter(devNull)
    hstsBitWriter = trieWriter(hstsLiteralWriter, pinsets, domainIds,
                               huffmanMap)
    writeEntries(hstsBitWriter, hsts["entries"])
    hstsBitWriter.Close()
    origLength = hstsBitWriter.position

    # Now that we have the true counts for each character, build the true
    # Huffman tree.
    root = buildHuffman(hstsBitWriter.huffmanCounts)
    huffmanMap = root.toMap()

    out.write("""
// kHSTSHuffmanTree describes a Huffman tree. The nodes of the tree are pairs
// of uint8s. The last node in the array is the root of the tree. Each pair is
// two uint8 values, the first is "left" and the second is "right". If a uint8
// value has the MSB set then it represents a literal leaf value. Otherwise
// it's a pointer to the n'th element of the array.
static const uint8 kHSTSHuffmanTree[] = {
""")

    huffmanLiteralWriter = cLiteralWriter(out)
    root.WriteTo(huffmanLiteralWriter)

    out.write("""
};

static const uint8 kPreloadedHSTSData[] = {
""")

    hstsLiteralWriter = cLiteralWriter(out)
    hstsBitWriter = trieWriter(hstsLiteralWriter, pinsets, domainIds,
                               huffmanMap)

    rootPosition = writeEntries(hstsBitWriter, hsts["entries"])
    hstsBitWriter.Close()

    bitLength = hstsBitWriter.position
    if debugging:
        print("Saved %d bits by using accurate Huffman counts.\n" %
              (origLength - bitLength), file=sys.stderr)

    out.write("""
};

""")
    out.write("static const unsigned kPreloadedHSTSBits = %d;\n\n" % bitLength)
    out.write("static const unsigned kHSTSRootPosition = %d;\n\n" %
              rootPosition)

class cLiteralWriter(object):
    """cLiteralWriter is an io.Writer that formats data suitable as
    the contents of a uint8_t array literal in C."""
    def __init__(self, out):
        self.out = out
        self.bytesThisLine = 0
        self.count = 0

    def WriteByte(self, b):
        if self.bytesThisLine == 8:
            self.out.write("\n")
            self.bytesThisLine = 0

        if self.bytesThisLine == 0:
            self.out.write("  ")
        else:
            self.out.write(" ")

        self.out.write("0x%0.2x," % b)
        self.bytesThisLine += 1
        self.count += 1

class trieWriter(object):
    """trieWriter handles wraps an io.Writer and provides a bit
    writing interface. It also contains the other information needed
    for writing out a compressed trie."""
    def __init__(self, w, pinsets, domainIds, huffman):
        self.w = w
        self.pinsets = pinsets # string -> pinsetData
        self.domainIds = domainIds # string -> int
        self.huffman = huffman # rune -> bitsAndLen
        self.b = 0
        self.used = 0
        self.position = 0
        self.huffmanCounts = 129 * [0]

    def WriteBits(self, bits, numBits):
        for i in xrange(1, numBits + 1):
            bit = 1 & (bits >> (numBits - i)) # bit #i set or not?
            self.b |= bit << (7 - self.used)
            self.used += 1
            self.position += 1
            if self.used == 8:
                self.w.WriteByte(self.b)
                self.used = 0
                self.b = 0

    def Close(self):
        self.w.WriteByte(self.b)


class bitsOrPosition(object):
    """bitsOrPosition contains either some bits (if numBits > 0) or a
    byte offset in the output (otherwise)."""
    def __init__(self, bits, numBits, position):
        self.bits = bits
        self.numBits = numBits
        self.position = position

def bitLength(i):
    numBits = 0
    while i != 0:
        numBits += 1
        i >>= 1
    return numBits

class bitBuffer(object):
    """bitBuffer buffers up a series of bits and positions because the
    final output location of the data isn't known yet and so the
    deltas from the current position to the written positions isn't
    known yet."""
    def __init__(self):
        self.b = 0
        self.used = 0
        self.elements = [] # bitsOrPosition objects.

    def WriteBit(self, bit):
        self.b |= (bit & 0xff) << (7 - self.used)
        self.used += 1
        if self.used == 8:
            self.elements.append(bitsOrPosition(self.b, self.used, 0))
            self.used = 0
            self.b = 0

    def WriteBits(self, bits, numBits):
        for i in xrange(1, numBits + 1):
            bit = 1 & (bits >> (numBits - i))
            self.WriteBit(bit)

    def WritePosition(self, lastPositionObj, position):
        """lastPositon is an array of one element so that it can be
        changed by this function. Change to return value?"""
        if lastPositionObj[0] != -1:
            delta = position - lastPositionObj[0]
            assert delta > 0, "delta position is not positive"
            numBits = bitLength(delta)
            assert numBits <= 7 + 15, "positive position delta too large"
            if numBits <= 7:
                self.WriteBits(0, 1)
                self.WriteBits(delta, 7)
            else:
                self.WriteBits(1, 1)
                self.WriteBits(numBits - 8, 4)
                self.WriteBits(delta, numBits)
            lastPositionObj[0] = position
            return

        if self.used != 0:
            self.elements.append(bitsOrPosition(self.b, self.used, 0))
            self.used = 0
            self.b = 0

        self.elements.append(bitsOrPosition(0, 0, position))
        lastPositionObj[0] = position

    def WriteChar(self, b, w):
        assert ord(b) in w.huffman, "WriteChar given rune not in Huffman table"
        bits = w.huffman[ord(b)]
        w.huffmanCounts[ord(b)] += 1
        self.WriteBits(bits.bits, bits.numBits)

    def WriteTo(self, w):
        position = w.position

        if self.used != 0:
            self.elements.append(bitsOrPosition(self.b, self.used, 0))
            self.used = 0
            self.b = 0

        for elem in self.elements:
            if elem.numBits != 0:
                w.WriteBits(elem.bits >> (8 - elem.numBits), elem.numBits)
            else:
                current = position
                target = elem.position
                assert target < current, "reference is not backwards"
                delta = current - target

                numBits = bitLength(delta)

                assert numBits < 32, "delta is too large"

                w.WriteBits(numBits, 5)
                w.WriteBits(delta, numBits)

class reversedEntry(object):
    def __init__(self, bytes, hsts):
        self.hsts = hsts
        self.bytes = bytes
        assert self.bytes[-1] == "\0"

class reversedEntries(list):
    def LongestCommonPrefix(self):
        if len(self) == 0:
            return None

        prefix = ""
        i = 0
        while True:
            if i == len(self[0].bytes):
                break
            candidate = self[0].bytes[i]
            if ord(candidate) == terminalValue:
                break
            ok = True

            for ent in self[1:]:
                if i > len(ent.bytes) or ent.bytes[i] != candidate:
                    ok = False
                    break;

            if not ok:
                break

            prefix += candidate
            i += 1
        return prefix

    def RemovePrefix(self, n):
        for ent in self:
            ent.bytes = ent.bytes[n:]

    def __getslice__(self, i, j):
        return reversedEntries(list.__getslice__(self, i, j))

def reverseName(name):
    for r in (ord(x) for x in name):
        assert 1 <= r <= 126, "byte in name is out of range."
    return name[::-1] + "\0"

def writeEntries(w, hstsEntries):
    ents = reversedEntries()
    for hstsEntry in hstsEntries:
        ents.append(reversedEntry(reverseName(hstsEntry["name"]),
                                  hstsEntry))

    ents.sort(key=lambda x: x.bytes)

    return writeDispatchTables(w, ents, 0)

debugging = False

def writeDispatchTables(w, ents, depth):
    buf = bitBuffer()

    assert len(ents) > 0, "empty ents passed to writeDispatchTables"

    prefix = ents.LongestCommonPrefix()
    l = len(prefix)
    while l > 0:
        buf.WriteBit(1)
        l -= 1
    buf.WriteBit(0)

    if len(prefix) > 0:
        if debugging:
            for i in range(depth):
                print(" ", end="")
        for b in prefix:
            buf.WriteChar(b, w)
            if debugging:
                print(b, end="")
            depth += 1

        if debugging:
            print("")

    ents.RemovePrefix(len(prefix))
    lastPositionObj = [-1]
    while len(ents) > 0:
        subents = reversedEntries()
        b = ents[0].bytes[0]
        j = 1
        while j < len(ents):
            if ents[j].bytes[0] != b:
                break
            j += 1

        subents = ents[:j]
        buf.WriteChar(b, w)

        if debugging:
            for i in range(depth):
                print(" ", end="")
            print("?%s" % b)

        if ord(b) == terminalValue:
            assert len(subents) == 1, "multiple values with the same name"
            hsts = ents[0].hsts
            includeSubdomains = 0
            if hsts.get("include_subdomains"):
                includeSubdomains = 1
            buf.WriteBit(includeSubdomains)

            forceHTTPS = 0
            if hsts.get("mode") == "force-https":
                forceHTTPS = 1
            buf.WriteBit(forceHTTPS)

            if hsts.get("pins", "") == "":
                buf.WriteBit(0)
            else:
                buf.WriteBit(1)
                pinsId = w.pinsets[hsts["pins"]].index
                assert pinsId < 16, "too many pinsets"
                buf.WriteBits(pinsId, 4)
                domainId = w.domainIds[domainConstant(hsts["name"])]
                assert domainId < 512, "too many domain ids: %d" % domainId
                buf.WriteBits(domainId, 9)
        else:
            subents.RemovePrefix(1)
            pos = writeDispatchTables(w, subents, depth + 2)
            if debugging:
                for i in range(depth):
                    print(" ", end="")
                print("@%d" % pos)
            buf.WritePosition(lastPositionObj, pos)

        ents = ents[j:]

    buf.WriteChar(chr(endOfTableValue), w)

    position = w.position
    buf.WriteTo(w)
    return position

class bitsAndLen(object):
    def __init__(self, bits, numBits):
        self.bits = bits
        self.numBits = numBits

class huffmanNode(object):
    """huffmanNode represents a node in a Huffman tree, where count is
    the frequency of the value that the node represents and is used
    only in tree construction."""

    def __init__(self, value, count, left, right):
        self.value = value
        self.count = count
        self.left = left
        self.right = right

    def isLeaf(self):
        return self.left is None and self.right is None

    def toMap(self):
        """toMap converts the Huffman tree rooted at n into a map from
        value to the bit sequence for that value."""
        ret = {}
        self.fillMap(ret, 0, 0)
        return ret

    def fillMap(self, m, bits, numBits):
        """fillMap is a helper function for toMap the recurses down
        the Huffman tree and fills in entries in m."""
        if self.isLeaf():
            m[self.value] = bitsAndLen(bits, numBits)
        else:
            newBits = bits << 1
            self.left.fillMap(m, newBits, numBits + 1)
            self.right.fillMap(m, newBits | 1, numBits + 1)

    def WriteTo(self, w):
        """WriteTo serialises the Huffman tree rooted at n to w in a
        format that can be processed by the Chromium code. See the comments in
        Chromium about the format."""
        leftValue = 0
        rightValue = 0
        childPosition = 0

        if self.left.isLeaf():
            leftValue = 128 | self.left.value
        else:
            childPosition = self.left.WriteTo(w)
            assert childPosition < 512, "huffman tree too large"
            leftValue = int(childPosition / 2)

        if self.right.isLeaf():
            rightValue = 128 | self.right.value
        else:
            childPosition = self.right.WriteTo(w)
            assert childPosition < 512, "huffman tree too large"
            rightValue = int(childPosition / 2)

        position = w.count
        w.WriteByte(leftValue)
        w.WriteByte(rightValue)
        return position

class nodeList(list):
    """list of huffmanNode objects"""
    pass

# terminalValue indicates the end of a string (which is the beginning of the
# string since we process it backwards).
terminalValue = 0

# endOfTableValue is a sentinal value that indicates that there are no more
# entries in a dispatch table.
endOfTableValue = 127

def approximateHuffman(entries):
    """approximateHuffman calculates an approximate frequency table for
    entries, for use in building a Huffman tree."""
    useCounts = 129 * [0]
    for ent in entries:
        for r in (ord(x) for x in ent["name"]):
            assert r != 0 and r < 127, "Rune out of range in name"
            useCounts[r] += 1
        useCounts[terminalValue] += 1
        useCounts[endOfTableValue] += 1

    return useCounts

def buildHuffman(useCounts):
    """buildHuffman builds a Huffman tree using useCounts as a
    frequency table."""
    root = None
    numNonZero = 0
    for count in useCounts:
        if count != 0:
            numNonZero += 1

    nodes = nodeList()
    for char, count in enumerate(useCounts):
        if count != 0:
            nodes.append(huffmanNode(char, count, None, None))

    assert nodes >= 2, "cannot build a tree with a single node"
    nodes.sort(key=lambda x: x.count)

    while len(nodes) > 1:
        parent = huffmanNode(0, nodes[0].count + nodes[1].count,
                             nodes[0], nodes[1])
        nodes = nodes[1:]
        nodes[0] = parent
        nodes.sort(key=lambda x: x.count)

    return nodes[0]

if __name__ == '__main__':
    sys.exit(main())
