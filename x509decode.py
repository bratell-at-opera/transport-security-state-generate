"""Minimal x509 decoder that extracts exactly what
transport_security_state_static_generate needs and nothing else."""


from __future__ import print_function

import base64
import re
import sys

from pyasn1.codec.der import encoder as der_encoder  # pylint: disable=F0401
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.univ import OctetString
from pyasn1_modules import rfc2459

def pemDecode(lines):
    """Decodes a certificate block, assuming it's of the simplest
    possible kind with no headers."""
    result = base64.b64decode("\n".join(lines[1:-1]))
    return result

def decodeName(name):
    """Extracts parts from a X509 Subject, such as "O", "OU" and
    "CN"."""
    result = {}
    # From RFC 4519
    # CN = 2.5.4.3
    # O = 2.5.4.10
    # OU = 2.5.4.11

    # C (country) = 2.5.4.6

    oidToStr = {
        (2, 5, 4, 3): "CN",
        (2, 5, 4, 6): "C",
        (2, 5, 4, 10): "O",
        (2, 5, 4, 11): "OU",
        }
    for rdn in name.getComponentByPosition(0):
        attrTypeValue = rdn.getComponentByPosition(0)
        attrType = attrTypeValue.getComponentByName("type")
        attrValue = attrTypeValue.getComponentByName("value")
        oidTuple = attrType.asTuple()
        result[oidTuple] = attrValue

        # Add a decoded value if we care.

        if oidTuple in oidToStr:
            oidStr = oidToStr[oidTuple]
            # If more than one, just save the first one.
            if not oidStr in result:
                decoded = der_decoder.decode(attrValue.asOctets())[0]
                assert isinstance(decoded, OctetString)
                result[oidStr] = str(decoded)

    return result


def parsePemCert(pemCert):
    """Given a pem decoded certificate, returns a dict with
    "subjectCN", "subjectO", "subjectOU" and
    "subjectPublicKeyInfo". The first three are strings or None while
    subjectPublicKeyInfo is a DER encoded subjectPublicKeyInfo."""
    block = pemDecode(pemCert)

    cert = der_decoder.decode(block, asn1Spec=rfc2459.Certificate())[0]
    tbsCert = cert.getComponentByName("tbsCertificate")
    nameParts = decodeName(tbsCert.getComponentByName("subject"))

    subjectPublicKeyInfo = tbsCert.getComponentByName("subjectPublicKeyInfo")
    rawsubjectpublickeyinfo = der_encoder.encode(subjectPublicKeyInfo)

    return {
        "subjectCN": nameParts.get("CN"),
        "subjectO": nameParts.get("O"),
        "subjectOU": nameParts.get("OU"),
        "subjectPublicKeyInfo": rawsubjectpublickeyinfo,
        }
    return cert
