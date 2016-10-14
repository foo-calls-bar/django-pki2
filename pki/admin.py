from django.contrib import admin

# Register your models here.
from django.conf import settings

import os
import datetime
from OpenSSL.crypto import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


REQ_DISTINGUISHED_NAME = {
    'C'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('C', None),
    'ST' : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('ST', None),
    'L'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('L', None),
    'O'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('O', None),
    'OU' : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('OU', None),
}


def random_serial_number():
    return utils.int_from_bytes(os.urandom(20), "big") >> 1


class ExtensionsList(object):
    def __init__(self, cert_type):
        self._type = cert_type

    @property
    def all(self):
        return [
            X509Extension(
                type_name=b'basicConstraints',
                value=b'CA:TRUE' if (
                    self._type == 'ca'
                ) else b'CA:FALSE',
                critical=False
            ),
        ] + (self._type in ['client', 'server'] and [
            X509Extension(
                type_name=b'keyUsage',
                value=b'digitalSignature,keyEncipherment' if (
                    self._type == 'server'
                ) else b'digitalSignature',
                critical=False
            ),
            X509Extension(
                type_name=b'extendedKeyUsage',
                value=b'serverAuth' if (
                    self._type == 'server'
                ) else b'clientAuth',
                critical=False
            ),
        ] or [])

    @property
    def client_extensions(self):
        return [
            X509Extension(
                type_name=b'basicConstraints',
                value=b'CA:FALSE',
                critical=False
            ),
            X509Extension(
                type_name=b'keyUsage',
                value=b'digitalSignature',
                critical=False
            ),
            X509Extension(
                type_name=b'extendedKeyUsage',
                value=b'clientAuth',
                critical=False
            ),
        ]

    @property
    def server_extensions():
        return [
            X509Extension(
                type_name=b'basicConstraints',
                value=b'CA:FALSE',
                critical=False
            ),
            X509Extension(
                type_name=b'keyUsage',
                value=b'digitalSignature, keyEncipherment',
                critical=False
            ),
            X509Extension(
                type_name=b'extendedKeyUsage',
                value=b'serverAuth',
                critical=False
            ),
        ]

    @property
    def ca_extensions():
        return [
            X509Extension(
                type_name=b'basicConstraints',
                value=b'CA:true',
                critical=False
            ),
        ]



def set_subject(x509, **kwargs):
    subj = x509.get_subject()
    extra = getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).copy()
    extra.update(kwargs)
    try:
        if extra.get('name', None):
            subj.commonName = extra.pop('name')
        for k,v in extra.items():
            if v: setattr(subj, k, v)
    except:
        raise



def subject_dict(x509):
    comps = x509.get_subject().get_components()
    return dict(zip(
        (i[0] for i in comps),
        (j[1] for j in comps)
    ))


def set_valid_times(x509, **offsets):
    before = datetime.datetime.now()
    deltas = offsets or {'days': 1}
    x509.set_notBefore(
        before.strftime('%Y%m%d%H%M%SZ').encode()
    )
    x509.set_notAfter((
        before + datetime.timedelta(**deltas)
    ).strftime('%Y%m%d%H%M%SZ').encode())


reqs = {
    'client': X509Req(),
    'server': X509Req(),
    'mainca': X509Req(),
    'rootca': X509Req(),
}

certs = {
    'client': X509(),
    'server': X509(),
    'mainca': X509(),
    'rootca': X509(),
}

pkeys = {
    'client': PKey(),
    'server': PKey(),
    'mainca': PKey(),
    'rootca': PKey(),
}

for k in pkeys.keys():
    pkeys[k].generate_key(TYPE_RSA, 2048)
    certs[k].set_pubkey(pkeys[k])
    reqs[k].set_pubkey(pkeys[k])
    set_subject(certs[k],
        C='US', ST='TX', L='Plano',
        O='Alpha Geek Computer Services',
        OU='VPN', emailAddress='root@alphageek.xyz',
    )
    set_subject(reqs[k],
        C='US', ST='TX', L='Plano',
        O='Alpha Geek Computer Services',
        OU='VPN', emailAddress='root@alphageek.xyz',
    )

set_valid_times(certs['rootca'], days=365*20)
set_valid_times(certs['mainca'], days=365*20)
set_valid_times(certs['client'], days=365*1)
set_valid_times(certs['server'], days=365*5)

certs['rootca'].add_extensions(ExtensionsList('ca').all)
certs['mainca'].add_extensions(ExtensionsList('ca').all)
certs['client'].add_extensions(ExtensionsList('client').all)
certs['server'].add_extensions(ExtensionsList('server').all)


reqs['rootca'].add_extensions(ExtensionsList('ca').all)
reqs['mainca'].add_extensions(ExtensionsList('ca').all)
reqs['client'].add_extensions(ExtensionsList('client').all)
reqs['server'].add_extensions(ExtensionsList('server').all)



REQ_DISTINGUISHED_NAME = {
    'C'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('C', 'US'),
    'ST' : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('ST', 'TX'),
    'L'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('L', 'Plano'),
    'O'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('O', None),
    'OU' : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('OU', None),
}



def gen_key(CN, base_dir='.', passwd=None, size=2048):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )
    with open(os.path.join(base_dir, '%s.key' % CN), 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=passwd and serialization.BestAvailableEncryption(
                b"%s" % passwd.encode()
            ) or serialization.NoEncryption()
        ))
    return key


def get_x509_name(CN, **kwargs):
    extra = getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).copy()
    extra.update(kwargs)
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, extra.get('C', 'US')),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, extra.get('ST', 'TX')),
        x509.NameAttribute(NameOID.LOCALITY_NAME, extra.get('L', 'Plano')),
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
    ]
    if extra.get('O', None):
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, extra['O'])),
    if extra.get('OU', None):
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, extra['OU'])),
    return x509.Name(attrs)


def gen_ca_req(name, passwd, base_dir='.'):
    cn = name.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value.replace(' ', '_')
    key = gen_key(cn, base_dir, passwd, 2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        name
    ).sign(
        key, hashes.SHA256(), default_backend()
    )
    with open(os.path.join(base_dir, '%s.csr' % cn), 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return (key, csr)



def gen_req(name, base_dir='.', passwd=None, alt_names=[]):
    cn = name.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value.replace(' ', '_')
    key = gen_key(cn, base_dir, passwd, 2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        name
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn.value) for cn in
            name.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )] + [x509.DNSName(n) for n in alt_names]
        ),
        critical=False
    ).sign(
        key, hashes.SHA256(), default_backend()
    )
    with open(os.path.join(base_dir, '%s.csr' % cn), 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return (key, csr)


def get_next_serial(base_dir):
    with open(os.path.join(base_dir, 'serial')) as f:
        return(int(f.read()))

def set_next_serial(base_dir, serial):
    with open(os.path.join(base_dir, 'serial'), 'w') as f:
        f.write(str(serial))

def gen_crt(cakey, cacrt, csr, cert_type, days=5*365, base_dir='.'):
    cn = csr.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value.replace(' ', '_')
    crt = x509.CertificateBuilder(
        extensions=list(csr.extensions),
        subject_name=csr.subject,
        issuer_name=cacrt.subject,
        public_key=csr.public_key(),
        serial_number=random_serial_number() if cert_type is 'ca' else get_next_serial(base_dir),
        not_valid_before=datetime.datetime.utcnow(),
        not_valid_after=datetime.datetime.utcnow()+datetime.timedelta(days=days),
    ).add_extension(
        x509.BasicConstraints(True, 0) if (
            cert_type is 'ca'
        ) else x509.BasicConstraints(False, None),
        critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            csr.public_key()
        ), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            cakey.public_key()
        ),
        critical=False
    )
    if cert_type in ['server', 'client']:
        crt = crt.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=cert_type is 'server' or False,
                crl_sign=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                encipher_only=False, decipher_only=False
            ),
            critical=False
        ).add_extension(
            x509.ExtendedKeyUsage([
                getattr(x509.ExtendedKeyUsageOID,
                    cert_type.upper() + '_AUTH'
                ),
            ]),
            critical=False
        )
    crt = crt.sign(cakey, hashes.SHA256(), default_backend())
    with open(os.path.join(base_dir, '%s.cert' % cn), 'wb') as f:
        f.write(crt.public_bytes(serialization.Encoding.PEM))
    if cert_type != 'ca':
        set_next_serial(base_dir, crt.serial_number + 1)
    return crt



def mkroot_ca(name, passwd, base_dir='.', days=10):
    cn = name.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value.replace(' ', '_')
    key = gen_key(cn, base_dir, passwd, 2048)
    issuer = subject = name
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days)
    ).add_extension(
        x509.BasicConstraints(True, 1),
        critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False
    ).sign(
        key, hashes.SHA256(), default_backend()
    )
    with open(os.path.join(base_dir, '%s.cert' % cn), 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return (key, cert)



def load_pkey(path, passwd):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(), b'%s' % passwd.encode(), default_backend()
        )


    for extension in csr.extensions:
        crt = crt.add_extension(
            x509.Extension(
                extension.oid,
                extension.critical,
                extension.value
            ), critical=extension.critical
        )

def get_cert(cakey,
