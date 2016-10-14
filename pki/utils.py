import os
import datetime
import getpass
from django.conf import settings
from cryptography import utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


REQ_DISTINGUISHED_NAME = {
    'C'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('C', 'US'),
    'ST' : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('ST', 'TX'),
    'L'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('L', 'Plano'),
    'O'  : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('O', None),
    'OU' : getattr(settings, 'REQ_DISTINGUISHED_NAME', {}).get('OU', None),
}


def random_serial_number():
    return utils.int_from_bytes(os.urandom(5), "big") >> 1


def get_next_serial(base_dir):
    if not os.path.exists(os.path.join(base_dir, 'serial')):
        return 1
    with open(os.path.join(base_dir, 'serial')) as f:
        return(int(f.read()))


def set_next_serial(base_dir, serial):
    with open(os.path.join(base_dir, 'serial'), 'w') as f:
        f.write(str(serial))


def dump_pkey_pem(pkey):
    return pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def dump_cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def load_pkey(path, passwd):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(), b'%s' % passwd.encode(), default_backend()
        )

def load_key(cert):
    passwd = b'%s' % getpass.getpass('password: ').encode() or None
    return serialization.load_pem_private_key(
        cert, passwd, default_backend()
    )

def load_crt(cert):
    return x509.load_pem_x509_certificate(
        cert, default_backend()
    )

def key_text(key, passwd=None):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=passwd and serialization.BestAvailableEncryption(
            b"%s" % passwd.encode()
        ) or serialization.NoEncryption()
    )


def csr_text(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def crt_text(crt):
    return crt.public_bytes(serialization.Encoding.PEM)


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


def gen_req(name, cert_type, base_dir='.', passwd=None, alt_names=[]):
    cn = name.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value.replace(' ', '_')

    key = gen_key(cn, base_dir, passwd, 2048)

    csr = x509.CertificateSigningRequestBuilder(
        subject_name=name
    )

    if cert_type is 'server':
        csr = csr.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn.value) for cn in
                name.get_attributes_for_oid(
                    NameOID.COMMON_NAME
                )] + [x509.DNSName(n) for n in alt_names]
            ),
            critical=False
        )

    csr = csr.sign(
        key, hashes.SHA256(), default_backend()
    )

    with open(os.path.join(base_dir, '%s.csr' % cn), 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return (key, csr)


def gen_crt(cakey, cacrt, csr, cert_type, days=5*365, base_dir='.', serial=None):
    cn = csr.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value.replace(' ', '_')
    crt = x509.CertificateBuilder(
        extensions=list(csr.extensions),
        subject_name=csr.subject,
        issuer_name=cacrt.subject,
        public_key=csr.public_key(),
        serial_number=serial or random_serial_number(),
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
                key_agreement=cert_type is 'client' or False,
                crl_sign=False, key_cert_sign=False,
                content_commitment=False, data_encipherment=False,
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
    crt = x509.CertificateBuilder().subject_name(
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
        f.write(crt.public_bytes(serialization.Encoding.PEM))
    return (key, crt)
