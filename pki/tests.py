import os
import getpass
from django.conf import settings
from django.test import TestCase
from .utils import *

del(REQ_DISTINGUISHED_NAME['OU'])
if not REQ_DISTINGUISHED_NAME['O']:
    REQ_DISTINGUISHED_NAME['O'] = 'Alpha Geek Computer Services'


class BasicPKITest(TestCase):

    def setUp(self):
        self.passwd = getpass.getpass('CA passwd: ')
        self.base = 'store'
        os.mkdir(self.base)

    def tearDown(self):
        if os.path.isdir(self.base):
            for root,dirs,files in os.walk(self.base):
                for f in files:
                    os.remove(os.path.join(root, f))
            os.rmdir(self.base)

    def test_gen_all(self):
        ra_name = get_x509_name('%s Root CA' % REQ_DISTINGUISHED_NAME['O'], **REQ_DISTINGUISHED_NAME)
        ca_name = get_x509_name('%s VPN CA' % REQ_DISTINGUISHED_NAME['O'], **REQ_DISTINGUISHED_NAME)
        s1_name = get_x509_name('vpn.alphageek.xyz', **REQ_DISTINGUISHED_NAME)
        c1_name = get_x509_name('client1', **REQ_DISTINGUISHED_NAME)
        rakey, racrt = mkroot_ca(ra_name, self.passwd, self.base, days=1)
        cakey, cacsr = gen_req(ca_name, 'ca', self.base, self.passwd)
        s1key, s1csr = gen_req(s1_name, 'server', self.base, None, ['test.vpn.alphageek.xyz'])
        c1key, c1csr = gen_req(c1_name, 'client', self.base)
        cacrt = gen_crt(rakey, racrt, cacsr, 'ca', 1, self.base)
        s1crt = gen_crt(cakey, cacrt, s1csr, 'server', 1, self.base)
        c1crt = gen_crt(cakey, cacrt, c1csr, 'client', 1, self.base)
        input()
