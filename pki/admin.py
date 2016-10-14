from django.contrib import admin
from cryptography import x509
from .utils import *
from .models import Certificate


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    def mk_client_cert(self, request, queryset):

        for q in queryset:
            if q.kind != 'CL':
                self.message_user(request, 'Select only clients')
                return
        for q in queryset:
            cname = get_x509_name(q.common_name, **REQ_DISTINGUISHED_NAME)
            ckey, ccsr = gen_req(cname, 'client', '/tmp')
            cert = Certificate.objects.get(kind='CA', comment='default')
            cacrt = load_crt(cert.cert.encode())
            cakey = load_key(cert.priv_key.encode())
            ccrt = gen_crt(cakey, cacrt, ccsr, 'client', base_dir='/tmp', serial=cert.next_serial_number)
            q.priv_key = dump_pkey_pem(cakey)
            q.cert = dump_cert_pem(cacrt)
