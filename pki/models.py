import os
import getpass
from django.db import models
from django.conf import settings


class Certificate(models.Model):
    (CA, TLS, DH, CRL, SERVER, CLIENT,) = (
        'CA', 'TL', 'DH', 'RL', 'SV', 'CL'
    )

    TYPE_CHOICES = (
        (CA, 'ca'), (TLS, 'tls_auth'),
        (DH, 'dh'), (CRL, 'crl'),
        (SERVER, 'server'), (CLIENT, 'client'),
    )

    common_name = models.CharField(
        max_length=128,
        primary_key=True
    )

    serial_number = models.IntegerField(
        null=True,
        blank=True
    )

    revoked = models.BooleanField(
        default=False
    )

    autologin = models.BooleanField(
        default=False
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    kind=models.CharField(
        max_length=2,
        choices=TYPE_CHOICES,
        default=CLIENT,
        verbose_name='Type'
    )

    next_serial_number = models.IntegerField(
        null=True,
        blank=True
    )

    key_size = models.IntegerField(
        null=True, blank=True
    )

    comment = models.TextField(
        blank=True
    )

    cert = models.TextField(
        blank=True
    )

    priv_key = models.TextField(
        blank=True
    )

    def __str__(self):
        return self.common_name
