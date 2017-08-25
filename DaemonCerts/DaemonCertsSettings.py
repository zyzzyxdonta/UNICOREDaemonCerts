# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

from DaemonCerts.utility.AbstractSettings import AbstractSettings

# Settings parser, parses equality args, such as Domains.UNITY="FQDN"

class DaemonCertsSettings(AbstractSettings):
    def __init__(self):
        super(DaemonCertsSettings,self).__init__("DaemonCerts")

    def _set_defaults(self):
        defaults = [
            ('FQDN' , "unicore.sample-fqdn.com", "FQDN of the main UNICORE server running most server daemons"),

            ('Domains.UNITY','sameas:FQDN',"FQDN of the machine running UNITY"),
            ('Domains.UNICOREX','sameas:FQDN',"FQDN of the machine running UNICOREX"),
            ('Domains.REGISTRY','sameas:FQDN',"FQDN of the machine running REGISTRY"),
            ('Domains.XUUDB','sameas:FQDN',"FQDN of the machine running XUUDB"),
            ('Domains.GATEWAY','sameas:FQDN',"FQDN of the machine running GATEWAY"),
            ('Domains.WORKFLOW','sameas:FQDN',"FQDN of the machine running WORKFLOW"),
            ('Domains.SERVORCH','sameas:FQDN',"FQDN of the machine running SERVORCH"),

            ('KeystorePass.UNITY','the!uvos',"Password for the p12 keystore holding the certificate of UNITY"),
            ('KeystorePass.UNICOREX','the!njs',"Password for the p12 keystore holding the certificate of UNICOREX"),
            ('KeystorePass.REGISTRY','the!registry',"Password for the p12 keystore holding the certificate of REGISTRY"),
            ('KeystorePass.XUUDB','the!xuudb',"Password for the p12 keystore holding the certificate of XUUDB"),
            ('KeystorePass.GATEWAY','the!gateway',"Password for the p12 keystore holding the certificate of GATEWAY"),
            ('KeystorePass.WORKFLOW','the!workflow',"Password for the p12 keystore holding the certificate of WORKFLOW"),
            ('KeystorePass.SERVORCH','the!servorch',"Password for the p12 keystore holding the certificate of SERVORCH"),

            ('cert.years', 50 , "Years these certificates should be valid, i.e. years until admin retirement"),
            ('cert.email','admin@unicore.com',"Email for the Cert authority and other certs"),
            ('cert.Country', 'US', "C-Field in the DN, e.g., US, DE, GB, etc. Maximum two letters!"),
            ('cert.Locality', 'San Francisco', "L-Field in the DN, Locality, i.e., City."),
            ('cert.State', 'California', "ST-Field in the DN, State."),
            ('cert.Organization', 'MyOrganization', "O-Field in the DN. Your company"),
            ('cert.OrganizationalUnit', 'IT Services',"OU-Field in the DN. Where the Admin works in. For example IT Services."),

            ('GCID','CLUSTER-SITE','GCID of the UNICORE site. Only required if using XUUDB'),

            ('directory.certs','./certs','Directory where all the certificates will be put'),
            ('directory.ca', './CA', 'Directory where the self signed CA will be put')
        ]

        for valuename,default,explanation in defaults:
            self._add_default(valuename,default,explanation)
