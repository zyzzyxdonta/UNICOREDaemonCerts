# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
import atexit

from OpenSSL import crypto

from DaemonCerts.DaemonCertsSettings import DaemonCertsSettings
from DaemonCerts.utility.misc_file_functions import mkdir_p

import os

class DaemonCerts(object):
    def __init__(self,sysargs):
        super(DaemonCerts,self).__init__()
        self.dcs = DaemonCertsSettings()
        try:
            self.dcs.parse_eq_args(sysargs, createdicts=False)
        except Exception as e:
            self.write_info_text()
            raise

        self.servers = [ "GATEWAY",
                         "XUUDB",
                         "UNICOREX",
                         "REGISTRY",
                         "UNITY"
                       ]

        FQDN = self.dcs.get_value("FQDN")
        if FQDN == "unicore.sample-fqdn.com" or len(sysargs) == 0:
            self.write_info_text()
            sys.exit(0)

        ca_path = self.dcs.get_value('directory.ca')
        mkdir_p(ca_path)
        serialpath = os.path.join(ca_path,"serial")
        self.serial = None
        if os.path.isfile(serialpath):
            with open(serialpath,'rt') as serialfile:
                for line in serialfile:
                    self.serial = int(line, 16)
                    break

        if self.serial is None:
            self.serial = 1

        atexit.register(self.cleanup)

    def get_san_extension_ca(self,san_string):
        #crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
        #crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
        return [ crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"), crypto.X509Extension(b"subjectAltName", False, san_string.encode("UTF-8")) ]

    def get_san_extension(self,san_string):
        #crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
        return [ crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                 crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
                 crypto.X509Extension(b"subjectAltName", False, san_string.encode("UTF-8")) ]

    def make_ca_dir(self):
        ca_path = self.dcs.get_value('directory.ca')
        mkdir_p(ca_path)
        return ca_path

    def make_truststore_dir(self):
        cert_path = self.dcs.get_value('directory.certs')
        truststore_path = os.path.join(cert_path, "truststore")
        mkdir_p(truststore_path)
        return truststore_path

    def make_cert_dirs(self):
        cert_path = self.dcs.get_value('directory.certs')
        mkdir_p(cert_path)

        unity_path = os.path.join(cert_path,"unity")
        mkdir_p(unity_path)
        return cert_path,unity_path

    def write_serial(self):
        ca_path = self.make_ca_dir()
        serialpath = os.path.join(ca_path, "serial")
        with open(serialpath, 'w') as serialfile:
            serialfile.write("%s\n"% hex(self.serial)[2:])

    def write_info_text(self):
        help_message="""
   ---- UNICORE Daemon Cert Generator ----
        
       Copyright Nanomatch GmbH 2017

   Usage:
   CreateDaemonCerts.py parameter2=value2 parameter2=value2. A list of all parameters follows:

   A typical command to generate Daemon Certs for all UNICORE server daemons would be:

   CreateDaemonCerts.py FQDN=int-bionano.it.kit.edu \\
                        cert.email=admin@your_mail.de \\
                        "cert.OrganizationalUnit=IT Services" \\
                        "cert.Organization=Nanomatch GmbH" \\
                        cert.Country=DE \\
                        cert.Locality=Karlsruhe \\
                        "cert.State=Baden Württemberg" \\
                        GCID=NANO-SITE 
     
    Please note that Country can only be two letter code. Individiual daemon domains can specified using: Domains.SERVER=FQDN. This is completely optional. Don't do it unless you really need it.
    The program will generate the certs and the following files:
    rfc4514_dns.txt contains the generated server DNs in the rfc4514 format.
    xuudb_commands.sh contains the server DNs again including the commands, which have to be executed to add them to XUUDB.
"""
        print(help_message)
        self.dcs.print_options(sys.stdout)


    def cleanup(self):
        self.write_serial()

    def main(self):
        ca_path = self.make_ca_dir()
        if not os.path.isfile(os.path.join(ca_path,"cacert.pem")):
            dn = self.gen_ca()
            print("Generated new CA, DN: <%s>"%dn)

        with open("xuudb_commands.sh",'w') as xuudb_com:
            with open("rfc4514_dns.txt", 'w') as rfc:
                gcid = self.dcs.get_value("GCID")
                for server in self.servers:
                    dn =self.gen_server_cert(server)
                    print("Generated key for server %s DN: <%s>" % (server,dn))
                    xcom = "bin/admin.sh adddn %s \"%s\" nobody server" %(gcid,dn)
                    xuudb_com.write("%s\n"%xcom)
                    rfc.write("%s\n"%dn)


    def get_ca_key(self):
        ca_path = self.dcs.get_value('directory.ca')
        ca_key_path = os.path.join(ca_path,"private","cakey.pem")
        ca_key_data = ""
        with open(ca_key_path,'rt') as ca_key_file:
            ca_key_data = ca_key_file.read()
        key = crypto.load_privatekey(crypto.FILETYPE_PEM,ca_key_data)

        ca_cert_path = os.path.join(ca_path,"cacert.pem")
        with open(ca_cert_path,'r') as ca_cert_file:
            ca_cert_data = ca_cert_file.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM,ca_cert_data)        

        return key,cert


    def gen_ca(self):
        #Here we generate a self-signed CA certificate
        #CN and SAN are set to FQDN.
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        years = self.dcs.get_value("cert.years")
        cert = crypto.X509()
        # X509 Version 3 has version number 2! It's the logical choice
        cert.set_version(2)
        CERT_C = self.dcs.get_value("cert.Country")
        CERT_ST = self.dcs.get_value("cert.State")
        CERT_L =  self.dcs.get_value("cert.Locality")
        CERT_O = self.dcs.get_value("cert.Organization")
        CERT_OU = self.dcs.get_value("cert.OrganizationalUnit")
        CERT_EMAIL = self.dcs.get_value("cert.email")
        FQDN = self.dcs.get_value("FQDN")
        SAN = "DNS:%s, email:%s"%(FQDN,CERT_EMAIL)

        cert.get_subject().C = CERT_C
        cert.get_subject().ST = CERT_ST
        cert.get_subject().L = CERT_L
        cert.get_subject().O = CERT_O
        cert.get_subject().OU = CERT_OU
        cert.get_subject().CN = FQDN
        cert.set_serial_number(self.serial)
        cert.add_extensions(self.get_san_extension_ca(SAN))

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(years*365*24*60*60)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')
        self.serial+=1

        ca_path = self.make_ca_dir()
        cakey_dir = os.path.join(ca_path,"private")
        mkdir_p(cakey_dir)
        cakey_filename = os.path.join(cakey_dir,"cakey.pem")
        with open(cakey_filename, "w") as out:
            out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("UTF-8"))

        cacert_filename = os.path.join(ca_path,"cacert.pem")
        with open(cacert_filename, "w") as out:
            out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8"))

        return self.name_to_rfc4514(cert.get_subject())

    def name_to_rfc4514(self,name):
        # CN=UNITY,OU=IT Services,O=MyOrganization,L=San Francisco,ST=California,C=US
        # RFC4514 is RFC2253 with unicode support and some extra tags we don't care about.
        estring = ""
        for topic,content in reversed(name.get_components()):
            estring += "%s=%s,"%(topic.decode("UTF-8"),content.decode("UTF-8"))
        estring = estring[:-1]
        #TODO: This section still requires escaping of special characters noted in rfc4514
        return estring

    def gen_server_cert(self,server):
        # create a key pair for server and sign it using the CA.
        # CN is daemon name, SAN is FQDN
        # In the special case of Unity we also write the PEM, as we need it for unicorex and probably the workflow server.
        ca_key,ca_cert = self.get_ca_key()

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        years = self.dcs.get_value("cert.years")
        cert = crypto.X509()
        # X509 Version 3 has version number 2! It's the logical choice
        cert.set_version(2)
        CERT_C = self.dcs.get_value("cert.Country")
        CERT_ST = self.dcs.get_value("cert.State")
        CERT_L = self.dcs.get_value("cert.Locality")
        CERT_O = self.dcs.get_value("cert.Organization")
        CERT_OU = self.dcs.get_value("cert.OrganizationalUnit")
        CERT_EMAIL = self.dcs.get_value("cert.email")
        FQDN = self.dcs.get_value("Domains.%s"%server)

        SAN = "DNS:%s, email:%s" % (FQDN, CERT_EMAIL)

        cert.get_subject().C = CERT_C
        cert.get_subject().ST = CERT_ST
        cert.get_subject().L = CERT_L
        cert.get_subject().O = CERT_O
        cert.get_subject().OU = CERT_OU
        cert.get_subject().CN = server
        cert.set_serial_number(self.serial)

        cert.add_extensions(self.get_san_extension(SAN))

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(years * 365 * 24 * 60 * 60)

        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(ca_key, 'sha1')
        self.serial += 1

        certpath, unity_path = self.make_cert_dirs()

        priv_key_path = os.path.join(certpath, server.lower()) + ".p12"

        passphrase = self.dcs.get_value('KeystorePass.%s'%server)
        pfx = crypto.PKCS12Type()
        pfx.set_privatekey(key)
        pfx.set_certificate(cert)
        pfxdata = pfx.export(passphrase)
        with open(priv_key_path, 'wb') as pfxfile:
            pfxfile.write(pfxdata)

        if server == "UNITY":
            unity_cert_path = os.path.join(unity_path,"unity.pem")
            with open(unity_cert_path,'w') as out:
                out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8"))

        return self.name_to_rfc4514(cert.get_subject())
