# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
import atexit
from lxml import etree

from OpenSSL import crypto

from DaemonCerts.DaemonCertsSettings import DaemonCertsSettings
from DaemonCerts.UNITYInitializerWriter import write_groovy_script, write_unity_module
from DaemonCerts.VOConfigWriter import write_vo_config
from DaemonCerts.utility.misc_file_functions import mkdir_p

import os, shutil
from os.path import join,sep


class DaemonCerts(object):
    def __init__(self,sysargs):
        super(DaemonCerts,self).__init__()
        self.dcs = DaemonCertsSettings()
        try:
            self.dcs.parse_eq_args(sysargs, createdicts=False)
        except Exception as e:
            self.write_info_text()
            raise
        self.dcs.finalize()

        self.servers = [ "GATEWAY",
                         "XUUDB",
                         "UNICOREX",
                         "REGISTRY",
                         "UNITY",
                         "WORKFLOW",
                         "SERVORCH",
                         "TSI"
                       ]

        FQDN = self.dcs.get_value("FQDN")
        if FQDN == "unicore.sample-fqdn.com" or len(sysargs) == 0:
            self.write_info_text()
            sys.exit(0)

        ca_path = self.dcs.get_value('directory.ca')
        mkdir_p(ca_path)
        serialpath = join(ca_path,"serial")
        self.serial = None
        if os.path.isfile(serialpath):
            with open(serialpath,'rt') as serialfile:
                for line in serialfile:
                    self.serial = int(line, 16)
                    break

        if self.serial is None:
            self.serial = 1

        atexit.register(self.cleanup)

        unipath = self.dcs.get_value("directory.unicore")
        #builds: unicore_path/daemon_name/conf/filename:
        get_path = lambda daemon, filename : "%s%s%s%s%s%s%s" %(unipath,sep,daemon,sep,"conf",sep,filename)
        # Dict { filename : { "values" : [ ("XPATH","VALUE") , ("XPATH","VALUE"), ... ]
        #                    "attrib" : [ ("XPATH","ATTRIB",VALUE) , ("XPATH","ATTRIB","VALUE"), ... ]
        # TODO: We are still missing lifetime infinity!
        self.vo_paths = [
            (self.dcs.get_value("GCID"),get_path("unicorex", "vo.config")),
            ("SERVORCH",get_path("servorch", "vo.config")),
            (self.dcs.get_value("WF-GCID"),get_path("workflow", "vo.config")),
            ("REGISTRY",get_path("registry", "vo.config"))
        ]

        self.static_xml_changes = {
            get_path("unicorex","xnjs_legacy.xml") :
            {
                "values" : [],
                "attrib" : [
                    ("//eng:Property[@name='CLASSICTSI.ssl.disable']","value","false"),
                    ("//eng:Property[@name='CLASSICTSI.machine']", "value", "%s" %self.dcs.get_value("Domains.TSI")),
                    ("//eng:Property[@name='XNJS.idbfile']", "value", "conf/sidbdir")
                ]
            },
            get_path("unicorex", "wsrflite.xml"):
            {
                "values": [],
                "attrib": [
                    ("//property[@name='container.baseurl']", "value", "https://%s:%d/%s/services"%
                                    (self.dcs.get_value("Domains.GATEWAY"),
                                     self.dcs.get_value("Port.GATEWAY"),
                                     self.dcs.get_value("GCID")
                                     )),
                    ("//property[@name='container.host']", "value", self.dcs.get_value("Domains.UNICOREX") ),
                    ("//property[@name='container.security.credential.password']", "value", self.dcs.get_value("KeystorePass.UNICOREX")),
                    ("//property[@name='container.client.serverHostnameChecking']", "value", "WARN"),
                    ("//property[@name='container.wsrf.lifetime.default']", "value", self.dcs.get_value("lifetime.default")),
                    ("//property[@name='container.wsrf.lifetime.JobManagement']", "value", self.dcs.get_value("lifetime.default")),
                    ("//property[@name='container.wsrf.lifetime.StorageManagement']", "value", self.dcs.get_value("lifetime.default")),
                ]
            },
            get_path("workflow", "wsrflite.xml"):
            {
                "values": [],
                "attrib": [
                    ("//property[@name='container.baseurl']", "value", "https://%s:%d/%s/services" %
                     (self.dcs.get_value("Domains.GATEWAY"),
                      self.dcs.get_value("Port.GATEWAY"),
                      self.dcs.get_value("WF-GCID")
                      )),
                    ("//property[@name='container.host']", "value", self.dcs.get_value("Domains.WORKFLOW")),
                    ("//property[@name='container.security.credential.password']", "value", self.dcs.get_value("KeystorePass.WORKFLOW")),
                    ("//property[@name='container.client.serverHostnameChecking']", "value", "WARN"),
                    ("//property[@name='container.wsrf.lifetime.default']", "value", self.dcs.get_value("lifetime.workflow")),
                    ("//property[@name='container.wsrf.lifetime.default.WorkflowManagement']", "value", self.dcs.get_value("lifetime.workflow"))
                ]
            },
            get_path("servorch", "wsrflite.xml"):
            {
                "values": [],
                "attrib": [
                    ("//property[@name='container.baseurl']", "value", "https://%s:%d/SERVORCH/services" % (self.dcs.get_value("Domains.GATEWAY"),self.dcs.get_value("Port.GATEWAY"))),
                    ("//property[@name='container.host']", "value", self.dcs.get_value("Domains.SERVORCH")),
                    ("//property[@name='container.security.credential.password']", "value",
                     self.dcs.get_value("KeystorePass.SERVORCH")),
                    ("//property[@name='container.client.serverHostnameChecking']", "value", "WARN")
                ]
            },
            get_path("registry", "wsrflite.xml"):
            {
                "values": [],
                "attrib": [
                    ("//property[@name='container.baseurl']", "value", "https://%s:%d/REGISTRY/services" %
                     (self.dcs.get_value("Domains.GATEWAY"),self.dcs.get_value("Port.GATEWAY"))  ),
                    ("//property[@name='container.host']", "value", self.dcs.get_value("Domains.REGISTRY")),
                    ("//property[@name='container.security.credential.password']", "value",
                     self.dcs.get_value("KeystorePass.REGISTRY")),
                    ("//property[@name='container.client.serverHostnameChecking']", "value", "WARN")
                ]
            }
        }
        self.static_plainfile_changes = {
            get_path("unicorex","uas.config") :
            [
                ("coreServices.targetsystemfactory.xnjs.configfile","conf/xnjs_legacy.xml"),
                ("container.sitename",self.dcs.get_value("GCID")),
                ("coreServices.sms.factory.DEFAULT.path",join(self.dcs.get_value("directory.userfiles"),"storage-factory")),
                ("coreServices.defaultsms.path",join(self.dcs.get_value("directory.userfiles"),"storage"),
                ("container.externalregistry.use","true"),
                ("container.externalregistry.url","https://%s:%d/REGISTRY/services/Registry?res=default_registry"%(self.dcs.get_value("Domains.GATEWAY"),self.dcs.get_value("Port.GATEWAY"))),
                ("container.security.rest.authentication.order","UNITY"),
                ("container.security.rest.authentication.UNITY.class","eu.unicore.services.rest.security.UnitySAMLAuthenticator"),
                ("container.security.rest.authentication.UNITY.address","https://%s:2443/unicore-soapidp/saml2unicoreidp-soap/AuthenticationService"%self.dcs.get_value("Domains.UNITY")),
                ("container.security.rest.authentication.UNITY.validate","true"),
                ("container.security.attributes.XUUDB.xuudbHost","https://%s"%(self.dcs.get_value("Domains.XUUDB"))),
                ("container.security.attributes.XUUDB.xuudbGCID",self.dcs.get_value("GCID")),
                ("container.security.attributes.VO-PULL.class","eu.unicore.uas.security.vo.SAMLPullAuthoriser"),
                ("container.security.attributes.VO-PULL.configurationFile","conf/vo.config"),
                ("container.security.attributes.order", "XUUDB" if self.dcs.get_value("AUTHSERVER") == "XUUDB" else "VO-PULL")
            ],
            get_path("gateway", "connections.properties"):
            [
                ("REGISTRY", "https://%s:7778"% self.dcs.get_value("Domains.REGISTRY")),
                ("SERVORCH", "https://%s:7701" % self.dcs.get_value("Domains.SERVORCH")),
                (self.dcs.get_value("GCID"), "https://%s:7777"% self.dcs.get_value("Domains.UNICOREX")),
                (self.dcs.get_value("WF-GCID"), "https://%s:7700" % self.dcs.get_value("Domains.WORKFLOW"))
            ],
            get_path("gateway", "gateway.properties"):
            [
                #("gateway.hostname", "https://%s:%d" % (self.dcs.get_value("Domains.GATEWAY"),self.dcs.get_value("Port.GATEWAY"))),
                ("gateway.hostname", "https://0.0.0.0:%d" % (self.dcs.get_value("Port.GATEWAY"))),
                ("gateway.httpServer.requireClientAuthn", "false")
            ],
            get_path("gateway", "security.properties"):
            [
                ("gateway.credential.password", self.dcs.get_value("KeystorePass.GATEWAY"))
            ],
            get_path("tsi_selected", "tsi.properties"):
            [
                ("tsi.my_addr", self.dcs.get_value("Domains.TSI")),
                ("tsi.njs_machine", self.dcs.get_value("Domains.UNICOREX")),
                ("tsi.keystore","<UnComment>"),
                ("tsi.keypass",self.dcs.get_value("KeystorePass.TSI")),
                ("tsi.certificate","<UnComment>"),
                ("tsi.truststore","<UnComment>")
            ],
            get_path("xuudb", "xuudb_client.conf"):
            [
                ("xuudb.address","https://%s:34463"%self.dcs.get_value("Domains.XUUDB")),
                ("xuudb.credential.password",self.dcs.get_value("KeystorePass.XUUDB"))
            ],
            get_path("xuudb", "xuudb_server.conf"):
            [
                ("xuudb.address", "https://%s:34463" % self.dcs.get_value("Domains.XUUDB")),
                ("xuudb.credential.password", self.dcs.get_value("KeystorePass.XUUDB"))
            ],
            get_path("unity", "pki.properties"):
            [
                ("unity.pki.credentials.MAIN.path", "conf/pki/unity.p12"),
                ("unity.pki.credentials.MAIN.keyAlias", "<Comment>"),
                ("unity.pki.credentials.MAIN.password", self.dcs.get_value("KeystorePass.UNITY")),
                ("unity.pki.truststores.MAIN.type", "directory"),
                ("unity.pki.truststores.MAIN.directoryLocations.1", "conf/pki/trusted-ca/*.pem"),
                ("unity.pki.truststores.MAIN.crlLocations.1", "conf/pki/trusted-ca/*.crl")
            ],
            get_path("unity","unityServer.conf"):
            [
                ("unityServer.core.initialAdminPassword",self.random_string(16) if self.dcs.get_value("AdminPass") == '<SCRAMBLE>' else self.dcs.get_value("AdminPass")),
                ("unityServer.core.httpServer.host", self.dcs.get_value("Domains.UNITY")),
                ("unityServer.core.httpServer.advertisedHost",  self.dcs.get_value("Domains.UNITY")),
                ("$include.oauthAS","<Comment>"),
                ("$include.demoContents","<Comment>"),
                ("$include.unicoreServerSetup", "${CONF}/modules/unicoreQuickstart.module"),
                ("$include.unicoreWithPam","<UnComment>")
            ],
            get_path("workflow", "uas.config"):
            [
                ("container.sitename", self.dcs.get_value("WF-GCID")),
                ("container.externalregistry.url","https://%s:%d/REGISTRY/services/Registry?res=default_registry"%(self.dcs.get_value("Domains.GATEWAY"),self.dcs.get_value("Port.GATEWAY"))),
                ("container.security.attributes.XUUDB.xuudbHost","https://%s"%self.dcs.get_value("Domains.XUUDB")),
                ("container.security.attributes.XUUDB.xuudbGCID", self.dcs.get_value("GCID")),
                ("container.security.rest.authentication.UNITY.class","eu.unicore.services.rest.security.UnitySAMLAuthenticator"),
                ("container.security.rest.authentication.UNITY.address","https://%s:2443/unicore-soapidp/saml2unicoreidp-soap/AuthenticationService"%self.dcs.get_value("Domains.UNITY")),
                ("container.security.rest.authentication.UNITY.validate","true"),
                ("container.security.rest.authentication.order", "UNITY"),
                ("container.security.attributes.VO-PULL.class","eu.unicore.uas.security.vo.SAMLPullAuthoriser"),
                ("container.security.attributes.VO-PULL.configurationFile","conf/vo.config"),
                ("container.security.attributes.order", "XUUDB" if self.dcs.get_value("AUTHSERVER") == "XUUDB" else "VO-PULL")
            ],
            get_path("registry", "uas.config"):
            [
                ("container.security.attributes.XUUDB.xuudbHost",
                 "https://%s" % self.dcs.get_value("Domains.XUUDB")),
                ("container.security.attributes.XUUDB.xuudbGCID", self.dcs.get_value("GCID")),
                ("container.security.rest.authentication.UNITY.class",
                 "eu.unicore.services.rest.security.UnitySAMLAuthenticator"),
                ("container.security.rest.authentication.UNITY.address",
                 "https://%s:2443/unicore-soapidp/saml2unicoreidp-soap/AuthenticationService" % self.dcs.get_value(
                     "Domains.UNITY")),
                ("container.security.rest.authentication.UNITY.validate", "true"),
                ("container.security.rest.authentication.order", "UNITY"),
                ("container.security.attributes.VO-PULL.class","eu.unicore.uas.security.vo.SAMLPullAuthoriser"),
                ("container.security.attributes.VO-PULL.configurationFile","conf/vo.config"),
                ("container.security.attributes.order", "XUUDB" if self.dcs.get_value("AUTHSERVER") == "XUUDB" else "VO-PULL")
            ],
            get_path("servorch", "uas.config"):
            [
                ("container.externalregistry.url",
                 "https://%s:%d/REGISTRY/services/Registry?res=default_registry" % (self.dcs.get_value(
                     "Domains.GATEWAY"),self.dcs.get_value("Port.GATEWAY"))),
                ("container.security.attributes.XUUDB.xuudbHost",
                 "https://%s" % self.dcs.get_value("Domains.XUUDB")),
                ("container.security.attributes.XUUDB.xuudbGCID", self.dcs.get_value("GCID")),
                ("container.security.rest.authentication.UNITY.class",
                 "eu.unicore.services.rest.security.UnitySAMLAuthenticator"),
                ("container.security.rest.authentication.UNITY.address",
                 "https://%s:2443/unicore-soapidp/saml2unicoreidp-soap/AuthenticationService" % self.dcs.get_value(
                     "Domains.UNITY")),
                ("container.security.rest.authentication.UNITY.validate", "true"),
                ("container.security.rest.authentication.order", "UNITY"),
                ("container.security.attributes.VO-PULL.class","eu.unicore.uas.security.vo.SAMLPullAuthoriser"),
                ("container.security.attributes.VO-PULL.configurationFile","conf/vo.config"),
                ("container.security.attributes.order", "XUUDB" if self.dcs.get_value("AUTHSERVER") == "XUUDB" else "VO-PULL")
            ]
        }

    def random_string(self, length):
        import random
        import string
        randstring = ''.join(random.sample(string.ascii_letters, length))
        return randstring

    def get_san_extension_ca(self,san_string):
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
        truststore_path = join(cert_path, "trusted")
        mkdir_p(truststore_path)
        return truststore_path

    def make_cert_dirs(self):
        cert_path = self.dcs.get_value('directory.certs')
        mkdir_p(cert_path)

        unity_path = join(cert_path,"unity")
        mkdir_p(unity_path)
        return cert_path,unity_path

    def write_serial(self):
        ca_path = self.make_ca_dir()
        serialpath = join(ca_path, "serial")
        with open(serialpath, 'w') as serialfile:
            serialfile.write("%s\n"% hex(self.serial)[2:])

    def write_info_text(self):
        help_message="""
   ---- UNICORE Daemon Cert Generator ----
        
       Copyright Nanomatch GmbH 2017

   Usage:
   CreateDaemonCerts.py parameter2=value2 parameter2=value2. A list of all parameters follows:

   A typical command to generate Daemon Certs for all UNICORE server daemons would be:

   CreateDaemonCerts.py FQDN=myhost.domain.com \\
                        cert.email=admin@your_mail.de \\
                        "cert.OrganizationalUnit=IT Services" \\
                        "cert.Organization=NM GmbH" \\
                        cert.Country=DE \\
                        cert.Locality=Karlsruhe \\
                        "cert.State=BW" \\
                        GCID=MY-SITE \\
                        Port.GATEWAY=8080 \\
                        directory.userfiles=/network/fast/directory 
     
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
        if not os.path.isfile(join(ca_path,"cacert.pem")):
            dn = self.gen_ca()
            print("Generated new CA, DN: <%s>"%dn)

        support_path_dir = self.dcs.get_value("directory.support")
        xuudb_file = join(support_path_dir,"xuudb_commands.sh")
        rfc_file = join(support_path_dir,"rfc4514_dns.txt")
        mkdir_p(support_path_dir)
        dn_list = []
        with open(xuudb_file,'w') as xuudb_com:
            with open(rfc_file, 'w') as rfc:
                gcid = self.dcs.get_value("GCID")
                for server in self.servers:
                    dn =self.gen_server_cert(server)
                    print("Generated key for server %s DN: <%s>" % (server,dn))
                    xcom = "bin/admin.sh adddn %s \"%s\" nobody server" %(gcid,dn)
                    xuudb_com.write("%s\n"%xcom)
                    rfc.write("%s\n"%dn)
                    self.dn_hooks(server,dn)
                    dn_list.append((server,dn))

        self.post_update(dn_list)
        with open(join(support_path_dir, "urlinfo.txt"), 'w') as out:
            gwurl = self.dcs.get_value("Domains.GATEWAY")
            unityurl = self.dcs.get_value("Domains.UNITY")
            port = self.dcs.get_value("Port.GATEWAY")
            gcid = self.dcs.get_value("GCID")
            wf_gcid = self.dcs.get_value("WF-GCID")
            cert = join(self.dcs.get_value("directory.certs"),'trusted','cacert.pem')
            infostring = """To setup REST Clients, the following two URLs are required:
   Base URI: https://%s:%d/%s/rest/core
   Workflow Link: https://%s:%d/%s/rest/workflows
            
 To setup UNICORE Clients, the following two URLs are required:
   Unity Address: https://%s:2443/unicore-soapidp/saml2unicoreidp-soap/AuthenticationService
   Registry Address: https://%s:%d/REGISTRY/services/Registry?res=default_registry
   They also require access to the following truststore: %s
   Please distribute this file and the truststore to all your users.
            """ %(gwurl,port,gcid,
                  gwurl,port,wf_gcid,
                  unityurl,
                  gwurl,port,
                  cert)
            print(infostring)
            out.write(infostring)


    def update_xml(self,filename,attrib_and_value_dict):
        tree = None
        if os.path.isfile(filename):
            with open(filename,'r') as xmlin:
                tree = etree.parse(xmlin)

            for xpath,value in attrib_and_value_dict["values"]:
                print("Changing File <%s>, Path <%s> to: %s"%(filename,xpath,value))
                self.change_xml_value(tree,xpath,value)

            for xpath,attrib,value in attrib_and_value_dict["attrib"]:
                print("Changing File <%s>, Path:Attribute <%s>:<%s> to: %s" % (filename, xpath, attrib, value))
                self.change_xml_attrib(tree,xpath,attrib,value)

            with open(filename, 'w') as xmlout:
                xmlout.write(etree.tostring(tree,encoding="UTF-8").decode("UTF-8"))
        #Else we just write out the instructions
        else:
            mkdir_p(os.path.dirname(filename))
            with open(filename + ".instructions.txt",'w') as xmlout:
                for xpath, value in attrib_and_value_dict["values"]:
                    print("Writing Instructions in File <%s>, Path <%s> to: %s" % (filename, xpath, value))
                    xmlout.write("Change value of path <%s> to: <%s>\n"%(xpath,value))
                for xpath, attrib, value in attrib_and_value_dict["attrib"]:
                    print("Writing Instructions in File <%s>, Path:Attribute <%s>:<%s> to: %s" % (filename, xpath, attrib, value))
                    xmlout.write("Change attribute <%s> of path <%s> to: <%s>\n" % (attrib, xpath, value))

    def change_xml_value(self,tree,xpath_expression,value):
        #xpath_expression: "//eng:Property[@name='CLASSICTSI.ssl.disable']"
        #value is string
        root = tree.getroot()
        test = tree.find(xpath_expression, namespaces=root.nsmap)
        test.text = value

    def change_xml_attrib(self,tree,xpath_expression,attrib,value):
        #xpath_expression: "//eng:Property[@name='CLASSICTSI.ssl.disable']"
        #attrib is string
        #value is string
        root = tree.getroot()
        xmlnode = tree.find(xpath_expression, namespaces=root.nsmap)
        xmlnode.attrib[attrib] = value


    def post_update(self,dn_list):
        for filename,attrib_and_value_dict in self.static_xml_changes.items():
            self.update_xml(filename,attrib_and_value_dict)
        for filename, changelist in self.static_plainfile_changes.items():
            for key,value in changelist:
                self.create_add_change_plain(filename,key,value)

        cert_dir = self.dcs.get_value("directory.certs")
        pem_rel_loc = join(cert_dir, "unity", "unity.pem")
        pem_abs_loc = os.path.abspath(pem_rel_loc)
        unity_fqdn = self.dcs.get_value("Domains.UNITY")
        gateway_fqdn = self.dcs.get_value("Domains.GATEWAY")
        gateway_port = self.dcs.get_value("Port.GATEWAY")
        for component,vofile in self.vo_paths:
            with open(vofile,'wt') as out:
                out.write(write_vo_config(pem_abs_loc,component,unity_fqdn,gateway_fqdn,gateway_port))

        #Finally we write the unity config:
        unity_conf_dir = join(self.dcs.get_value("directory.unicore"),"unity","conf")
        content_init_file = join(unity_conf_dir,"scripts")
        mkdir_p(content_init_file)
        content_init_file = join(content_init_file,"unicoreServerContentInitializer.groovy")
        with open(content_init_file,'w') as out:
            out.write(write_groovy_script(dn_list))

        module_init_file = join(unity_conf_dir,"modules")
        mkdir_p(module_init_file)
        module_init_file = join(module_init_file,"unicoreQuickstart.module")
        with open(module_init_file,'w') as out:
            out.write(write_unity_module())

        unicorex_conf_dir = join(self.dcs.get_value("directory.unicore"), "unicorex", "conf")
        simpleidb = join(unicorex_conf_dir,'simpleidb')
        sidbdir = join(unity_conf_dir,'sidbdir')
        mkdir_p(sidbdir)
        #We only move in case it exists. This allows us to run this installer more often.
        if os.path.isfile(simpleidb):
            shutil.move(simpleidb,sidbdir)

        filespacedir = join(self.dcs.get_value("directory.userfiles"),"storage")
        mkdir_p(filespacedir)
        os.chmod(filespacedir,0o1777)
        storagefactorydir = join(self.dcs.get_value("directory.userfiles"),"storage-factory")
        mkdir_p(storagefactorydir)
        os.chmod(storagefactorydir,0o1777)

    def create_add_change_plain(self,filename,key,value):
        print("File: <%s>, Changing value of key <%s> to <%s>" % (filename, key, value))
        if os.path.isfile(filename):
            found = False
            outname = filename + '_new'
            with open(filename, 'rt') as myin:
                with open(outname,'wt') as myout:
                    for line in myin:
                        if "=" in line:
                            splitline = line.split("=")
                            keypruned = splitline[0].replace(" ","")
                            if keypruned == key or keypruned == "#%s"%key:
                                found = True
                                if value == "<UnComment>":
                                    if line.startswith("#"):
                                        myout.write(line[1:])
                                    else:
                                        myout.write(line)
                                elif value == "<Comment>":
                                    if line.startswith("#"):
                                        myout.write(line)
                                    else:
                                        myout.write("#%s"%line)
                                else:
                                    myout.write("%s=%s\n" % (key, value))

                            else:
                                myout.write(line)
                        else:
                            myout.write(line)
                    if not found:
                        if not "Comment" in value:
                            myout.write("%s=%s\n" % (key, value))
            shutil.move(outname,filename)
        else:
            mkdir_p(os.path.dirname(filename))
            with open(filename,'a') as out:
                out.write("%s=%s\n"%(key,value))

    def dn_hooks(self,server,dn):
        #Here we write specific template files for the servers, where specific DNs are required, such as ACLs.
        unicore_dir = self.dcs.get_value("directory.unicore")
        server_confdir = join(unicore_dir,server.lower(),"conf")

        if server == 'XUUDB':
            mkdir_p(server_confdir)
            acl_file = join(server_confdir,"xuudb.acl")
            with open(acl_file,'wt') as acl:
                acl.write("%s\n"%dn)

        elif server == 'UNICOREX':
            #UNICOREX DN has to be known by TSI:
            tsi_confdir = join(unicore_dir,"tsi_selected","conf")
            mkdir_p(tsi_confdir)
            tsi_conffile = join(tsi_confdir,"tsi.properties")
            self.create_add_change_plain(tsi_conffile,"tsi.allowed_dn.1",dn)

    def get_ca_key(self):
        ca_path = self.dcs.get_value('directory.ca')
        ca_key_path = join(ca_path,"private","cakey.pem")
        ca_key_data = ""
        with open(ca_key_path,'rt') as ca_key_file:
            ca_key_data = ca_key_file.read()

        key = crypto.load_privatekey(crypto.FILETYPE_PEM,ca_key_data)

        ca_cert_path = join(ca_path,"cacert.pem")
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
        cakey_dir = join(ca_path,"private")
        mkdir_p(cakey_dir)
        cakey_filename = join(cakey_dir,"cakey.pem")
        with open(cakey_filename, "w") as out:
            out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("UTF-8"))
        os.chmod(out, 0o600)

        cacert_filename = join(ca_path,"cacert.pem")
        with open(cacert_filename, "w") as out:
            out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8"))

        #Here we save the pem again in the trusted directory:
        trustedpath = self.make_truststore_dir()
        trustedpem = join(trustedpath,"cacert.pem")
        with open(trustedpem, "w") as out:
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

        priv_key_path = join(certpath, server.lower()) + ".p12"

        passphrase = self.dcs.get_value('KeystorePass.%s'%server)
        pfx = crypto.PKCS12Type()
        pfx.set_privatekey(key)
        pfx.set_certificate(cert)
        pfxdata = pfx.export(passphrase)
        with open(priv_key_path, 'wb') as pfxfile:
            pfxfile.write(pfxdata)
        os.chmod(pfxfile, 0o600)

        if server == "UNITY":
            # Unity PEM needs to be "trusted" as saml assertion issuer by unicorex
            unity_cert_path = join(unity_path,"unity.pem")
            with open(unity_cert_path,'w') as out:
                out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8"))

            # Unity defaults to a jks truststore:
            unicore_dir = self.dcs.get_value("directory.unicore")
            unity_pki_dir = join(unicore_dir, "unity", "conf","pki")
            unity_truststore_path = join(unity_pki_dir,"trusted-ca")
            mkdir_p(unity_truststore_path)
            unity_privatekey = join(unity_pki_dir,"unity.p12")
            with open(unity_privatekey, 'wb') as pfxfile:
                pfxfile.write(pfxdata)
            os.chmod(pfxfile, 0o600)

            mkdir_p(unity_truststore_path)
            unity_truststore_path = join(unity_truststore_path,"truststore.pem")
            with open(unity_truststore_path,'w') as out:
                out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("UTF-8"))

        if server == "TSI":
            # TSI needs its cert and key both in PEM format
            unicore_dir = self.dcs.get_value("directory.unicore")
            server_confdir = join(unicore_dir, "tsi_selected", "conf")
            mkdir_p(server_confdir)
            tsi_cert_path = join(server_confdir, "tsi-cert.pem")

            tsi_truststore_path = join(server_confdir, "tsi-truststore.pem")
            with open(tsi_truststore_path,'w') as out:
                out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("UTF-8"))

            with open(tsi_cert_path, 'w') as out:
                out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8"))

            tsi_key_path = join(server_confdir, "tsi-key.pem")
            tsi_passphrase = self.dcs.get_value("KeystorePass.TSI")
            with open(tsi_key_path, 'w') as out:
                out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, passphrase=tsi_passphrase.encode("UTF-8")).decode("UTF-8"))
            os.chmod(tsi_key_path, 0o600)

        return self.name_to_rfc4514(cert.get_subject())
