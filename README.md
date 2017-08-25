# UNICOREDaemonCerts

## Description
UNICOREDaemonCerts creates the certificates and private keys for standard UNICORE installations. The output paths and keystore passes are set to the ones used in a standard UNICORE install.

## Usage:

Call CreateDaemonCerts.py without parameters to show all parameters and their default values.

Usage is: CreateDaemonCerts.py parameter2=value2 parameter2=value2.
A typical command to generate Daemon Certs for all UNICORE server daemons would be:

    CreateDaemonCerts.py FQDN=myhost.domain.com \
                        cert.email=admin@your_mail.de \
                        "cert.OrganizationalUnit=IT Services" \
                        "cert.Organization=NM GmbH" \
                        cert.Country=DE \
                        cert.Locality=Karlsruhe \
                        "cert.State=BW" \
                        GCID=MY-SITE 

                        
## Requirements
1. A recent version of pyopenssl
2. python3 is tested, python2 should work, but is unsupported.

## Remarks
* Country can only be two letter code. 
* Even though you can change the keystore passwords, doesn't mean you need to. They only exist, because you cannot save an unprotected p12 keystore. You do not gain security by changing them.
* Don't use umlauts and special characters such as +,-,\0, etc. for the moment. Umlauts are treated differently in RFC2253 and RFC4514 and XUUDB support should be RFC2253, but it also accepts RFC4514 and you should therefore only use the subset, which is treated equal among both.
* Individiual daemon domains can specified using: Domains.SERVER=FQDN. This is completely optional. Don't do it unless you really need it. (You need it, if different daemons run on different servers).

## Output
The program will generate the certs (also the CA certs, if not existing) and the following files:
* rfc4514_dns.txt contains the generated server DNs in the rfc4514 format.
* xuudb_commands.sh contains the server DNs again including the commands, which have to be executed to add them to XUUDB.

## Using a existing CA
In this case you need to have the following filestructure in your directory.CA=CA_DIR directory.
* CADIR/cacert.pem contains the CA certificates.
* CADIR/private/cakey.pem contains the CA private key
* CADIR/serial contains the next usable serial as hex

WARNING: this is untested. Especially it does not keep standed /etc/ssl/index.* files updated. The only thing, which is kept updated is serial. Don't use it with a production CA, unless you made lots of backups.

## License
BSD 3-Clause

## Copyright
Nanomatch GmbH 2017

## TODO
* Find out, which standard is supported by XUUDB.
* In case of existing CA, keep index.txts updated.
* Testing.
