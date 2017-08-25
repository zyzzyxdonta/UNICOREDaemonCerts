# UNICOREDaemonCerts

## Description
UNICOREDaemonCerts creates the certificates and private keys for standard UNICORE installations. The output paths and keystore passes are set to the ones used in a standard UNICORE install.

## Usage:
CreateDaemonCerts.py parameter2=value2 parameter2=value2. A list of all parameters follows:

A typical command to generate Daemon Certs for all UNICORE server daemons would be:

    CreateDaemonCerts.py FQDN=int-bionano.it.kit.edu \
                        cert.email=admin@your_mail.de \
                        "cert.OrganizationalUnit=IT Services" \
                        "cert.Organization=Nanomatch GmbH" \
                        cert.Country=DE \
                        cert.Locality=Karlsruhe \
                        "cert.State=Baden Württemberg" \
                        GCID=NANO-SITE 

                        
## Requirements
1. A recent version of pyopenssl
2. python3 is tested, python2 should work, but is unsupported.

## Remarks
* Country can only be two letter code. 
* Even though you can change the keystore passwords, doesn't mean you need to. They only exist, because you cannot save an unprotected p12 keystore. You do not gain security by changing them.
* Don't use umlauts and special characters such as +,-,\0, etc. for the moment. Umlauts are treated differently in RFC2253 and RFC4514 and XUUDB support should be RFC2253, but it also accepts RFC4514 and you should therefore only use the subset, which is treated equal among both.
* Individiual daemon domains can specified using: Domains.SERVER=FQDN. This is completely optional. Don't do it unless you really need it. (You need it, if different daemons run on different servers).

## Output
The program will generate the certs and the following files:
* rfc4514_dns.txt contains the generated server DNs in the rfc4514 format.
* xuudb_commands.sh contains the server DNs again including the commands, which have to be executed to add them to XUUDB.

## License
BSD 3-Clause

## Copyright
Nanomatch GmbH 2017

## TODO
* Find out, which standard is supported by XUUDB.
* Testing.
