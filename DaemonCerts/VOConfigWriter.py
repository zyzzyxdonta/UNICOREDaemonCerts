# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals


def write_vo_config(UNITY_PEM_LOCATION,COMPONENT,UNITY_FQDN,GATEWAY_FQDN,GATEWAY_PORT):
    template = """# ##########################
# General configuration
# ##########################

# VO or group which is accepted by this attribute source. Server will honor
#  only attributes with exactly this scope or global (i.e. without scope set).
vo.group=/unicore/%s

# Those attributes specify a truststore, with certificates (not corresponding CA's
#  certificates!) of trusted VO services. NEVER use the SSL truststore of UNICORE/X
#  for this purpose as it effectively turns off the whole authorization!
#  It is used for push mode and in pull mode when signature verification is enabled.

vo.truststore.type=directory
vo.truststore.directoryLocations.1=%s


# It is REQUIRED if pull mode is enabled, and must be this server's URI used to identify
#  to the VO service. In push mode it is used as this server actor's name (note that
#  assertions in WS security element with no actor set are also accepted).
vo.localServerURI=https://%s:%d/%s

# Unity server identification URI
vo.voServerURI=https://%s:2443/unicore-soap-aip/saml2unicoreidp-soap/AssertionQueryService

# This group of settings defines mapping of SAML attributes to UNICORE incarnation attributes.
# If you use UVOS and standard attributes there you don't have to change them.
# See documentation for details.
vo.unicoreAttribute.xlogin=urn:unicore:attrType:xlogin
vo.unicoreAttribute.xlogin.default=urn:unicore:attrType:defaultXlogin
vo.unicoreAttribute.role=urn:unicore:attrType:role
vo.unicoreAttribute.role.default=urn:unicore:attrType:defaultRole
vo.unicoreAttribute.group=urn:unicore:attrType:primaryGid
vo.unicoreAttribute.group.default=urn:unicore:attrType:defaultPrimaryGid
vo.unicoreAttribute.supplementaryGroups=urn:unicore:attrType:supplementaryGids
vo.unicoreAttribute.supplementaryGroups.default=urn:unicore:attrType:defaultSupplementaryGids
vo.unicoreAttribute.addDefaultGroups=urn:unicore:attrType:addDefaultGroups
vo.unicoreAttribute.queue=urn:unicore:attrType:queue
vo.unicoreAttribute.queue.default=urn:unicore:attrType:defaultQueue
vo.unicoreAttribute.virtualOrganisations=urn:SAML:voprofile:group



# ##########################
# PULL mode configuration
# ##########################

# Enable this mode? Default is false. Usually you can leave it with true value and control
# whether the mode is enabled by using (or not) a respective attribute source in uas.config.
vo.pull.enable=true

vo.pull.enableGenericAttributes=true

# Full URL of SAML VO service.
# Note that this server's CA cert must be present in UNICORE/X truststore.
vo.pull.voServerURL=https://%s:2443/unicore-soap-aip/saml2unicoreidp-soap/AssertionQueryService

# Additional security (except transport level which is always on) can be achieved by
#  verification of signatures. The key which is used for verification must be present
#  in vo.truststore (see above) and have an alias defined below. Default is true.

# Whether pull mode should be skipped if user sent (or pushed) some attributes with the request.
#  Note that to make this feature work PUSH mode must be enabled AND PULL authorizer must
#  be invoked AFTER the PUSH authorizer.
vo.pull.disableIfAttributesWerePushed=false

# Caching time of pulled attributes (in seconds). Use negative value to turn off the cache.
vo.pull.cacheTtl=300


# ##########################
# PUSH mode configuration
# ##########################

# Enable this mode? Default is false. Usually you can leave it with true value and control
# whether the mode is enabled by using (or not) a respective attribute source in uas.config.
vo.push.enable=false
"""%(COMPONENT,UNITY_PEM_LOCATION,GATEWAY_FQDN,GATEWAY_PORT,COMPONENT,UNITY_FQDN,UNITY_FQDN)
    return template
