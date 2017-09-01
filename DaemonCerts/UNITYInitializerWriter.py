# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals


def write_groovy_script(dn_list):
    template = """
/*
 * Script adding UNICORE server DN to /unicore/servers group.  
 *
 * Depends on unicoreContentInitializer.groovy
 */

import java.util.Map;

import pl.edu.icm.unity.stdext.attr.StringAttribute;
import pl.edu.icm.unity.stdext.credential.PasswordToken;
import pl.edu.icm.unity.stdext.identity.X500Identity;
import pl.edu.icm.unity.types.basic.Attribute;
import pl.edu.icm.unity.types.basic.AttributeType;
import pl.edu.icm.unity.types.basic.EntityParam;
import pl.edu.icm.unity.types.basic.EntityState;
import pl.edu.icm.unity.types.basic.Identity;
import pl.edu.icm.unity.types.basic.IdentityParam;
import pl.edu.icm.unity.types.basic.IdentityTaV;

import groovy.transform.Field


@Field final String CN_ATTR = "cn"


if (!isColdStart)
{
        log.debug("Database already initialized with content, skipping...");
        return;
}

try
{
        Map<String, AttributeType> existingATs = attributeTypeManagement.getAttributeTypesAsMap();
        if (!existingATs.containsKey("urn:unicore:attrType:role"))
        {
                log.error("UNICORE server can be only installed if the main UNICORE initialization was performed.");
                return;
        }
"""
    for servername,dn in dn_list:
        template += 'addServer("%s", "%s");\n'%(dn,servername)
    template +="""
} catch (Exception e)
{
        log.warn("Error loading demo UNICORE contents. This is not critical and usaully " +
                        "means that your existing data is in conflict with the loaded contents.", e);
}


void addServer(String dn, String cn)
{
        IdentityParam unicoreClient = new IdentityParam(X500Identity.ID, dn);
        Identity unicoreClientA = entityManagement.addEntity(unicoreClient, "Certificate",
                        EntityState.valid, false);
        EntityParam Server = new EntityParam(unicoreClientA.getEntityId());
        groupsManagement.addMemberFromParent("/unicore", Server);
        groupsManagement.addMemberFromParent("/unicore/servers", Server);
        log.info("Adding DN: ",dn," with CN: ",cn," to UNITY.");
        Attribute cnA = StringAttribute.of(CN_ATTR, "/", cn);
        attributesManagement.setAttribute(Server, cnA, false);
}
"""
    return template

def write_unity_module():
    template = """# initialization script: creates groups structure and UNICORE attribute types
unityServer.core.script.9002.file=${CONF}/scripts/unicoreServerContentInitializer.groovy
unityServer.core.script.9002.trigger=pre-init
"""
    return template
