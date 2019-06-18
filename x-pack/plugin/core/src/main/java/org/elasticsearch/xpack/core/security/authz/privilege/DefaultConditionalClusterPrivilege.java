/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Enum that defines default conditional cluster privileges
 */
enum DefaultConditionalClusterPrivilege {
    MANAGE_OWN_API_KEY("manage_own_api_key", ManageApiKeyConditionalClusterPrivilege.createOwnerManageApiKeyConditionalClusterPrivilege());

    final ConditionalClusterPrivilege conditionalClusterPrivilege;
    private final String privilegeName;

    private static Map<String, DefaultConditionalClusterPrivilege> privilegeNameToEnumMap = new HashMap<>();
    private static Map<ConditionalClusterPrivilege, DefaultConditionalClusterPrivilege> ccpToEnumMap = new HashMap<>();
    static {
        for (DefaultConditionalClusterPrivilege privilege : values()) {
            privilegeNameToEnumMap.put(privilege.privilegeName, privilege);
            ccpToEnumMap.put(privilege.conditionalClusterPrivilege, privilege);
        }
    }

    DefaultConditionalClusterPrivilege(final String privilegeName, final ConditionalClusterPrivilege conditionalClusterPrivilege) {
        this.privilegeName = privilegeName;
        this.conditionalClusterPrivilege = conditionalClusterPrivilege;
    }

    ConditionalClusterPrivilege conditionalClusterPrivilege() {
        return conditionalClusterPrivilege;
    }

    static DefaultConditionalClusterPrivilege fromString(String privilegeName) {
        return privilegeNameToEnumMap.get(privilegeName);
    }

    static String privilegeName(ConditionalClusterPrivilege ccp) {
        if (ccpToEnumMap.containsKey(ccp)) {
            return ccpToEnumMap.get(ccp).privilegeName;
        }
        return null;
    }

    static Set<String> names() {
        return privilegeNameToEnumMap.keySet();
    }
}