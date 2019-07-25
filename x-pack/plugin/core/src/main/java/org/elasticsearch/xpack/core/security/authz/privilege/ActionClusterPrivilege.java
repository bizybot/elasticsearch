/*
 *
 *  * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  * or more contributor license agreements. Licensed under the Elastic License;
 *  * you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;

import java.util.Set;

public class ActionClusterPrivilege implements NameableClusterPrivilege {
    private final String name;
    private final Set<String> allowedActionPatterns;
    private final Set<String> deniedActionPatterns;

    public ActionClusterPrivilege(String name, Set<String> allowedActionPatterns) {
        this(name, allowedActionPatterns, Set.of());
    }

    public ActionClusterPrivilege(String name, Set<String> allowedActionPatterns, Set<String> deniedActionPatterns) {
        this.name = name;
        this.allowedActionPatterns = allowedActionPatterns;
        this.deniedActionPatterns = deniedActionPatterns;
    }

    @Override
    public String name() {
        return name;
    }

    public Set<String> getAllowedActionPatterns() {
        return allowedActionPatterns;
    }

    public Set<String> getDeniedActionPatterns() {
        return deniedActionPatterns;
    }

    @Override
    public ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
        return builder.add(this, allowedActionPatterns, deniedActionPatterns);
    }

}
