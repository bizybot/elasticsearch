/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;

/**
 * This class represents cluster level privileges that can be used to define user permissions.
 */
public interface ClusterPrivilege {

    /**
     * Builds a {@link ClusterPermission} from this privilege
     * @param builder {@link ClusterPermission.Builder} used to build the permission
     * @return {@link ClusterPermission.Builder}
     */
    ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder);
}
