/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;

public interface ClusterPrivilege {
    ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder);
}
