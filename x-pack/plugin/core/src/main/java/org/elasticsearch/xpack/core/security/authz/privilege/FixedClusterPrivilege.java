/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

/**
 * A {@link ClusterPrivilege} that is statically defined. It has a single name, and cannot be configured.
 */
public interface FixedClusterPrivilege extends ClusterPrivilege {

    String name();

}
