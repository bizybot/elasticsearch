/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.function.BiPredicate;

/**
 * A {@link ConfigurableClusterPrivilege} is an interface that helps adding a condition to a {@link AutomatonClusterPrivilege}, that
 * defines a {@link BiPredicate} for a {@link TransportRequest} (that determines which requests may be executed) and a
 * {@link Authentication} (for current authenticated user).
 * The predicate can be used to determine if the request is permitted in the context of given authentication.
 */
public interface ConfigurableClusterPrivilege extends AutomatonClusterPrivilege {

    /**
     * The request-level privilege (as a {@link BiPredicate}) that is required by this configurable privilege that acts in the
     * context of given authentication.
     */
    BiPredicate<TransportRequest, Authentication> getRequestPredicate();

    default ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
        return builder.add(this, Automatons.predicate(automaton()), getRequestPredicate());
    }
}
