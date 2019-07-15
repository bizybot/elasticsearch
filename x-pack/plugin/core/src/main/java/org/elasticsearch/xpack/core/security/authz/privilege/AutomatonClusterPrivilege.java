/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;

/**
 * A {@link ClusterPrivilege} that is implemented using an {@link Automaton} over an action name.
 */
public interface AutomatonClusterPrivilege extends ClusterPrivilege {

    Automaton automaton();

    default ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
        return builder.add(this);
    }
}
