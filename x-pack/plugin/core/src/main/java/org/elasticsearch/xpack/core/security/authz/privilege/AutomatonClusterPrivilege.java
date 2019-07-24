/*
 *
 *  Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  or more contributor license agreements. Licensed under the Elastic License;
 *  you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;

/**
 * A {@link ClusterPrivilege} that uses {@link Automaton} for predicates.
 * For example, a cluster privilege that uses automaton based predicate to determine which
 * cluster actions are allowed.
 */
public interface AutomatonClusterPrivilege extends ClusterPrivilege {
    Automaton automaton();
}
