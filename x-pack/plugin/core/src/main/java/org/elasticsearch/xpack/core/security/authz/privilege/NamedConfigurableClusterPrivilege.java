/*
 *
 *  * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  * or more contributor license agreements. Licensed under the Elastic License;
 *  * you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;

/**
 * A {@link ConfigurableClusterPrivilege} that is  statically defined with a logical name that provides access to actions via an
 * {@link Automaton} and determine whether the request is permitted in the context of given authentication
 * {@link ConfigurableClusterPrivilege}.
 */
public interface NamedConfigurableClusterPrivilege extends NameableClusterPrivilege, ConfigurableClusterPrivilege {
}
