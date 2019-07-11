/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.support.Automatons;

/**
 * A {@link ClusterPrivilege} that grants direct access to one or more actions
 */
public final class ActionClusterPrivilege implements FixedClusterPrivilege, AutomatonClusterPrivilege {

    private final String action;
    private final Automaton automaton;

    public ActionClusterPrivilege(String action) {
        this.action = action;
        this.automaton = Automatons.patterns(action + "*");
    }

    public String name() {
        return action;
    }

    public String action() {
        return action;
    }

    @Override
    public Automaton automaton() {
        return this.automaton;
    }

    @Override
    public ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
        return builder.add(this);
    }

}
