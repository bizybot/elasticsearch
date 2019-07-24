/*
 *
 *  Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  or more contributor license agreements. Licensed under the Elastic License;
 *  you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.Objects;

/**
 * A {@link ClusterPrivilege} which is named ({@link NameableClusterPrivilege}) and is {@link Automaton} based privilege
 * ({@link AutomatonClusterPrivilege}).
 */
public final class FixedClusterPrivilege implements NameableClusterPrivilege, AutomatonClusterPrivilege {

    private String name;
    private Automaton automaton;

    public FixedClusterPrivilege(String name, String... actionPatterns) {
        this(name, Automatons.patterns(actionPatterns));
    }

    public FixedClusterPrivilege(String name, Automaton automaton) {
        this.name = name;
        this.automaton = automaton;
    }

    @Override
    public Automaton automaton() {
        return automaton;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final FixedClusterPrivilege that = (FixedClusterPrivilege) o;
        return name.equals(that.name) && automaton.equals(that.automaton);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, automaton);
    }

    @Override
    public ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
        builder.add(this);
        return builder;
    }
}
