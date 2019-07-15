/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.Set;

/**
 * A {@link ClusterPrivilege} that is has a logical name that provides access to actions via an {@link Automaton}.
 */ 
public final class NamedClusterPrivilege implements NameableClusterPrivilege {

    private final String name;
    private final Automaton automaton;

    public NamedClusterPrivilege(String name, Automaton automaton) {
        this.name = name;
        this.automaton = automaton;
    }

    public NamedClusterPrivilege(String name, Set<String> patterns) {
        this(name, Automatons.patterns(patterns));
    }

    public NamedClusterPrivilege(String name, String... patterns) {
        this(name, Set.of(patterns));
    }

    public String name() {
        return name;
    }

    @Override
    public Automaton automaton() {
        return automaton;
    }

}
