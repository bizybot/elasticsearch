/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authz.privilege.AutomatonClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * A permission that is based on privileges for cluster wide actions, with the optional ability to inspect the request object
 */
public class ClusterPermission {

    public static final ClusterPermission NONE = new ClusterPermission(Set.of(), List.of());

    public interface PermissionCheck {
        boolean check(String action, TransportRequest request);

        boolean grants(ClusterPrivilege privilege);
    }

    private final Set<ClusterPrivilege> privileges;
    private final List<PermissionCheck> checks;

    public ClusterPermission(Set<ClusterPrivilege> privileges, List<PermissionCheck> checks) {
        this.privileges = Set.copyOf(privileges);
        this.checks = List.copyOf(checks);
    }

    public boolean check(String action, TransportRequest request) {
        return this.checks.stream().anyMatch(c -> c.check(action, request));
    }

    public boolean grants(ClusterPrivilege privilege) {
        return this.checks.stream().anyMatch(c -> c.grants(privilege));
    }

    public Set<ClusterPrivilege> privileges() {
        return this.privileges;
    }

    public static final Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Set<ClusterPrivilege> privileges;
        private List<Automaton> actionAutomatons;
        private List<PermissionCheck> checks;

        public Builder() {
            this.privileges = new LinkedHashSet<>();
            this.actionAutomatons = new ArrayList<>();
            this.checks = new ArrayList<>();
        }

        /**
         * This method exists so that we can optimize privileges that rely exclusively on action Automata
         */
        public Builder add(AutomatonClusterPrivilege privilege) {
            this.privileges.add(privilege);
            this.actionAutomatons.add(privilege.automaton());
            return this;
        }

        public Builder add(ClusterPrivilege privilege, PermissionCheck check) {
            this.privileges.add(privilege);
            this.checks.add(check);
            return this;
        }

        public Builder add(ClusterPrivilege privilege, Predicate<String> actionPredicate, Predicate<TransportRequest> requestPredicate) {
            return add(privilege, new PermissionCheck() {
                @Override
                public boolean check(String action, TransportRequest request) {
                    return actionPredicate.test(action) && requestPredicate.test(request);
                }

                @Override
                public boolean grants(ClusterPrivilege checkPrivilege) {
                    return privilege.equals(checkPrivilege);
                }
            });
        }

        public ClusterPermission build() {
            if (this.privileges.isEmpty()) {
                return NONE;
            } else if (this.actionAutomatons.isEmpty()) {
                return new ClusterPermission(this.privileges, this.checks);
            } else {
                final Automaton mergedAutomaton = Automatons.unionAndMinimize(this.actionAutomatons);
                final List<PermissionCheck> automatonAndChecks = new ArrayList<>(checks.size() + 1);
                automatonAndChecks.add(new AutomatonCheck(mergedAutomaton));
                automatonAndChecks.addAll(this.checks);
                return new ClusterPermission(this.privileges, automatonAndChecks);
            }
        }
    }

    private static class AutomatonCheck implements PermissionCheck {

        private final Automaton automaton;
        private final Predicate<String> predicate;

        private AutomatonCheck(Automaton automaton) {
            this.automaton = automaton;
            this.predicate = Automatons.predicate(automaton);
        }

        @Override
        public boolean check(String action, TransportRequest request) {
            return this.predicate.test(action);
        }

        @Override
        public boolean grants(ClusterPrivilege privilege) {
            if (privilege instanceof AutomatonClusterPrivilege) {
                final Automaton privilegeAutomaton = ((AutomatonClusterPrivilege) privilege).automaton();
                return Operations.subsetOf(privilegeAutomaton, this.automaton);
            }
            return false;
        }
    }
}
