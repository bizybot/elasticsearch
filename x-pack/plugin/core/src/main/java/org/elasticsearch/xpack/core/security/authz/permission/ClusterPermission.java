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
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * A {@link ClusterPermission} represents cluster wide access for a user.
 * A ClusterPermission consists of one or many {@link ClusterPrivilege} that
 * define the predicates that test access to cluster action for a given request.
 */
public class ClusterPermission {
    public static final ClusterPermission NONE = new ClusterPermission(Set.of(), List.of());

    private final Set<ClusterPrivilege> clusterPrivileges;
    private final List<PermissionCheck> checks;

    ClusterPermission(Set<ClusterPrivilege> clusterPrivileges,
                      List<PermissionCheck> checks) {
        this.clusterPrivileges = Set.copyOf(clusterPrivileges);
        this.checks = List.copyOf(checks);
    }

    /**
     * Checks permission to a cluster action for a given request.
     * @param action cluster action
     * @param request {@link TransportRequest}
     * @return {@code true} if the access is allowed else returns {@link false}
     */
    public boolean check(String action, TransportRequest request) {
        return checks.stream().anyMatch(permission -> permission.check(action, request));
    }

    /**
     * Checks if the specified {@link ClusterPermission}'s actions are implied by this {@link ClusterPermission}
     * @param clusterPermission {@link ClusterPermission}
     * @return {@code true} if the specified cluster permissions actions are implied by this cluster permission else returns {@code false}
     */
    public boolean implies(ClusterPermission clusterPermission) {
        return this.checks.stream().anyMatch(permCheck -> permCheck.implies(clusterPermission.checks));
    }

    /**
     * @return set of {@link ClusterPrivilege}'s
     */
    public Set<ClusterPrivilege> privileges() {
        return clusterPrivileges;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final Set<ClusterPrivilege> clusterPrivileges = new HashSet<>();
        private final List<Automaton> actionAutomatons = new ArrayList<>();
        private final List<PermissionCheck> permissionChecks = new ArrayList<>();

        public Builder add(final AutomatonClusterPrivilege automatonClusterPrivilege) {
            this.clusterPrivileges.add(automatonClusterPrivilege);
            this.actionAutomatons.add(automatonClusterPrivilege.automaton());
            return this;
        }

        public Builder add(final ConfigurableClusterPrivilege configurableClusterPrivilege, final Predicate<String> actionPredicate,
                           final Predicate<TransportRequest> requestPredicate) {
            this.clusterPrivileges.add(configurableClusterPrivilege);
            this.permissionChecks.add(new ConfigurablePermissionCheck(configurableClusterPrivilege, actionPredicate, requestPredicate));
            return this;
        }

        public Builder add(final ClusterPrivilege clusterPrivilege, final PermissionCheck permissionCheck) {
            this.clusterPrivileges.add(clusterPrivilege);
            this.permissionChecks.add(permissionCheck);
            return this;
        }

        public ClusterPermission build() {
            if (false == actionAutomatons.isEmpty()) {
                final Automaton mergedAutomaton = Automatons.unionAndMinimize(this.actionAutomatons);
                final List<PermissionCheck> automatonAndChecks = new ArrayList<>(this.permissionChecks.size() + 1);
                automatonAndChecks.add(new AutomatonPermissionCheck(mergedAutomaton));
                automatonAndChecks.addAll(this.permissionChecks);
                return new ClusterPermission(this.clusterPrivileges, automatonAndChecks);
            } else {
                if (clusterPrivileges.isEmpty() && permissionChecks.isEmpty()) {
                    return NONE;
                }
                return new ClusterPermission(this.clusterPrivileges, this.permissionChecks);
            }
        }
    }

    private interface PermissionCheck {
        boolean check(String action, TransportRequest request);

        boolean implies(List<PermissionCheck> permissionCheck);
    }

    private static class AutomatonPermissionCheck implements PermissionCheck {
        private final Automaton automaton;

        AutomatonPermissionCheck(Automaton automaton) {
            this.automaton = automaton;
        }

        @Override
        public boolean check(String action, TransportRequest request) {
            return Automatons.predicate(automaton).test(action);
        }

        @Override
        public boolean implies(List<PermissionCheck> permissionCheck) {
            return permissionCheck
                .stream()
                .filter(pCheck -> pCheck instanceof AutomatonPermissionCheck)
                .anyMatch(pCheck -> Operations.subsetOf(((AutomatonPermissionCheck) pCheck).automaton, this.automaton));
        }
    }

    private static class ConfigurablePermissionCheck implements PermissionCheck {
        private final ConfigurableClusterPrivilege configurableClusterPrivilege;
        private final Predicate<String> actionPredicate;
        private final Predicate<TransportRequest> requestPredicate;

        ConfigurablePermissionCheck(ConfigurableClusterPrivilege configurableClusterPrivilege, final Predicate<String> actionPredicate,
                                    final Predicate<TransportRequest> requestPredicate) {
            this.configurableClusterPrivilege = configurableClusterPrivilege;
            this.actionPredicate = actionPredicate;
            this.requestPredicate = requestPredicate;
        }

        @Override
        public boolean check(String action, TransportRequest request) {
            return actionPredicate.test(action) &&
                requestPredicate.test(request);
        }

        @Override
        public boolean implies(List<PermissionCheck> permissionCheck) {
            return permissionCheck
                .stream()
                .filter(pCheck -> pCheck instanceof ConfigurablePermissionCheck)
                .anyMatch(pCheck -> {
                    ConfigurablePermissionCheck otherCheck = (ConfigurablePermissionCheck) pCheck;
                    return this.configurableClusterPrivilege.equals(otherCheck.configurableClusterPrivilege);
                });
        }
    }
}
