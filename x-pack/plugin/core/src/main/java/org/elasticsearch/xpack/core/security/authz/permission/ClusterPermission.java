/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * A permission that is based on privileges for cluster wide actions, with the optional ability to inspect the request object
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
     *
     * @param action  cluster action
     * @param request {@link TransportRequest}
     * @return {@code true} if the access is allowed else returns {@code false}
     */
    public boolean check(String action, TransportRequest request) {
        return checks.stream().anyMatch(permission -> permission.check(action, request));
    }

    /**
     * Checks if the specified {@link ClusterPermission}'s actions are implied by this {@link ClusterPermission}
     *
     * @param clusterPermission {@link ClusterPermission}
     * @return {@code true} if the specified cluster permissions actions are implied by this cluster permission else returns {@code false}
     */
    public boolean implies(ClusterPermission clusterPermission) {
        for (PermissionCheck permissionCheck : this.checks) {
            for (PermissionCheck check : clusterPermission.checks) {
                if (permissionCheck.implies(check)) {
                    return true;
                }
            }
        }
        return false;
    }

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

        public Builder add(final ClusterPrivilege clusterPrivilege, Set<String> allowedActionPatterns, Set<String> deniedActionPatterns) {
            this.clusterPrivileges.add(clusterPrivilege);
            if (allowedActionPatterns.isEmpty() && deniedActionPatterns.isEmpty()) {
                this.actionAutomatons.add(Automatons.EMPTY);
            } else {
                Automaton allowedAutomaton = Automatons.patterns(allowedActionPatterns);
                Automaton deniedAutomaton = Automatons.patterns(deniedActionPatterns);
                this.actionAutomatons.add(Automatons.minusAndMinimize(allowedAutomaton, deniedAutomaton));
            }
            return this;
        }

        public Builder add(final ConfigurableClusterPrivilege configurableClusterPrivilege, Predicate<String> actionPredicate,
                           Predicate<TransportRequest> requestPredicate) {
            this.clusterPrivileges.add(configurableClusterPrivilege);
            this.permissionChecks.add(new ConfigurablePermissionCheck(configurableClusterPrivilege,
                actionPredicate,
                requestPredicate));
            return this;
        }

        public ClusterPermission build() {
            if (clusterPrivileges.isEmpty() && permissionChecks.isEmpty()) {
                return NONE;
            }
            List<PermissionCheck> checks = this.permissionChecks;
            if (false == actionAutomatons.isEmpty()) {
                final Automaton mergedAutomaton = Automatons.unionAndMinimize(this.actionAutomatons);
                checks = new ArrayList<>(this.permissionChecks.size() + 1);
                checks.add(new AutomatonPermissionCheck(mergedAutomaton));
                checks.addAll(this.permissionChecks);
            }
            return new ClusterPermission(this.clusterPrivileges, checks);
        }
    }

    /**
     * Evaluates whether the cluster actions (optionally for a given request)
     * is permitted by this permission.
     */
    public interface PermissionCheck {
        /**
         * Checks permission to a cluster action for a given request.
         *
         * @param action  action name
         * @param request {@link TransportRequest}
         * @return
         */
        boolean check(String action, TransportRequest request);

        /**
         * checks whether specified {@link PermissionCheck} is implied by this {@link PermissionCheck}.
         *
         * @param permissionCheck
         * @return {@code true} if the specified specified {@link PermissionCheck} is implied by this {@link PermissionCheck} else
         * returns {@code false}
         */
        boolean implies(PermissionCheck permissionCheck);
    }

    public static class AutomatonPermissionCheck implements PermissionCheck {
        private final Automaton automaton;

        AutomatonPermissionCheck(Automaton automaton) {
            this.automaton = automaton;
        }

        @Override
        public boolean check(String action, TransportRequest request) {
            return Automatons.predicate(automaton).test(action);
        }

        @Override
        public boolean implies(PermissionCheck permissionCheck) {
            if (permissionCheck instanceof AutomatonPermissionCheck) {
                Operations.subsetOf(((AutomatonPermissionCheck) permissionCheck).automaton, this.automaton);
            }
            return false;
        }
    }

    public static class ConfigurablePermissionCheck implements PermissionCheck {
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
        public boolean implies(PermissionCheck permissionCheck) {
            if (permissionCheck instanceof ConfigurablePermissionCheck) {
                ConfigurablePermissionCheck otherCheck = (ConfigurablePermissionCheck) permissionCheck;
                return this.configurableClusterPrivilege.equals(otherCheck.configurableClusterPrivilege);
            }
            return false;
        }
    }
}
