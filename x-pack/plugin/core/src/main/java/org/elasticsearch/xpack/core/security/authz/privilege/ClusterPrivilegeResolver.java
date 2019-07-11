/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.action.admin.cluster.repositories.get.GetRepositoriesAction;
import org.elasticsearch.action.admin.cluster.snapshots.create.CreateSnapshotAction;
import org.elasticsearch.action.admin.cluster.snapshots.get.GetSnapshotsAction;
import org.elasticsearch.action.admin.cluster.snapshots.status.SnapshotsStatusAction;
import org.elasticsearch.action.admin.cluster.state.ClusterStateAction;
import org.elasticsearch.common.Strings;
import org.elasticsearch.xpack.core.indexlifecycle.action.GetLifecycleAction;
import org.elasticsearch.xpack.core.indexlifecycle.action.GetStatusAction;
import org.elasticsearch.xpack.core.security.action.token.InvalidateTokenAction;
import org.elasticsearch.xpack.core.security.action.token.RefreshTokenAction;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesAction;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.elasticsearch.xpack.core.security.support.Automatons.minusAndMinimize;
import static org.elasticsearch.xpack.core.security.support.Automatons.patterns;

/**
 * Translates cluster privilege names into concrete implementations
 */
public final class ClusterPrivilegeResolver {

    // shared automatons
    private static final Automaton MANAGE_SECURITY_AUTOMATON = patterns("cluster:admin/xpack/security/*");
    private static final Automaton MANAGE_SAML_AUTOMATON = patterns("cluster:admin/xpack/security/saml/*",
        InvalidateTokenAction.NAME, RefreshTokenAction.NAME);
    private static final Automaton MANAGE_OIDC_AUTOMATON = patterns("cluster:admin/xpack/security/oidc/*");
    private static final Automaton MANAGE_TOKEN_AUTOMATON = patterns("cluster:admin/xpack/security/token/*");
    private static final Automaton MANAGE_API_KEY_AUTOMATON = patterns("cluster:admin/xpack/security/api_key/*");
    private static final Automaton MONITOR_AUTOMATON = patterns("cluster:monitor/*");
    private static final Automaton MONITOR_ML_AUTOMATON = patterns("cluster:monitor/xpack/ml/*");
    private static final Automaton MONITOR_DATA_FRAME_AUTOMATON = patterns("cluster:monitor/data_frame/*");
    private static final Automaton MONITOR_WATCHER_AUTOMATON = patterns("cluster:monitor/xpack/watcher/*");
    private static final Automaton MONITOR_ROLLUP_AUTOMATON = patterns("cluster:monitor/xpack/rollup/*");
    private static final Automaton ALL_CLUSTER_AUTOMATON = patterns("cluster:*", "indices:admin/template/*");
    private static final Automaton MANAGE_AUTOMATON = minusAndMinimize(ALL_CLUSTER_AUTOMATON, MANAGE_SECURITY_AUTOMATON);
    private static final Automaton MANAGE_ML_AUTOMATON = patterns("cluster:admin/xpack/ml/*", "cluster:monitor/xpack/ml/*");
    private static final Automaton MANAGE_DATA_FRAME_AUTOMATON = patterns("cluster:admin/data_frame/*", "cluster:monitor/data_frame/*");
    private static final Automaton MANAGE_WATCHER_AUTOMATON = patterns("cluster:admin/xpack/watcher/*", "cluster:monitor/xpack/watcher/*");
    private static final Automaton TRANSPORT_CLIENT_AUTOMATON = patterns("cluster:monitor/nodes/liveness", "cluster:monitor/state");
    private static final Automaton MANAGE_IDX_TEMPLATE_AUTOMATON = patterns("indices:admin/template/*");
    private static final Automaton MANAGE_INGEST_PIPELINE_AUTOMATON = patterns("cluster:admin/ingest/pipeline/*");
    private static final Automaton MANAGE_ROLLUP_AUTOMATON = patterns("cluster:admin/xpack/rollup/*", "cluster:monitor/xpack/rollup/*");
    private static final Automaton MANAGE_CCR_AUTOMATON =
        patterns("cluster:admin/xpack/ccr/*", ClusterStateAction.NAME, HasPrivilegesAction.NAME);
    private static final Automaton CREATE_SNAPSHOT_AUTOMATON = patterns(CreateSnapshotAction.NAME, SnapshotsStatusAction.NAME + "*",
        GetSnapshotsAction.NAME, SnapshotsStatusAction.NAME, GetRepositoriesAction.NAME);
    private static final Automaton READ_CCR_AUTOMATON = patterns(ClusterStateAction.NAME, HasPrivilegesAction.NAME);
    private static final Automaton MANAGE_ILM_AUTOMATON = patterns("cluster:admin/ilm/*");
    private static final Automaton READ_ILM_AUTOMATON = patterns(GetLifecycleAction.NAME, GetStatusAction.NAME);

    public static final NamedClusterPrivilege NONE = new NamedClusterPrivilege("none", Automatons.EMPTY);
    public static final NamedClusterPrivilege ALL = new NamedClusterPrivilege("all", ALL_CLUSTER_AUTOMATON);
    public static final NamedClusterPrivilege MONITOR = new NamedClusterPrivilege("monitor", MONITOR_AUTOMATON);
    public static final NamedClusterPrivilege MONITOR_ML = new NamedClusterPrivilege("monitor_ml", MONITOR_ML_AUTOMATON);
    public static final NamedClusterPrivilege MONITOR_DATA_FRAME =
        new NamedClusterPrivilege("monitor_data_frame_transforms", MONITOR_DATA_FRAME_AUTOMATON);
    public static final NamedClusterPrivilege MONITOR_WATCHER = new NamedClusterPrivilege("monitor_watcher", MONITOR_WATCHER_AUTOMATON);
    public static final NamedClusterPrivilege MONITOR_ROLLUP = new NamedClusterPrivilege("monitor_rollup", MONITOR_ROLLUP_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE = new NamedClusterPrivilege("manage", MANAGE_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_ML = new NamedClusterPrivilege("manage_ml", MANAGE_ML_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_DATA_FRAME =
        new NamedClusterPrivilege("manage_data_frame_transforms", MANAGE_DATA_FRAME_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_TOKEN = new NamedClusterPrivilege("manage_token", MANAGE_TOKEN_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_WATCHER = new NamedClusterPrivilege("manage_watcher", MANAGE_WATCHER_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_ROLLUP = new NamedClusterPrivilege("manage_rollup", MANAGE_ROLLUP_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_IDX_TEMPLATES =
        new NamedClusterPrivilege("manage_index_templates", MANAGE_IDX_TEMPLATE_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_INGEST_PIPELINES =
        new NamedClusterPrivilege("manage_ingest_pipelines", MANAGE_INGEST_PIPELINE_AUTOMATON);
    public static final NamedClusterPrivilege TRANSPORT_CLIENT = new NamedClusterPrivilege("transport_client", TRANSPORT_CLIENT_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_SECURITY = new NamedClusterPrivilege("manage_security", MANAGE_SECURITY_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_SAML = new NamedClusterPrivilege("manage_saml", MANAGE_SAML_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_OIDC = new NamedClusterPrivilege("manage_oidc", MANAGE_OIDC_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_API_KEY = new NamedClusterPrivilege("manage_api_key", MANAGE_API_KEY_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_PIPELINE =
        new NamedClusterPrivilege("manage_pipeline", "cluster:admin/ingest/pipeline/*");
    public static final NamedClusterPrivilege MANAGE_CCR = new NamedClusterPrivilege("manage_ccr", MANAGE_CCR_AUTOMATON);
    public static final NamedClusterPrivilege READ_CCR = new NamedClusterPrivilege("read_ccr", READ_CCR_AUTOMATON);
    public static final NamedClusterPrivilege CREATE_SNAPSHOT = new NamedClusterPrivilege("create_snapshot", CREATE_SNAPSHOT_AUTOMATON);
    public static final NamedClusterPrivilege MANAGE_ILM = new NamedClusterPrivilege("manage_ilm", MANAGE_ILM_AUTOMATON);
    public static final NamedClusterPrivilege READ_ILM = new NamedClusterPrivilege("read_ilm", READ_ILM_AUTOMATON);

    private static final Map<String, FixedClusterPrivilege> VALUES = Stream.<FixedClusterPrivilege>of(
        NONE,
        ALL,
        MONITOR,
        MONITOR_ML,
        MONITOR_DATA_FRAME,
        MONITOR_WATCHER,
        MONITOR_ROLLUP,
        MANAGE,
        MANAGE_ML,
        MANAGE_DATA_FRAME,
        MANAGE_TOKEN,
        MANAGE_WATCHER,
        MANAGE_IDX_TEMPLATES,
        MANAGE_INGEST_PIPELINES,
        TRANSPORT_CLIENT,
        MANAGE_SECURITY,
        MANAGE_SAML,
        MANAGE_OIDC,
        MANAGE_API_KEY,
        MANAGE_PIPELINE,
        MANAGE_ROLLUP,
        MANAGE_CCR,
        READ_CCR,
        CREATE_SNAPSHOT,
        MANAGE_ILM,
        READ_ILM).collect(Collectors.toUnmodifiableMap(FixedClusterPrivilege::name, Function.identity()));

    public static FixedClusterPrivilege resolve(String name) {
        name = Objects.requireNonNull(name).toLowerCase(Locale.ROOT);
        if (isClusterAction(name)) {
            return new ActionClusterPrivilege(name);
        }
        final FixedClusterPrivilege fixedPrivilege = VALUES.get(name);
        if (fixedPrivilege != null) {
            return fixedPrivilege;
        }
        throw new IllegalArgumentException("unknown cluster privilege [" + name + "]. a privilege must be either " +
            "one of the predefined fixed cluster privileges [" +
            Strings.collectionToCommaDelimitedString(VALUES.entrySet()) + "] or a pattern over one of the available " +
            "cluster actions");

    }

    public static Set<String> names() {
        return Collections.unmodifiableSet(VALUES.keySet());
    }

    public static boolean isClusterAction(String actionName) {
        return actionName.startsWith("cluster:") || actionName.startsWith("indices:admin/template/");
    }
}
