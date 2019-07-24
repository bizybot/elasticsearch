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
import org.elasticsearch.xpack.core.indexlifecycle.action.StartILMAction;
import org.elasticsearch.xpack.core.indexlifecycle.action.StopILMAction;
import org.elasticsearch.xpack.core.security.action.token.InvalidateTokenAction;
import org.elasticsearch.xpack.core.security.action.token.RefreshTokenAction;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesAction;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.elasticsearch.xpack.core.snapshotlifecycle.action.GetSnapshotLifecycleAction;

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
    private static final Automaton MANAGE_SLM_AUTOMATON =
        patterns("cluster:admin/slm/*", StartILMAction.NAME, StopILMAction.NAME, GetStatusAction.NAME);
    private static final Automaton READ_SLM_AUTOMATON = patterns(GetSnapshotLifecycleAction.NAME, GetStatusAction.NAME);

    public static final NameableClusterPrivilege NONE = new FixedClusterPrivilege("none", Automatons.EMPTY);
    public static final NameableClusterPrivilege ALL = new FixedClusterPrivilege("all", ALL_CLUSTER_AUTOMATON);
    public static final NameableClusterPrivilege MONITOR = new FixedClusterPrivilege("monitor", MONITOR_AUTOMATON);
    public static final NameableClusterPrivilege MONITOR_ML = new FixedClusterPrivilege("monitor_ml", MONITOR_ML_AUTOMATON);
    public static final NameableClusterPrivilege MONITOR_DATA_FRAME =
        new FixedClusterPrivilege("monitor_data_frame_transforms", MONITOR_DATA_FRAME_AUTOMATON);
    public static final NameableClusterPrivilege MONITOR_WATCHER = new FixedClusterPrivilege("monitor_watcher", MONITOR_WATCHER_AUTOMATON);
    public static final NameableClusterPrivilege MONITOR_ROLLUP = new FixedClusterPrivilege("monitor_rollup", MONITOR_ROLLUP_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE = new FixedClusterPrivilege("manage", MANAGE_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_ML = new FixedClusterPrivilege("manage_ml", MANAGE_ML_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_DATA_FRAME =
        new FixedClusterPrivilege("manage_data_frame_transforms", MANAGE_DATA_FRAME_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_TOKEN = new FixedClusterPrivilege("manage_token", MANAGE_TOKEN_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_WATCHER = new FixedClusterPrivilege("manage_watcher", MANAGE_WATCHER_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_ROLLUP = new FixedClusterPrivilege("manage_rollup", MANAGE_ROLLUP_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_IDX_TEMPLATES =
        new FixedClusterPrivilege("manage_index_templates", MANAGE_IDX_TEMPLATE_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_INGEST_PIPELINES =
        new FixedClusterPrivilege("manage_ingest_pipelines", MANAGE_INGEST_PIPELINE_AUTOMATON);
    public static final NameableClusterPrivilege TRANSPORT_CLIENT = new FixedClusterPrivilege("transport_client",
        TRANSPORT_CLIENT_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_SECURITY = new FixedClusterPrivilege("manage_security", MANAGE_SECURITY_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_SAML = new FixedClusterPrivilege("manage_saml", MANAGE_SAML_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_OIDC = new FixedClusterPrivilege("manage_oidc", MANAGE_OIDC_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_API_KEY = new FixedClusterPrivilege("manage_api_key", MANAGE_API_KEY_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_PIPELINE =
        new FixedClusterPrivilege("manage_pipeline", "cluster:admin/ingest/pipeline/*");
    public static final NameableClusterPrivilege MANAGE_CCR = new FixedClusterPrivilege("manage_ccr", MANAGE_CCR_AUTOMATON);
    public static final NameableClusterPrivilege READ_CCR = new FixedClusterPrivilege("read_ccr", READ_CCR_AUTOMATON);
    public static final NameableClusterPrivilege CREATE_SNAPSHOT = new FixedClusterPrivilege("create_snapshot", CREATE_SNAPSHOT_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_ILM = new FixedClusterPrivilege("manage_ilm", MANAGE_ILM_AUTOMATON);
    public static final NameableClusterPrivilege READ_ILM = new FixedClusterPrivilege("read_ilm", READ_ILM_AUTOMATON);
    public static final NameableClusterPrivilege MANAGE_SLM = new FixedClusterPrivilege("manage_slm", MANAGE_SLM_AUTOMATON);
    public static final NameableClusterPrivilege READ_SLM = new FixedClusterPrivilege("read_slm", READ_SLM_AUTOMATON);

    private static final Map<String, NameableClusterPrivilege> VALUES = Stream.<NameableClusterPrivilege>of(
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
        READ_ILM,
        MANAGE_SLM,
        READ_SLM).collect(Collectors.toUnmodifiableMap(NameableClusterPrivilege::name, Function.identity()));

    public static NameableClusterPrivilege resolve(String name) {
        name = Objects.requireNonNull(name).toLowerCase(Locale.ROOT);
        if (isClusterAction(name)) {
            return new FixedClusterPrivilege(name, name);
        }
        final NameableClusterPrivilege fixedPrivilege = VALUES.get(name);
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
