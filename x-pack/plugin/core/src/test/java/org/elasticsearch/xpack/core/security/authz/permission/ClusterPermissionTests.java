/*
 *
 *  Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  or more contributor license agreements. Licensed under the Elastic License;
 *  you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.client.security.user.privileges.ManageApplicationPrivilege;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilegeResolver;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivileges;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.junit.Before;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

public class ClusterPermissionTests extends ESTestCase {
    private TransportRequest mockTransportRequest;
    private ClusterPrivilege cpThatDoesNothing = new ClusterPrivilege() {
        @Override
        public ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
            return builder;
        }
    };

    @Before
    public void setup() {
        mockTransportRequest = Mockito.mock(TransportRequest.class);
    }

    public void testClusterPermissionBuilder() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        assertNotNull(builder);
        assertThat(builder.build(), is(ClusterPermission.NONE));

        builder = ClusterPrivilegeResolver.MANAGE_SECURITY.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("kibana_app"));
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege2 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("beats_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        builder = manageApplicationsClusterPrivilege2.buildPermission(builder);

        final ClusterPermission clusterPermission = builder.build();
        assertNotNull(clusterPermission);
        assertNotNull(clusterPermission.privileges());
        final Set<ClusterPrivilege> privileges = clusterPermission.privileges();
        assertNotNull(privileges);
        assertThat(privileges.size(), is(4));
        assertThat(privileges, containsInAnyOrder(ClusterPrivilegeResolver.MANAGE_SECURITY, ClusterPrivilegeResolver.MANAGE_ILM,
            manageApplicationsClusterPrivilege1, manageApplicationsClusterPrivilege2));
    }

    public void testClusterPermissionCheck() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_SECURITY.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);

        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("kibana_app"));
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege2 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("beats_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        builder = manageApplicationsClusterPrivilege2.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.check("cluster:admin/xpack/security/token/invalidate", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/ilm/stop", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/xpack/security/privilege/get", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/snapshot/status", mockTransportRequest), is(false));
    }

    public void testClusterPermissionCheckWithEmptyActionPatterns() {
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        builder.add(cpThatDoesNothing, Set.of(), Set.of());
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.check("cluster:admin/ilm/start", mockTransportRequest), is(false));
        assertThat(clusterPermission.check("cluster:admin/xpack/security/token/invalidate", mockTransportRequest), is(false));
    }

    public void testClusterPermissionCheckWithExcludeOnlyActionPatterns() {
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        builder.add(cpThatDoesNothing, Set.of(), Set.of("cluster:some/thing/to/exclude"));
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.check("cluster:admin/ilm/start", mockTransportRequest), is(false));
        assertThat(clusterPermission.check("cluster:admin/xpack/security/token/invalidate", mockTransportRequest), is(false));
    }

    public void testClusterPermissionCheckWithActionPatterns() {
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        builder.add(cpThatDoesNothing, Set.of("cluster:admin/*"), Set.of("cluster:admin/ilm/*"));
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.check("cluster:admin/ilm/start", mockTransportRequest), is(false));
        assertThat(clusterPermission.check("cluster:admin/xpack/security/token/invalidate", mockTransportRequest), is(true));
    }

    public void testClusterPermissionCheckWithActionPatternsAndNoExludePatterns() {
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        builder.add(cpThatDoesNothing, Set.of("cluster:admin/*"), Set.of());
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.check("cluster:admin/ilm/start", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/xpack/security/token/invalidate", mockTransportRequest), is(true));
    }

    public void testNoneClusterPermissionIsImpliedByNone() {
        assertThat(ClusterPermission.NONE.implies(ClusterPermission.NONE), is(true));
    }

    public void testNoneClusterPermissionIsImpliedByAny() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_SECURITY.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("kibana_app"));
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege2 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("beats_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        builder = manageApplicationsClusterPrivilege2.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.implies(ClusterPermission.NONE), is(true));
    }

    public void testClusterPermissionSubsetWithConfigurableClusterPrivilegeIsImpliedByClusterPermission() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("kibana_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        ClusterPermission.Builder builder1 = ClusterPermission.builder();
        builder1 = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder1);
        builder1 = manageApplicationsClusterPrivilege1.buildPermission(builder1);
        final ClusterPermission otherClusterPermission = builder1.build();
        assertThat(clusterPermission.implies(otherClusterPermission), is(true));
    }

    public void testClusterPermissionSubsetWithConfigurableClusterPrivilegeWithAppNamesSubsetIsImpliedByClusterPermission() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("kibana_app", "beats_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        ClusterPermission.Builder builder1 = ClusterPermission.builder();
        builder1 = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder1);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege2 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("beats_app"));
        builder1 = manageApplicationsClusterPrivilege2.buildPermission(builder1);
        final ClusterPermission otherClusterPermission = builder1.build();

        assertThat(clusterPermission.implies(otherClusterPermission), is(true));
    }

    public void testClusterPermissionNonSubsetWithConfigurableClusterPrivilegeIsImpliedByClusterPermission() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("kibana_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        ClusterPermission.Builder builder1 = ClusterPermission.builder();
        builder1 = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder1);
        builder1 = manageApplicationsClusterPrivilege1.buildPermission(builder1);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege2 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("beats_app"));
        builder1 = manageApplicationsClusterPrivilege2.buildPermission(builder1);
        final ClusterPermission otherClusterPermission = builder1.build();

        assertThat(clusterPermission.implies(otherClusterPermission), is(false));
    }

    public void testClusterPermissionNonSubsetIsNotImpliedByClusterPermission() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        ClusterPermission.Builder builder1 = ClusterPermission.builder();
        builder1 = ClusterPrivilegeResolver.MANAGE_API_KEY.buildPermission(builder1);
        final ClusterPermission otherClusterPermission = builder1.build();

        assertThat(clusterPermission.implies(otherClusterPermission), is(false));
    }

    public void testClusterPermissionSubsetIsImpliedByClusterPermission() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        ClusterPermission.Builder builder1 = ClusterPermission.builder();
        builder1 = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder1);
        final ClusterPermission otherClusterPermission = builder1.build();

        assertThat(clusterPermission.implies(otherClusterPermission), is(true));
    }

    public void testClusterPermissionIsImpliedBySameClusterPermission() {
        ClusterPermission.Builder builder = ClusterPermission.builder();
        builder = ClusterPrivilegeResolver.MANAGE_ML.buildPermission(builder);
        builder = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final ConfigurableClusterPrivilege manageApplicationsClusterPrivilege1 =
            new ConfigurableClusterPrivileges.ManageApplicationPrivileges(Set.of("beats_app"));
        builder = manageApplicationsClusterPrivilege1.buildPermission(builder);
        final ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.implies(clusterPermission), is(true));
    }

    public void testClusterPermissionSubsetIsImpliedByAllClusterPermission() {
        final ClusterPermission allClusterPermission = ClusterPrivilegeResolver.ALL.buildPermission(ClusterPermission.builder()).build();
        ClusterPermission otherClusterPermission =
            ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(ClusterPermission.builder()).build();

        assertThat(allClusterPermission.implies(otherClusterPermission), is(true));
    }
}
