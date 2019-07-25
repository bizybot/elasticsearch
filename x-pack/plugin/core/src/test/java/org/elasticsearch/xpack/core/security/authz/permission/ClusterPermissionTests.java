/*
 *
 *  * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  * or more contributor license agreements. Licensed under the Elastic License;
 *  * you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.permission;

import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.authz.privilege.ActionClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilege;
import org.elasticsearch.xpack.core.security.authz.privilege.ClusterPrivilegeResolver;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

public class ClusterPermissionTests extends ESTestCase {

    public void testClusterPermissionBuilder() {
        final TransportRequest mockTransportRequest = Mockito.mock(TransportRequest.class);
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        assertNotNull(builder);
        assertThat(builder.build(), is(ClusterPermission.NONE));

        ClusterPrivilegeResolver.MANAGE_SECURITY.buildPermission(builder);
        ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege1 =
            new MockConfigurableClusterPrivilege(r -> r == mockTransportRequest);
        final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege2 =
            new MockConfigurableClusterPrivilege(r -> false);
        mockConfigurableClusterPrivilege1.buildPermission(builder);
        mockConfigurableClusterPrivilege2.buildPermission(builder);

        {
            ClusterPermission clusterPermission = builder.build();
            assertNotNull(clusterPermission);
            assertNotNull(clusterPermission.privileges());
            Tuple<Set<ClusterPrivilege>, Set<ConfigurableClusterPrivilege>> privileges = clusterPermission.privileges();
            assertNotNull(privileges.v1());
            assertThat(privileges.v1().size(), is(2));
            assertThat(privileges.v1(), containsInAnyOrder(ClusterPrivilegeResolver.MANAGE_SECURITY, ClusterPrivilegeResolver.MANAGE_ILM));
            assertNotNull(privileges.v2());
            assertThat(privileges.v2().size(), is(2));
            assertThat(privileges.v2(), containsInAnyOrder(mockConfigurableClusterPrivilege1, mockConfigurableClusterPrivilege2));
        }

    }

    public void testClusterPermissionCheck() {
        final TransportRequest mockTransportRequest = Mockito.mock(TransportRequest.class);
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        ClusterPrivilegeResolver.MANAGE_SECURITY.buildPermission(builder);
        ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);

        final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege1 =
            new MockConfigurableClusterPrivilege(r -> r == mockTransportRequest);
        final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege2 =
            new MockConfigurableClusterPrivilege(r -> false);
        mockConfigurableClusterPrivilege1.buildPermission(builder);
        mockConfigurableClusterPrivilege2.buildPermission(builder);
        ClusterPermission clusterPermission = builder.build();

        assertThat(clusterPermission.check("cluster:admin/xpack/security/token/invalidate", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/ilm/stop", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/xpack/security/privilege/get", mockTransportRequest), is(true));
        assertThat(clusterPermission.check("cluster:admin/snapshot/status", mockTransportRequest), is(false));
    }

    public void testClusterPermissionImplies() {
        final TransportRequest mockTransportRequest = Mockito.mock(TransportRequest.class);
        final ClusterPermission.Builder builder = ClusterPermission.builder();
        ClusterPrivilegeResolver.MANAGE_SECURITY.buildPermission(builder);
        ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(builder);
        final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege1 =
            new MockConfigurableClusterPrivilege(r -> r == mockTransportRequest);
        final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege2 =
            new MockConfigurableClusterPrivilege(r -> false);
        mockConfigurableClusterPrivilege1.buildPermission(builder);
        mockConfigurableClusterPrivilege2.buildPermission(builder);

        {
            ClusterPermission clusterPermission = builder.build();
            ClusterPermission impliedBy = ClusterPermission.builder().build();
            assertThat(clusterPermission.implies(impliedBy), is(false));
        }
        {
            ClusterPermission clusterPermission = builder.build();
            ClusterPermission impliedBy = randomFrom(mockConfigurableClusterPrivilege1,
                mockConfigurableClusterPrivilege2).buildPermission(builder).build();
            assertThat(clusterPermission.implies(impliedBy), is(true));
        }
        {
            final TransportRequest mockTransportRequest3 = Mockito.mock(TransportRequest.class);
            final MockConfigurableClusterPrivilege mockConfigurableClusterPrivilege3 =
                new MockConfigurableClusterPrivilege(r -> r == mockTransportRequest3);
            ClusterPermission clusterPermission = builder.build();
            ClusterPermission impliedBy = mockConfigurableClusterPrivilege3.buildPermission(ClusterPermission.builder()).build();
            assertThat(clusterPermission.implies(impliedBy), is(false));
        }
        {
            ClusterPermission clusterPermission = ClusterPrivilegeResolver.ALL.buildPermission(ClusterPermission.builder()).build();
            ClusterPermission impliedBy = ClusterPrivilegeResolver.ALL.buildPermission(ClusterPermission.builder()).build();
            assertThat(clusterPermission.implies(impliedBy), is(true));

            clusterPermission = ClusterPrivilegeResolver.ALL.buildPermission(ClusterPermission.builder()).build();
            impliedBy = ClusterPrivilegeResolver.MANAGE_ILM.buildPermission(ClusterPermission.builder()).build();
            assertThat(clusterPermission.implies(impliedBy), is(true));
        }
    }

    private static class MockConfigurableClusterPrivilege implements ConfigurableClusterPrivilege {
        ActionClusterPrivilege clusterPrivilege = new ActionClusterPrivilege("manage_app_privs",
            Set.of("cluster:admin/xpack/security/privilege/*"));
        private Predicate<TransportRequest> requestPredicate;

        MockConfigurableClusterPrivilege(Predicate<TransportRequest> requestPredicate) {
            this.requestPredicate = requestPredicate;
        }

        @Override
        public Category getCategory() {
            return Category.APPLICATION;
        }

        @Override
        public ClusterPrivilege getPrivilege() {
            return clusterPrivilege;
        }

        @Override
        public Predicate<TransportRequest> getRequestPredicate() {
            return requestPredicate;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder;
        }

        @Override
        public String getWriteableName() {
            return "mock-ccp";
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            final MockConfigurableClusterPrivilege that = (MockConfigurableClusterPrivilege) o;
            return clusterPrivilege.equals(that.clusterPrivilege) &&
                requestPredicate.equals(that.requestPredicate);
        }

        @Override
        public int hashCode() {
            return Objects.hash(clusterPrivilege, requestPredicate);
        }

        @Override
        public String toString() {
            return "MockConfigurableClusterPrivilege{" +
                "clusterPrivilege=" + clusterPrivilege +
                ", requestPredicate=" + requestPredicate +
                '}';
        }

        @Override
        public ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
            return builder.add(this, Automatons.predicate(clusterPrivilege.getAllowedActionPatterns()), requestPredicate);
        }
    }
}
