/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.NamedWriteableAwareStreamInput;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.EqualsHashCodeTestUtils;
import org.elasticsearch.xpack.core.XPackClientPlugin;
import org.elasticsearch.xpack.core.security.action.privilege.DeletePrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.DeletePrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.privilege.GetPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.GetPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.role.PutRoleAction;
import org.elasticsearch.xpack.core.security.action.rolemapping.DeleteRoleMappingAction;
import org.elasticsearch.xpack.core.security.action.user.GetUsersAction;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesAction;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.authz.privilege.ConfigurableClusterPrivileges.ManageApplicationPrivileges;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;

import static org.elasticsearch.common.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;
import static org.elasticsearch.test.TestMatchers.predicateMatches;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class ManageApplicationPrivilegesTests extends ESTestCase {

    public void testSerialization() throws Exception {
        final ManageApplicationPrivileges original = buildPrivileges();
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            original.writeTo(out);
            final NamedWriteableRegistry registry = new NamedWriteableRegistry(new XPackClientPlugin(Settings.EMPTY).getNamedWriteables());
            try (StreamInput in = new NamedWriteableAwareStreamInput(out.bytes().streamInput(), registry)) {
                final ManageApplicationPrivileges copy = ManageApplicationPrivileges.createFrom(in);
                assertThat(copy, equalTo(original));
                assertThat(original, equalTo(copy));
            }
        }
    }

    public void testGenerateAndParseXContent() throws Exception {
        final XContent xContent = randomFrom(XContentType.values()).xContent();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            final XContentBuilder builder = new XContentBuilder(xContent, out);

            final ManageApplicationPrivileges original = buildPrivileges();
            builder.startObject();
            original.toXContent(builder, ToXContent.EMPTY_PARAMS);
            builder.endObject();
            builder.flush();

            final byte[] bytes = out.toByteArray();
            try (XContentParser parser = xContent.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, bytes)) {
                assertThat(parser.nextToken(), equalTo(XContentParser.Token.START_OBJECT));
                // ManageApplicationPrivileges.parse requires that the parser be positioned on the "manage" field.
                assertThat(parser.nextToken(), equalTo(XContentParser.Token.FIELD_NAME));
                final ManageApplicationPrivileges clone = ManageApplicationPrivileges.parse(parser);
                assertThat(parser.nextToken(), equalTo(XContentParser.Token.END_OBJECT));

                assertThat(clone, equalTo(original));
                assertThat(original, equalTo(clone));
            }
        }
    }

    public void testEqualsAndHashCode() {
        final int applicationNameLength = randomIntBetween(4, 7);
        final ManageApplicationPrivileges privileges = buildPrivileges(applicationNameLength);
        final EqualsHashCodeTestUtils.MutateFunction<ManageApplicationPrivileges> mutate
            = orig -> buildPrivileges(applicationNameLength + randomIntBetween(1, 3));
        EqualsHashCodeTestUtils.checkEqualsAndHashCode(privileges, this::clone, mutate);
    }

    public void testActionPattern() {
        // TODO -- FIXME, does this test still make sense?
        Predicate<String> predicate = ManageApplicationPrivileges.ACTION_PREDICATE;
        for (String actionName : Arrays.asList(GetPrivilegesAction.NAME, PutPrivilegesAction.NAME, DeletePrivilegesAction.NAME)) {
            assertThat(predicate, predicateMatches(actionName));
        }
        for (String actionName : Arrays.asList(GetUsersAction.NAME, PutRoleAction.NAME, DeleteRoleMappingAction.NAME,
            HasPrivilegesAction.NAME)) {
            assertThat(predicate, not(predicateMatches(actionName)));
        }
    }

    public void testPermission() {
        // TODO -- FIXME, does this test still make sense?
        final ManageApplicationPrivileges kibanaAndLogstash = new ManageApplicationPrivileges(Sets.newHashSet("kibana-*", "logstash"));
        final ManageApplicationPrivileges cloudAndSwiftype = new ManageApplicationPrivileges(Sets.newHashSet("cloud-*", "swiftype"));

        final ClusterPermission kibanaAndLogstashPermission = getPermission(kibanaAndLogstash);
        final ClusterPermission cloudAndSwiftypePermission = getPermission(cloudAndSwiftype);
        assertThat(kibanaAndLogstashPermission, notNullValue());
        assertThat(cloudAndSwiftypePermission, notNullValue());

        final GetPrivilegesRequest getKibana1 = new GetPrivilegesRequest();
        getKibana1.application("kibana-1");
        assertThat(kibanaAndLogstashPermission.check(GetPrivilegesAction.NAME, getKibana1), equalTo(true));
        assertThat(cloudAndSwiftypePermission.check(GetPrivilegesAction.NAME, getKibana1), equalTo(false));

        final DeletePrivilegesRequest deleteLogstash = new DeletePrivilegesRequest("logstash", new String[]{"all"});
        assertThat(kibanaAndLogstashPermission.check(DeletePrivilegesAction.NAME, deleteLogstash), equalTo(true));
        assertThat(cloudAndSwiftypePermission.check(DeletePrivilegesAction.NAME, deleteLogstash), equalTo(false));

        final PutPrivilegesRequest putKibana = new PutPrivilegesRequest();

        final List<ApplicationPrivilegeDescriptor> kibanaPrivileges = new ArrayList<>();
        for (int i = randomIntBetween(2, 6); i > 0; i--) {
            kibanaPrivileges.add(new ApplicationPrivilegeDescriptor("kibana-" + i,
                randomAlphaOfLengthBetween(3, 6).toLowerCase(Locale.ROOT), Collections.emptySet(), Collections.emptyMap()));
        }
        putKibana.setPrivileges(kibanaPrivileges);
        assertThat(kibanaAndLogstashPermission.check(PutPrivilegesAction.NAME, putKibana), equalTo(true));
        assertThat(cloudAndSwiftypePermission.check(PutPrivilegesAction.NAME, putKibana), equalTo(false));
    }

    private ClusterPermission getPermission(ClusterPrivilege privilege) {
        return privilege.buildPermission(ClusterPermission.builder()).build();
    }

    public void testSecurityForGetAllApplicationPrivileges() {
        final GetPrivilegesRequest getAll = new GetPrivilegesRequest();
        getAll.application(null);
        getAll.privileges(new String[0]);

        assertThat(getAll.validate(), nullValue());

        final ManageApplicationPrivileges kibanaOnly = new ManageApplicationPrivileges(Sets.newHashSet("kibana-*"));
        final ManageApplicationPrivileges allApps = new ManageApplicationPrivileges(Sets.newHashSet("*"));

        assertThat(getPermission(kibanaOnly).check(GetPrivilegesAction.NAME, getAll), equalTo(false));
        assertThat(getPermission(allApps).check(GetPrivilegesAction.NAME, getAll), equalTo(true));
    }

    private ManageApplicationPrivileges clone(ManageApplicationPrivileges original) {
        return new ManageApplicationPrivileges(new LinkedHashSet<>(original.getApplicationNames()));
    }

    private ManageApplicationPrivileges buildPrivileges() {
        return buildPrivileges(randomIntBetween(4, 7));
    }

    static ManageApplicationPrivileges buildPrivileges(int applicationNameLength) {
        Set<String> applicationNames = Sets.newHashSet(Arrays.asList(generateRandomStringArray(5, applicationNameLength, false, false)));
        return new ManageApplicationPrivileges(applicationNames);
    }
}
