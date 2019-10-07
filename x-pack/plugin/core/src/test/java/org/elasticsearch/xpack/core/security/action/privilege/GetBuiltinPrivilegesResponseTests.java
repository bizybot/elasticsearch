/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action.privilege;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class GetBuiltinPrivilegesResponseTests extends ESTestCase {

    public void testToXContent() throws IOException {
        final String[] cluster = new String[]{"monitor", "manage_security"};
        final String[] index = new String[]{"create", "create_doc", "index", "index_doc"};
        final GetBuiltinPrivilegesResponse.Deprecations deprecations = new GetBuiltinPrivilegesResponse.Deprecations();
        if (deprecations != null) {
            deprecations.addDeprecatedIndexPrivilege("create", "create_doc", false);
            deprecations.addDeprecatedIndexPrivilege("index", "index_doc", false);
        }
        final GetBuiltinPrivilegesResponse response = new GetBuiltinPrivilegesResponse(cluster, index, deprecations);
        XContentBuilder builder = XContentFactory.jsonBuilder();
        response.toXContent(builder, ToXContent.EMPTY_PARAMS);

        String expectedJson = "{\"cluster\":[\"monitor\",\"manage_security\"]," +
            "\"index\":[\"create\",\"create_doc\",\"index\",\"index_doc\"]," +
            "\"deprecations\":{\"cluster\":[]," +
            "\"index\":[{\"name\":\"create\",\"alternative\":\"create_doc\"," +
            "\"hasExactReplacement\":false},{\"name\":\"index\",\"alternative\":\"index_doc\",\"hasExactReplacement\":false}]}}";
        assertThat(Strings.toString(builder), is(expectedJson));
    }

    public void testSerialization() throws IOException {
        final String[] cluster = generateRandomStringArray(8, randomIntBetween(3, 8), false, true);
        final String[] index = generateRandomStringArray(8, randomIntBetween(3, 8), false, true);
        final GetBuiltinPrivilegesResponse.Deprecations deprecations = randomFrom(new GetBuiltinPrivilegesResponse.Deprecations(), null);
        if (deprecations != null) {
            deprecations.addDeprecatedIndexPrivilege("create", "create_doc", false);
        }
        final GetBuiltinPrivilegesResponse original = new GetBuiltinPrivilegesResponse(cluster, index, deprecations);

        final BytesStreamOutput out = new BytesStreamOutput();
        original.writeTo(out);

        final GetBuiltinPrivilegesResponse copy = new GetBuiltinPrivilegesResponse(out.bytes().streamInput());

        assertThat(copy.getClusterPrivileges(), equalTo(cluster));
        assertThat(copy.getIndexPrivileges(), equalTo(index));
        if (deprecations == null) {
            assertThat(copy.getDeprecations(), is(nullValue()));
        } else {
            assertThat(copy.getDeprecations().getClusterPrivileges(), is(empty()));
            assertThat(copy.getDeprecations().getIndexPrivileges().size(), is(1));
            assertThat(copy.getDeprecations().getIndexPrivileges().get(0),
                is(new GetBuiltinPrivilegesResponse.DeprecationInfo("create", "create_doc", false)));
        }
    }

}
