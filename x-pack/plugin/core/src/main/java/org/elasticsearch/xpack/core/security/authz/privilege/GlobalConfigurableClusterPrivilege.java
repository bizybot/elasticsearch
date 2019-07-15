/*
 *
 *  * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  * or more contributor license agreements. Licensed under the Elastic License;
 *  * you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.NamedWriteable;
import org.elasticsearch.common.xcontent.ToXContentFragment;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * A {@link GlobalConfigurableClusterPrivilege} is a form of {@link ConfigurableClusterPrivilege} that can be configured by an
 * Elasticsearch security administrator within a {@link org.elasticsearch.xpack.core.security.authz.RoleDescriptor}.
 */
public interface GlobalConfigurableClusterPrivilege extends ConfigurableClusterPrivilege, NamedWriteable, ToXContentFragment {

    /**
     * The category under which this privilege should be rendered when output as XContent.
     */
    Category getCategory();

    /**
     * A {@link GlobalConfigurableClusterPrivilege} should generate a fragment of {@code XContent}, which consists of
     * a single field name, followed by its value (which may be an object, an array, or a simple value).
     */
    @Override
    XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException;

    /**
     * Categories exist for to segment privileges for the purposes of rendering to XContent.
     * {@link GlobalConfigurableClusterPrivilege#toXContent(XContentBuilder, Params)} builds one XContent
     * object for a collection of {@link GlobalConfigurableClusterPrivilege} instances, with the top level fields built
     * from the categories.
     */
    enum Category {
        APPLICATION(new ParseField("application")),
        WATCH(new ParseField("watch"));

        public final ParseField field;

        Category(ParseField field) {
            this.field = field;
        }
    }
}
