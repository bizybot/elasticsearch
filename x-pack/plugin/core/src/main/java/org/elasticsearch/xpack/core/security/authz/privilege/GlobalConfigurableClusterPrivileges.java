/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParseException;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.xpack.core.security.authz.privilege.GlobalConfigurableClusterPrivilege.Category;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Static utility class for working with {@link GlobalConfigurableClusterPrivilege} instances
 */
public final class GlobalConfigurableClusterPrivileges {

    public static final GlobalConfigurableClusterPrivilege[] EMPTY_ARRAY = new GlobalConfigurableClusterPrivilege[0];

    public static final Writeable.Reader<GlobalConfigurableClusterPrivilege> READER =
        in1 -> in1.readNamedWriteable(GlobalConfigurableClusterPrivilege.class);
    public static final Writeable.Writer<GlobalConfigurableClusterPrivilege> WRITER =
        (out1, value) -> out1.writeNamedWriteable(value);

    private GlobalConfigurableClusterPrivileges() {
    }

    /**
     * Utility method to read an array of {@link GlobalConfigurableClusterPrivilege} objects from a {@link StreamInput}
     */
    public static GlobalConfigurableClusterPrivilege[] readArray(StreamInput in) throws IOException {
        return in.readArray(READER, GlobalConfigurableClusterPrivilege[]::new);
    }

    /**
     * Utility method to write an array of {@link GlobalConfigurableClusterPrivilege} objects to a {@link StreamOutput}
     */
    public static void writeArray(StreamOutput out, GlobalConfigurableClusterPrivilege[] privileges) throws IOException {
        out.writeArray(WRITER, privileges);
    }

    /**
     * Writes a single object value to the {@code builder} that contains each of the provided privileges.
     * The privileges are grouped according to their {@link GlobalConfigurableClusterPrivilege#getCategory() categories}
     */
    public static XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params,
                                             Collection<GlobalConfigurableClusterPrivilege> privileges) throws IOException {
        builder.startObject();
        for (Category category : Category.values()) {
            builder.startObject(category.field.getPreferredName());
            for (GlobalConfigurableClusterPrivilege privilege : privileges) {
                if (category == privilege.getCategory()) {
                    privilege.toXContent(builder, params);
                }
            }
            builder.endObject();
        }
        return builder.endObject();
    }

    /**
     * Read a list of privileges from the parser. The parser should be positioned at the
     * {@link XContentParser.Token#START_OBJECT} token for the privileges value
     */
    public static List<GlobalConfigurableClusterPrivilege> parse(XContentParser parser) throws IOException {
        List<GlobalConfigurableClusterPrivilege> privileges = new ArrayList<>();

        expectedToken(parser.currentToken(), parser, XContentParser.Token.START_OBJECT);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            expectedToken(parser.currentToken(), parser, XContentParser.Token.FIELD_NAME);

            expectFieldName(parser, Category.APPLICATION.field);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.START_OBJECT);
            expectedToken(parser.nextToken(), parser, XContentParser.Token.FIELD_NAME);

            expectFieldName(parser, ManageApplicationPrivileges.Fields.MANAGE);
            privileges.add(ManageApplicationPrivileges.parse(parser));
            expectedToken(parser.nextToken(), parser, XContentParser.Token.END_OBJECT);
        }

        return privileges;
    }

    private static void expectedToken(XContentParser.Token read, XContentParser parser, XContentParser.Token expected) {
        if (read != expected) {
            throw new XContentParseException(parser.getTokenLocation(),
                "failed to parse privilege. expected [" + expected + "] but found [" + read + "] instead");
        }
    }

    private static void expectFieldName(XContentParser parser, ParseField... fields) throws IOException {
        final String fieldName = parser.currentName();
        if (Arrays.stream(fields).anyMatch(pf -> pf.match(fieldName, parser.getDeprecationHandler())) == false) {
            throw new XContentParseException(parser.getTokenLocation(),
                "failed to parse privilege. expected " + (fields.length == 1 ? "field name" : "one of") + " ["
                    + Strings.arrayToCommaDelimitedString(fields) + "] but found [" + fieldName + "] instead");
        }
    }

}
