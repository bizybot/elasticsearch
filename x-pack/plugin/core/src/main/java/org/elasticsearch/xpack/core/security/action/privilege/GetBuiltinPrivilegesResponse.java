/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.security.action.privilege;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Response containing one or more application privileges retrieved from the security index
 */
public final class GetBuiltinPrivilegesResponse extends ActionResponse implements ToXContentObject {

    private String[] clusterPrivileges;
    private String[] indexPrivileges;
    private Deprecations deprecations;

    public GetBuiltinPrivilegesResponse(String[] clusterPrivileges, String[] indexPrivileges, Deprecations deprecations) {
        this.clusterPrivileges = Objects.requireNonNull(clusterPrivileges, "Cluster privileges cannot be null");
        this.indexPrivileges =  Objects.requireNonNull(indexPrivileges, "Index privileges cannot be null");
        this.deprecations = deprecations;
    }

    public GetBuiltinPrivilegesResponse(Collection<String> clusterPrivileges,
                                        Collection<String> indexPrivileges, Deprecations deprecations) {
        this(clusterPrivileges.toArray(Strings.EMPTY_ARRAY), indexPrivileges.toArray(Strings.EMPTY_ARRAY), deprecations);
    }

    public GetBuiltinPrivilegesResponse() {
        this(Collections.emptySet(), Collections.emptySet(), null);
    }

    public GetBuiltinPrivilegesResponse(StreamInput in) throws IOException {
        super(in);
        this.clusterPrivileges = in.readStringArray();
        this.indexPrivileges = in.readStringArray();
        if (in.getVersion().onOrAfter(Version.V_8_0_0)) {
            this.deprecations = in.readOptionalWriteable(Deprecations::new);
        }
    }

    public String[] getClusterPrivileges() {
        return clusterPrivileges;
    }

    public String[] getIndexPrivileges() {
        return indexPrivileges;
    }

    public Deprecations getDeprecations() {
        return deprecations;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringArray(clusterPrivileges);
        out.writeStringArray(indexPrivileges);
        if (out.getVersion().onOrAfter(Version.V_8_0_0)) {
            out.writeOptionalWriteable(deprecations);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.array("cluster", getClusterPrivileges());
        builder.array("index", getIndexPrivileges());
        builder.field("deprecations", getDeprecations());
        builder.endObject();
        return builder;
    }

    public static class Deprecations implements ToXContentObject, Writeable {
        private List<DeprecationInfo> clusterPrivileges = new ArrayList<>();
        private List<DeprecationInfo> indexPrivileges = new ArrayList<>();

        public Deprecations() {
        }

        public Deprecations(StreamInput in) throws IOException {
            this.clusterPrivileges = in.readList(DeprecationInfo::new);
            this.indexPrivileges = in.readList(DeprecationInfo::new);
        }

        public void addDeprecatedClusterPrivilege(String name, String alternative, boolean hasExactReplacement) {
            this.clusterPrivileges.add(new DeprecationInfo(name, alternative, hasExactReplacement));
        }

        public void addDeprecatedIndexPrivilege(String name, String alternative, boolean hasExactReplacement) {
            this.indexPrivileges.add(new DeprecationInfo(name, alternative, hasExactReplacement));
        }

        public List<DeprecationInfo> getClusterPrivileges() {
            return clusterPrivileges;
        }

        public List<DeprecationInfo> getIndexPrivileges() {
            return indexPrivileges;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeList(clusterPrivileges);
            out.writeList(indexPrivileges);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Deprecations that = (Deprecations) o;
            return clusterPrivileges.equals(that.clusterPrivileges) &&
                indexPrivileges.equals(that.indexPrivileges);
        }

        @Override
        public int hashCode() {
            return Objects.hash(clusterPrivileges, indexPrivileges);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.startObject()
                .field("cluster", clusterPrivileges)
                .field("index", indexPrivileges)
                .endObject();
        }
    }
    public static class DeprecationInfo implements ToXContentObject, Writeable {
        private String name;
        private String alternative;
        private boolean isExactReplacement;

        DeprecationInfo(String name, @Nullable String alternative, boolean isExactReplacement) {
            this.name = Objects.requireNonNull(name, "deprecated privilege name is required");
            this.alternative = alternative;
            this.isExactReplacement = isExactReplacement;
        }

        DeprecationInfo(StreamInput in) throws IOException {
            this.name = in.readString();
            this.alternative = in.readString();
            this.isExactReplacement = in.readBoolean();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(name);
            out.writeString(alternative);
            out.writeBoolean(isExactReplacement);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            DeprecationInfo that = (DeprecationInfo) o;
            return isExactReplacement == that.isExactReplacement &&
                name.equals(that.name) &&
                Objects.equals(alternative, that.alternative);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, alternative, isExactReplacement);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.startObject()
                .field("name", name)
                .field("alternative", alternative)
                .field("isExactReplacement", isExactReplacement)
                .endObject();
        }
    }
}
