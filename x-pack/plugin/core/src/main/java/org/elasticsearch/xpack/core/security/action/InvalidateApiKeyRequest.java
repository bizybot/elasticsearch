/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;

import static org.elasticsearch.action.ValidateActions.addValidationError;

/**
 * Request for invalidating API key(s) so that it can no longer be used
 */
public final class InvalidateApiKeyRequest extends ActionRequest {

    private String realmName;
    private String userName;
    private String apiKeyId;
    private String apiKeyName;

    public InvalidateApiKeyRequest() {
    }

    private InvalidateApiKeyRequest(@Nullable String realmName, @Nullable String userName, @Nullable String apiKeyId,
            @Nullable String apiKeyName) {
        this.realmName = realmName;
        this.userName = userName;
        this.apiKeyId = apiKeyId;
        this.apiKeyName = apiKeyName;
    }

    public String getRealmName() {
        return realmName;
    }

    public String getUserName() {
        return userName;
    }

    public String getApiKeyId() {
        return apiKeyId;
    }

    public String getApiKeyName() {
        return apiKeyName;
    }

    /**
     * Creates invalidate api key request for given realm name
     * @param realmName realm name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingRealmName(String realmName) {
        return new InvalidateApiKeyRequest(realmName, null, null, null);
    }

    /**
     * Creates invalidate API key request for given user name
     * @param userName user name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingUserName(String userName) {
        return new InvalidateApiKeyRequest(null, userName, null, null);
    }

    /**
     * Creates invalidate API key request for given realm and user name
     * @param realmName realm name
     * @param userName user name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingRealmAndUserName(String realmName, String userName) {
        return new InvalidateApiKeyRequest(realmName, userName, null, null);
    }

    /**
     * Creates invalidate API key request for given api key id
     * @param apiKeyId api key id
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyId(String apiKeyId) {
        return new InvalidateApiKeyRequest(null, null, apiKeyId, null);
    }

    /**
     * Creates invalidate api key request for given api key name
     * @param apiKeyName api key name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyName(String apiKeyName) {
        return new InvalidateApiKeyRequest(null, null, null, apiKeyName);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (Strings.hasText(realmName) == false && Strings.hasText(userName) == false && Strings.hasText(apiKeyId) == false
                && Strings.hasText(apiKeyName) == false) {
            validationException = addValidationError("api key id or api key name or username and/or realm name must be specified", null);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(realmName);
        out.writeOptionalString(userName);
        out.writeOptionalString(apiKeyId);
        out.writeOptionalString(apiKeyName);
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        realmName = in.readOptionalString();
        userName = in.readOptionalString();
        apiKeyId = in.readOptionalString();
        apiKeyName = in.readOptionalString();
    }
}
