/*
 *
 *  * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  * or more contributor license agreements. Licensed under the Elastic License;
 *  * you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.apache.lucene.util.automaton.Automaton;
import org.elasticsearch.common.Strings;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.GetApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.util.function.BiPredicate;

/**
 * {@link ManageOwnApiKeyClusterPrivilege} is a named {@link NamedConfigurableClusterPrivilege} that
 * allows access to API key actions on API keys owned by the authenticated user.
 */
public class ManageOwnApiKeyClusterPrivilege implements NamedConfigurableClusterPrivilege {

    private Automaton manageOwnApiKeyActionsAutomaton = Automatons.patterns("cluster:admin/xpack/security/api_key/*");
    private BiPredicate<TransportRequest, Authentication> requestPredicate;

    @Override
    public Automaton automaton() {
        return manageOwnApiKeyActionsAutomaton;
    }

    @Override
    public BiPredicate<TransportRequest, Authentication> getRequestPredicate() {
        requestPredicate = (request, authentication) -> {
            if (request instanceof CreateApiKeyRequest) {
                return true;
            } else if (request instanceof GetApiKeyRequest) {
                final GetApiKeyRequest getApiKeyRequest = (GetApiKeyRequest) request;
                return checkIfUserIsOwnerOfApiKeys(authentication, getApiKeyRequest.getApiKeyId(), getApiKeyRequest.getUserName(),
                    getApiKeyRequest.getRealmName());
            } else if (request instanceof InvalidateApiKeyRequest) {
                final InvalidateApiKeyRequest invalidateApiKeyRequest = (InvalidateApiKeyRequest) request;
                return checkIfUserIsOwnerOfApiKeys(authentication, invalidateApiKeyRequest.getId(),
                    invalidateApiKeyRequest.getUserName(), invalidateApiKeyRequest.getRealmName());
            }
            return false;
        };

        return requestPredicate;
    }

    @Override
    public String name() {
        return "manage_own_api_key";
    }

    private boolean checkIfUserIsOwnerOfApiKeys(Authentication authentication, String apiKeyId, String username, String realmName) {
        if (authentication.getAuthenticatedBy().getType().equals("_es_api_key")) {
            // API key id from authentication must match the id from request
            String authenticatedApiKeyId = (String) authentication.getMetadata().get("_security_api_key_id");
            if (Strings.hasText(apiKeyId)) {
                return apiKeyId.equals(authenticatedApiKeyId);
            }
        } else {
            String authenticatedUserPrincipal = authentication.getUser().principal();
            String authenticatedUserRealm = authentication.getAuthenticatedBy().getName();
            if (Strings.hasText(username) && Strings.hasText(realmName)) {
                return username.equals(authenticatedUserPrincipal) && realmName.equals(authenticatedUserRealm);
            }
        }
        return false;
    }
}
