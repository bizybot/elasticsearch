/*
 *
 *  Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 *  or more contributor license agreements. Licensed under the Elastic License;
 *  you may not use this file except in compliance with the Elastic License.
 *
 */

package org.elasticsearch.xpack.core.security.authz.privilege;

import org.elasticsearch.common.Strings;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.GetApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.InvalidateApiKeyRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.permission.ClusterPermission;
import org.elasticsearch.xpack.core.security.support.Automatons;

/**
 * Named cluster privilege for managing API keys owned by the current authenticated user.
 */
public class ManageOwnApiKeyClusterPrivilege implements NamedClusterPrivilege {
    public static final ManageOwnApiKeyClusterPrivilege INSTANCE = new ManageOwnApiKeyClusterPrivilege();
    private static final String PRIVILEGE_NAME = "manage_own_api_key";

    private ManageOwnApiKeyClusterPrivilege() {
    }

    @Override
    public String name() {
        return PRIVILEGE_NAME;
    }

    @Override
    public ClusterPermission.Builder buildPermission(ClusterPermission.Builder builder) {
        return builder.add(this, ManageOwnClusterPermissionCheck.INSTANCE);
    }

    private static final class ManageOwnClusterPermissionCheck extends ClusterPermission.AutomatonPermissionCheck {
        public static final ManageOwnClusterPermissionCheck INSTANCE = new ManageOwnClusterPermissionCheck();

        private ManageOwnClusterPermissionCheck() {
            super(Automatons.patterns("cluster:admin/xpack/security/api_key/*"));
        }

        @Override
        public boolean check(final String action, final TransportRequest request, final Authentication authentication) {
            if (super.check(action, request, authentication)) {
                if (request instanceof CreateApiKeyRequest) {
                    return true;
                } else if (request instanceof GetApiKeyRequest) {
                    final GetApiKeyRequest getApiKeyRequest = (GetApiKeyRequest) request;
                    return checkIfUserIsOwnerOfApiKeys(authentication, getApiKeyRequest.getApiKeyId(), getApiKeyRequest.getUserName(),
                        getApiKeyRequest.getRealmName());
                } else if (request instanceof InvalidateApiKeyRequest) {
                    final InvalidateApiKeyRequest invalidateApiKeyRequest = (InvalidateApiKeyRequest) request;
                    return checkIfUserIsOwnerOfApiKeys(authentication, invalidateApiKeyRequest.getId(),
                        invalidateApiKeyRequest.getUserName(),
                        invalidateApiKeyRequest.getRealmName());
                }
            }
            return false;
        }

        @Override
        public boolean implies(final ClusterPermission.PermissionCheck permissionCheck) {
            return super.implies(permissionCheck);
        }

        private boolean checkIfUserIsOwnerOfApiKeys(Authentication authentication, String apiKeyId, String username, String realmName) {
            if (isCurrentAuthenticationUsingSameApiKeyIdFromRequest(authentication, apiKeyId)) {
                return true;
            } else {
                /*
                 * TODO bizybot we need to think on how we can propagate appropriate error message to the end user when username, realm name
                 *   is missing. This is similar to the problem of propagating right error messages in case of access denied.
                 */
                String authenticatedUserPrincipal = authentication.getUser().principal();
                String authenticatedUserRealm = authentication.getAuthenticatedBy().getName();
                if (Strings.hasText(username) && Strings.hasText(realmName)) {
                    return username.equals(authenticatedUserPrincipal) && realmName.equals(authenticatedUserRealm);
                }
            }
            return false;
        }

        private boolean isCurrentAuthenticationUsingSameApiKeyIdFromRequest(Authentication authentication, String apiKeyId) {
            if (authentication.getAuthenticatedBy().getType().equals("_es_api_key")) {
                // API key id from authentication must match the id from request
                String authenticatedApiKeyId = (String) authentication.getMetadata().get("_security_api_key_id");
                if (Strings.hasText(apiKeyId)) {
                    return apiKeyId.equals(authenticatedApiKeyId);
                }
            }
            return false;
        }
    }
}
