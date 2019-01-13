/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.CharArrays;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.logging.DeprecationLogger;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.ScrollHelper;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyRequest;
import org.elasticsearch.xpack.core.security.action.CreateApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.support.ApiKeysInvalidationResult;
import org.elasticsearch.xpack.core.security.authc.support.Hasher;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;
import org.elasticsearch.xpack.security.support.SecurityIndexManager;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.SecretKeyFactory;

import static org.elasticsearch.action.support.TransportActions.isShardNotAvailableException;
import static org.elasticsearch.search.SearchService.DEFAULT_KEEPALIVE_SETTING;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;

public class ApiKeyService {

    private static final Logger logger = LogManager.getLogger(ApiKeyService.class);
    private static final DeprecationLogger deprecationLogger = new DeprecationLogger(logger);
    private static final String TYPE = "doc";
    private static final int MAX_RETRY_ATTEMPTS = 5;
    static final String API_KEY_ID_KEY = "_security_api_key_id";
    static final String API_KEY_ROLE_DESCRIPTORS_KEY = "_security_api_key_role_descriptors";
    static final String API_KEY_ROLE_KEY = "_security_api_key_role";

    public static final Setting<String> PASSWORD_HASHING_ALGORITHM = new Setting<>(
        "xpack.security.authc.api_key_hashing.algorithm", "pbkdf2", Function.identity(), v -> {
        if (Hasher.getAvailableAlgoStoredHash().contains(v.toLowerCase(Locale.ROOT)) == false) {
            throw new IllegalArgumentException("Invalid algorithm: " + v + ". Valid values for password hashing are " +
                Hasher.getAvailableAlgoStoredHash().toString());
        } else if (v.regionMatches(true, 0, "pbkdf2", 0, "pbkdf2".length())) {
            try {
                SecretKeyFactory.getInstance("PBKDF2withHMACSHA512");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException(
                    "Support for PBKDF2WithHMACSHA512 must be available in order to use any of the " +
                        "PBKDF2 algorithms for the [xpack.security.authc.api_key.hashing.algorithm] setting.", e);
            }
        }
    }, Setting.Property.NodeScope);
    public static final Setting<TimeValue> DELETE_TIMEOUT = Setting.timeSetting("xpack.security.authc.api_key.delete.timeout",
            TimeValue.MINUS_ONE, Property.NodeScope);
    public static final Setting<TimeValue> DELETE_INTERVAL = Setting.timeSetting("xpack.security.authc.api_key.delete.interval",
            TimeValue.timeValueMinutes(30L), Property.NodeScope);

    private final Clock clock;
    private final Client client;
    private final SecurityIndexManager securityIndex;
    private final ClusterService clusterService;
    private final Hasher hasher;
    private final boolean enabled;
    private final Settings settings;
    private final ExpiredApiKeysRemover expiredApiKeysRemover;
    private volatile long lastExpirationRunMs;
    private final TimeValue deleteInterval;

    public ApiKeyService(Settings settings, Clock clock, Client client, SecurityIndexManager securityIndex, ClusterService clusterService) {
        this.clock = clock;
        this.client = client;
        this.securityIndex = securityIndex;
        this.clusterService = clusterService;
        this.enabled = XPackSettings.API_KEY_SERVICE_ENABLED_SETTING.get(settings);
        this.hasher = Hasher.resolve(PASSWORD_HASHING_ALGORITHM.get(settings));
        this.deleteInterval = DELETE_INTERVAL.get(settings);
        this.settings = settings;
        this.expiredApiKeysRemover = new ExpiredApiKeysRemover(settings, client);
    }

    /**
     * Asynchronously creates a new API key based off of the request and authentication
     * @param authentication the authentication that this api key should be based off of
     * @param request the request to create the api key included any permission restrictions
     * @param listener the listener that will be used to notify of completion
     */
    public void createApiKey(Authentication authentication, CreateApiKeyRequest request, ActionListener<CreateApiKeyResponse> listener) {
        ensureEnabled();
        if (authentication == null) {
            listener.onFailure(new IllegalArgumentException("authentication must be provided"));
        } else {
            final Instant created = clock.instant();
            final Instant expiration = getApiKeyExpiration(created, request);
            final SecureString apiKey = UUIDs.randomBase64UUIDSecureString();
            final Version version = clusterService.state().nodes().getMinNodeVersion();
            if (version.before(Version.V_7_0_0)) { // TODO(jaymode) change to V6_6_0 on backport!
                logger.warn("nodes prior to the minimum supported version for api keys {} exist in the cluster; these nodes will not be " +
                    "able to use api keys", Version.V_7_0_0);
            }

            final char[] keyHash = hasher.hash(apiKey);
            try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
                builder.startObject()
                    .field("doc_type", "api_key")
                    .field("creation_time", created.toEpochMilli())
                    .field("expiration_time", expiration == null ? null : expiration.toEpochMilli())
                    .field("api_key_invalidated", false);

                byte[] utf8Bytes = null;
                try {
                    utf8Bytes = CharArrays.toUtf8Bytes(keyHash);
                    builder.field("api_key_hash").utf8Value(utf8Bytes, 0, utf8Bytes.length);
                } finally {
                    if (utf8Bytes != null) {
                        Arrays.fill(utf8Bytes, (byte) 0);
                    }
                }

                builder.startObject("role_descriptors");
                for (RoleDescriptor descriptor : request.getRoleDescriptors()) {
                    builder.field(descriptor.getName(), (contentBuilder, params) -> descriptor.toXContent(contentBuilder, params, true));
                }
                builder.endObject();
                builder.field("name", request.getName())
                    .field("version", version.id)
                    .startObject("creator")
                    .field("principal", authentication.getUser().principal())
                    .field("metadata", authentication.getUser().metadata())
                    .field("realm", authentication.getLookedUpBy() == null ?
                        authentication.getAuthenticatedBy().getName() : authentication.getLookedUpBy().getName())
                    .endObject()
                    .endObject();
                final IndexRequest indexRequest =
                    client.prepareIndex(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE)
                        .setSource(builder)
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .request();
                securityIndex.prepareIndexIfNeededThenExecute(listener::onFailure, () ->
                    executeAsyncWithOrigin(client, SECURITY_ORIGIN, IndexAction.INSTANCE, indexRequest,
                        ActionListener.wrap(indexResponse ->
                                listener.onResponse(new CreateApiKeyResponse(request.getName(), indexResponse.getId(), apiKey, expiration)),
                            listener::onFailure)));
            } catch (IOException e) {
                listener.onFailure(e);
            } finally {
                Arrays.fill(keyHash, (char) 0);
            }
        }
    }

    /**
     * Checks for the presence of a {@code Authorization} header with a value that starts with
     * {@code ApiKey }. If found this will attempt to authenticate the key.
     */
    void authenticateWithApiKeyIfPresent(ThreadContext ctx, ActionListener<AuthenticationResult> listener) {
        if (enabled) {
            final ApiKeyCredentials credentials;
            try {
                credentials = getCredentialsFromHeader(ctx);
            } catch (IllegalArgumentException iae) {
                listener.onResponse(AuthenticationResult.unsuccessful(iae.getMessage(), iae));
                return;
            }

            if (credentials != null) {
                final GetRequest getRequest = client.prepareGet(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE, credentials.getId())
                    .setFetchSource(true).request();
                executeAsyncWithOrigin(ctx, SECURITY_ORIGIN, getRequest, ActionListener.<GetResponse>wrap(response -> {
                    if (response.isExists()) {
                        try (ApiKeyCredentials ignore = credentials) {
                            final Map<String, Object> source = response.getSource();
                            validateApiKeyCredentials(source, credentials, clock, listener);
                        }
                    } else {
                        credentials.close();
                        listener.onResponse(
                            AuthenticationResult.unsuccessful("unable to find apikey with id " + credentials.getId(), null));
                    }
                }, e -> {
                    credentials.close();
                    listener.onResponse(AuthenticationResult.unsuccessful("apikey authentication for id " + credentials.getId() +
                        " encountered a failure", e));
                }), client::get);
            } else {
                listener.onResponse(AuthenticationResult.notHandled());
            }
        } else {
            listener.onResponse(AuthenticationResult.notHandled());
        }
    }

    /**
     * The current request has been authenticated by an API key and this method enables the
     * retrieval of role descriptors that are associated with the api key and triggers the building
     * of the {@link Role} to authorize the request.
     */
    public void getRoleForApiKey(Authentication authentication, CompositeRolesStore rolesStore, ActionListener<Role> listener) {
        if (authentication.getAuthenticationType() != Authentication.AuthenticationType.API_KEY) {
            throw new IllegalStateException("authentication type must be api key but is " + authentication.getAuthenticationType());
        }

        final Map<String, Object> metadata = authentication.getMetadata();
        final String apiKeyId = (String) metadata.get(API_KEY_ID_KEY);

        final Map<String, Object> roleDescriptors = (Map<String, Object>) metadata.get(API_KEY_ROLE_DESCRIPTORS_KEY);
        final List<RoleDescriptor> roleDescriptorList = roleDescriptors.entrySet().stream()
            .map(entry -> {
                final String name = entry.getKey();
                final Map<String, Object> rdMap = (Map<String, Object>) entry.getValue();
                try (XContentBuilder builder = XContentBuilder.builder(XContentType.JSON.xContent())) {
                    builder.map(rdMap);
                    try (XContentParser parser = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY,
                        new ApiKeyLoggingDeprecationHandler(deprecationLogger, apiKeyId),
                        BytesReference.bytes(builder).streamInput())) {
                        return RoleDescriptor.parse(name, parser, false);
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }).collect(Collectors.toList());

        rolesStore.buildAndCacheRoleFromDescriptors(roleDescriptorList, apiKeyId, listener);

    }

    /**
     * Validates the ApiKey using the source map
     * @param source the source map from a get of the ApiKey document
     * @param credentials the credentials provided by the user
     * @param listener the listener to notify after verification
     */
    static void validateApiKeyCredentials(Map<String, Object> source, ApiKeyCredentials credentials, Clock clock,
                                          ActionListener<AuthenticationResult> listener) {
        final Boolean invalidated = (Boolean) source.get("api_key_invalidated");
        if (invalidated == null) {
            listener.onResponse(AuthenticationResult.terminate("api key document is missing invalidated field", null));
        } else if (invalidated) {
            listener.onResponse(AuthenticationResult.terminate("api key has been invalidated", null));
        }

        final String apiKeyHash = (String) source.get("api_key_hash");
        if (apiKeyHash == null) {
            throw new IllegalStateException("api key hash is missing");
        }
        final boolean verified = verifyKeyAgainstHash(apiKeyHash, credentials);

        if (verified) {
            final Long expirationEpochMilli = (Long) source.get("expiration_time");
            if (expirationEpochMilli == null || Instant.ofEpochMilli(expirationEpochMilli).isAfter(clock.instant())) {
                final Map<String, Object> creator = Objects.requireNonNull((Map<String, Object>) source.get("creator"));
                final String principal = Objects.requireNonNull((String) creator.get("principal"));
                final Map<String, Object> metadata = (Map<String, Object>) creator.get("metadata");
                final Map<String, Object> roleDescriptors = (Map<String, Object>) source.get("role_descriptors");
                final String[] roleNames = roleDescriptors.keySet().toArray(Strings.EMPTY_ARRAY);
                final User apiKeyUser = new User(principal, roleNames, null, null, metadata, true);
                final Map<String, Object> authResultMetadata = new HashMap<>();
                authResultMetadata.put(API_KEY_ROLE_DESCRIPTORS_KEY, roleDescriptors);
                authResultMetadata.put(API_KEY_ID_KEY, credentials.getId());
                listener.onResponse(AuthenticationResult.success(apiKeyUser, authResultMetadata));
            } else {
                listener.onResponse(AuthenticationResult.terminate("api key is expired", null));
            }
        } else {
            listener.onResponse(AuthenticationResult.unsuccessful("invalid credentials", null));
        }
    }

    /**
     * Gets the API Key from the <code>Authorization</code> header if the header begins with
     * <code>ApiKey </code>
     */
    static ApiKeyCredentials getCredentialsFromHeader(ThreadContext threadContext) {
        String header = threadContext.getHeader("Authorization");
        if (Strings.hasText(header) && header.regionMatches(true, 0, "ApiKey ", 0, "ApiKey ".length())
            && header.length() > "ApiKey ".length()) {
            final byte[] decodedApiKeyCredBytes = Base64.getDecoder().decode(header.substring("ApiKey ".length()));
            char[] apiKeyCredChars = null;
            try {
                apiKeyCredChars = CharArrays.utf8BytesToChars(decodedApiKeyCredBytes);
                int colonIndex = -1;
                for (int i = 0; i < apiKeyCredChars.length; i++) {
                    if (apiKeyCredChars[i] == ':') {
                        colonIndex = i;
                        break;
                    }
                }

                if (colonIndex < 1) {
                    throw new IllegalArgumentException("invalid ApiKey value");
                }
                return new ApiKeyCredentials(new String(Arrays.copyOfRange(apiKeyCredChars, 0, colonIndex)),
                    new SecureString(Arrays.copyOfRange(apiKeyCredChars, colonIndex + 1, apiKeyCredChars.length)));
            } finally {
                if (apiKeyCredChars != null) {
                    Arrays.fill(apiKeyCredChars, (char) 0);
                }
            }
        }
        return null;
    }

    private static boolean verifyKeyAgainstHash(String apiKeyHash, ApiKeyCredentials credentials) {
        final char[] apiKeyHashChars = apiKeyHash.toCharArray();
        try {
            Hasher hasher = Hasher.resolveFromHash(apiKeyHash.toCharArray());
            return hasher.verify(credentials.getKey(), apiKeyHashChars);
        } finally {
            Arrays.fill(apiKeyHashChars, (char) 0);
        }
    }

    private Instant getApiKeyExpiration(Instant now, CreateApiKeyRequest request) {
        if (request.getExpiration() != null) {
            return now.plusSeconds(request.getExpiration().getSeconds());
        } else {
            return null;
        }
    }

    private void ensureEnabled() {
        if (enabled == false) {
            throw new IllegalStateException("api keys are not enabled");
        }
    }

    // package private class for testing
    static final class ApiKeyCredentials implements Closeable {
        private final String id;
        private final SecureString key;

        ApiKeyCredentials(String id, SecureString key) {
            this.id = id;
            this.key = key;
        }

        String getId() {
            return id;
        }

        SecureString getKey() {
            return key;
        }

        @Override
        public void close() {
            key.close();
        }
    }

    private static class ApiKeyLoggingDeprecationHandler implements DeprecationHandler {

        private final DeprecationLogger deprecationLogger;
        private final String apiKeyId;

        private ApiKeyLoggingDeprecationHandler(DeprecationLogger logger, String apiKeyId) {
            this.deprecationLogger = logger;
            this.apiKeyId = apiKeyId;
        }

        @Override
        public void usedDeprecatedName(String usedName, String modernName) {
            deprecationLogger.deprecated("Deprecated field [{}] used in api key [{}], expected [{}] instead",
                usedName, apiKeyId, modernName);
        }

        @Override
        public void usedDeprecatedField(String usedName, String replacedWith) {
            deprecationLogger.deprecated("Deprecated field [{}] used in api key [{}], replaced by [{}]",
                usedName, apiKeyId, replacedWith);
        }
    }

    /**
     * Invalidate API keys for given realm and user name.
     * @param realmName realm name
     * @param userName user name
     * @param invalidateListener listener for {@link ApiKeysInvalidationResult}
     */
    public void invalidateApiKeysForRealmAndUser(String realmName, String userName,
            ActionListener<ApiKeysInvalidationResult> invalidateListener) {
        ensureEnabled();
        if (Strings.hasText(realmName) == false && Strings.hasText(userName) == false) {
            logger.trace("No realm name or username provided");
            invalidateListener.onFailure(new IllegalArgumentException("realm name or username must be provided"));
        } else {
            findActiveApiKeysForUserAndRealm(userName, realmName, ActionListener.wrap(apiKeyIds -> {
                    if (apiKeyIds.isEmpty()) {
                        logger.warn("No api keys to invalidate for realm [{}] and username [{}]", realmName, userName);
                        invalidateListener.onResponse(ApiKeysInvalidationResult.emptyResult());
                    } else {
                        invalidateAllApiKeys(apiKeyIds, invalidateListener);
                    }
                }, invalidateListener::onFailure));
        }
    }

    private void invalidateAllApiKeys(Collection<String> apiKeyIds, ActionListener<ApiKeysInvalidationResult> invalidateListener) {
        maybeStartApiKeyRemover();
        indexInvalidation(apiKeyIds, invalidateListener, new AtomicInteger(0), null);
    }

    /**
     * Invalidate API keys for given API key id
     * @param apiKeyId API key id
     * @param invalidateListener listener for {@link ApiKeysInvalidationResult}
     */
    public void invalidateApiKeysForApiKeyId(String apiKeyId, ActionListener<ApiKeysInvalidationResult> invalidateListener) {
        ensureEnabled();
        invalidateAllApiKeys(Collections.singleton(apiKeyId), invalidateListener);
    }

    /**
     * Invalidate API keys for given API key name
     * @param apiKeyName API key name
     * @param invalidateListener listener for {@link ApiKeysInvalidationResult}
     */
    public void invalidateApiKeysForApiKeyName(String apiKeyName, ActionListener<ApiKeysInvalidationResult> invalidateListener) {
        ensureEnabled();
        if (Strings.hasText(apiKeyName) == false) {
            logger.trace("No api key name provided");
            invalidateListener.onFailure(new IllegalArgumentException("api key name must be provided"));
        } else {
            findActiveApiKeysForApiKeyName(apiKeyName, ActionListener.wrap(apiKeyIds -> {
                    if (apiKeyIds.isEmpty()) {
                        logger.warn("No api keys to invalidate for api key name [{}]", apiKeyName);
                        invalidateListener.onResponse(ApiKeysInvalidationResult.emptyResult());
                    } else {
                        invalidateAllApiKeys(apiKeyIds, invalidateListener);
                    }
                }, invalidateListener::onFailure));
        }
    }

    private void findActiveApiKeysForUserAndRealm(String userName, String realmName, ActionListener<Collection<String>> listener) {
        final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
        if (frozenSecurityIndex.indexExists() == false) {
            listener.onResponse(Collections.emptyList());
        } else if (frozenSecurityIndex.isAvailable() == false) {
            listener.onFailure(frozenSecurityIndex.getUnavailableReason());
        } else {
            final BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("doc_type", "api_key"))
                .filter(QueryBuilders.termQuery("api_key_invalidated", false));
            if (Strings.hasText(userName)) {
                boolQuery.filter(QueryBuilders.termQuery("creator.principal", userName));
            }
            if (Strings.hasText(realmName)) {
                boolQuery.filter(QueryBuilders.termQuery("creator.realm", realmName));
            }

            findActiveApiKeys(boolQuery, listener);
        }
    }

    private void findActiveApiKeys(final BoolQueryBuilder boolQuery, ActionListener<Collection<String>> listener) {
        final SearchRequest request = client.prepareSearch(SecurityIndexManager.SECURITY_INDEX_NAME)
            .setScroll(DEFAULT_KEEPALIVE_SETTING.get(settings))
            .setQuery(boolQuery)
            .setVersion(false)
            .setSize(1000)
            .setFetchSource(true)
            .request();
        securityIndex.checkIndexVersionThenExecute(listener::onFailure,
            () -> ScrollHelper.fetchAllByEntity(client, request, listener,
                (SearchHit hit) -> hit.getId()));
    }

    private void findActiveApiKeysForApiKeyName(String apiKeyName, ActionListener<Collection<String>> listener) {
        final SecurityIndexManager frozenSecurityIndex = securityIndex.freeze();
        if (frozenSecurityIndex.indexExists() == false) {
            listener.onResponse(Collections.emptyList());
        } else if (frozenSecurityIndex.isAvailable() == false) {
            listener.onFailure(frozenSecurityIndex.getUnavailableReason());
        } else {
            final BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("doc_type", "api_key"))
                .filter(QueryBuilders.termQuery("api_key_invalidated", false));
            if (Strings.hasText(apiKeyName)) {
                boolQuery.filter(QueryBuilders.termQuery("name", apiKeyName));
            }

            findActiveApiKeys(boolQuery, listener);
        }
    }

    /**
     * Performs the actual invalidation of a collection of api keys
     *
     * @param apiKeyIds       the api keys to invalidate
     * @param listener        the listener to notify upon completion
     * @param attemptCount    the number of attempts to invalidate that have already been tried
     * @param previousResult  if this not the initial attempt for invalidation, it contains the result of invalidating
     *                        api keys up to the point of the retry. This result is added to the result of the current attempt
     */
    private void indexInvalidation(Collection<String> apiKeyIds, ActionListener<ApiKeysInvalidationResult> listener,
                                   AtomicInteger attemptCount, @Nullable ApiKeysInvalidationResult previousResult) {
        if (apiKeyIds.isEmpty()) {
            logger.warn("No api key ids provided for invalidation");
            listener.onFailure(new ElasticsearchSecurityException("No api key ids provided for invalidation"));
        } else if (attemptCount.get() > MAX_RETRY_ATTEMPTS) {
            logger.warn("Failed to invalidate [{}] api keys after [{}] attempts", apiKeyIds.size(),
                attemptCount.get());
            listener.onFailure(new ElasticsearchSecurityException("failed to invalidate api keys"));
        } else {
            BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();
            for (String apiKeyId : apiKeyIds) {
                UpdateRequest request = client.prepareUpdate(SecurityIndexManager.SECURITY_INDEX_NAME, TYPE, apiKeyId)
                    .setDoc(Collections.singletonMap("api_key_invalidated", true))
                    .request();
                bulkRequestBuilder.add(request);
            }
            bulkRequestBuilder.setRefreshPolicy(RefreshPolicy.WAIT_UNTIL);
            securityIndex.prepareIndexIfNeededThenExecute(ex -> listener.onFailure(traceLog("prepare security index", ex)),
                () -> executeAsyncWithOrigin(client.threadPool().getThreadContext(), SECURITY_ORIGIN, bulkRequestBuilder.request(),
                    ActionListener.<BulkResponse>wrap(bulkResponse -> {
                        ArrayList<String> retryApiKeyIds = new ArrayList<>();
                        ArrayList<ElasticsearchException> failedRequestResponses = new ArrayList<>();
                        ArrayList<String> previouslyInvalidated = new ArrayList<>();
                        ArrayList<String> invalidated = new ArrayList<>();
                        if (null != previousResult) {
                            failedRequestResponses.addAll((previousResult.getErrors()));
                            previouslyInvalidated.addAll(previousResult.getPreviouslyInvalidatedApiKeys());
                            invalidated.addAll(previousResult.getInvalidatedApiKeys());
                        }
                        for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                            if (bulkItemResponse.isFailed()) {
                                Throwable cause = bulkItemResponse.getFailure().getCause();
                                final String failedApiKeyId = bulkItemResponse.getFailure().getId();
                                if (isShardNotAvailableException(cause)) {
                                    retryApiKeyIds.add(failedApiKeyId);
                                }
                                else {
                                    traceLog("invalidate api key", failedApiKeyId, cause);
                                    failedRequestResponses.add(new ElasticsearchException("Error invalidating api key", cause));
                                }
                            } else {
                                UpdateResponse updateResponse = bulkItemResponse.getResponse();
                                if (updateResponse.getResult() == DocWriteResponse.Result.UPDATED) {
                                    logger.debug("Invalidated api key for doc [{}]", updateResponse.getId());
                                    invalidated.add(updateResponse.getId());
                                } else if (updateResponse.getResult() == DocWriteResponse.Result.NOOP) {
                                    previouslyInvalidated.add(updateResponse.getId());
                                }
                            }
                        }
                        if (retryApiKeyIds.isEmpty() == false) {
                            ApiKeysInvalidationResult incompleteResult = new ApiKeysInvalidationResult(invalidated, previouslyInvalidated,
                                failedRequestResponses, attemptCount.get());
                            attemptCount.incrementAndGet();
                            indexInvalidation(retryApiKeyIds, listener, attemptCount, incompleteResult);
                        }
                        ApiKeysInvalidationResult result = new ApiKeysInvalidationResult(invalidated, previouslyInvalidated,
                            failedRequestResponses, attemptCount.get());
                        listener.onResponse(result);
                    }, e -> {
                        Throwable cause = ExceptionsHelper.unwrapCause(e);
                        traceLog("invalidate api keys", cause);
                        if (isShardNotAvailableException(cause)) {
                            attemptCount.incrementAndGet();
                            indexInvalidation(apiKeyIds, listener, attemptCount, previousResult);
                        } else {
                            listener.onFailure(e);
                        }
                    }), client::bulk));
        }
    }

    /**
     * Logs an exception concerning a specific api key at TRACE level (if enabled)
     */
    private <E extends Throwable> E traceLog(String action, String identifier, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof ElasticsearchException) {
                final ElasticsearchException esEx = (ElasticsearchException) exception;
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}] - [{}]", action, identifier, detail),
                        esEx);
                } else {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}]", action, identifier),
                        esEx);
                }
            } else {
                logger.trace(() -> new ParameterizedMessage("Failure in [{}] for id [{}]", action, identifier), exception);
            }
        }
        return exception;
    }

    /**
     * Logs an exception at TRACE level (if enabled)
     */
    private <E extends Throwable> E traceLog(String action, E exception) {
        if (logger.isTraceEnabled()) {
            if (exception instanceof ElasticsearchException) {
                final ElasticsearchException esEx = (ElasticsearchException) exception;
                final Object detail = esEx.getHeader("error_description");
                if (detail != null) {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}] - [{}]", action, detail), esEx);
                } else {
                    logger.trace(() -> new ParameterizedMessage("Failure in [{}]", action), esEx);
                }
            } else {
                logger.trace(() -> new ParameterizedMessage("Failure in [{}]", action), exception);
            }
        }
        return exception;
    }

    private void maybeStartApiKeyRemover() {
        if (securityIndex.isAvailable()) {
            if (client.threadPool().relativeTimeInMillis() - lastExpirationRunMs > deleteInterval.getMillis()) {
                expiredApiKeysRemover.submit(client.threadPool());
                lastExpirationRunMs = client.threadPool().relativeTimeInMillis();
            }
        }
    }
}
