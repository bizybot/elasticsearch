/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authc.kerberos.support;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static org.elasticsearch.xpack.security.authc.kerberos.support.KerberosTicketValidator.SPNEGO_OID;
import static org.elasticsearch.xpack.security.authc.kerberos.support.KerberosTicketValidator.IS_IBM_JVM;
import static org.elasticsearch.xpack.security.authc.kerberos.support.KerberosTicketValidator.IBM_KRB5_LOGIN_MODULE;
import static org.elasticsearch.xpack.security.authc.kerberos.support.KerberosTicketValidator.SUN_KRB5_LOGIN_MODULE;

/**
 * This class is used as a Spnego client during testing and handles SPNEGO
 * interactions using GSS context negotiation.<br>
 * It is not advisable to share a SpnegoClient between threads as there is no
 * synchronization in place, internally this depends on {@link GSSContext} for
 * context negotiation which maintains sequencing for replay detections.<br>
 * Use {@link #close()} to release and dispose {@link LoginContext} and
 * {@link GSSContext} after usage.
 */
class SpnegoClient implements AutoCloseable {
    private static final Logger LOGGER = ESLoggerFactory.getLogger(SpnegoClient.class);

    public static final String CRED_CONF_NAME = "PasswordConf";
    private final GSSManager gssManager = GSSManager.getInstance();
    private final LoginContext loginContext;
    private final GSSContext gssContext;

    /**
     * Creates SpengoClient to interact with given service principal<br>
     * Use {@link #close()} to logout {@link LoginContext} and dispose
     * {@link GSSContext} after usage.
     *
     * @param userPrincipalName User principal name for login as client
     * @param password password for client
     * @param servicePrincipalName Service principal name with whom this client
     *            interacts with.
     * @throws PrivilegedActionException
     * @throws GSSException
     */
    SpnegoClient(final String userPrincipalName, final SecureString password, final String servicePrincipalName)
            throws PrivilegedActionException, GSSException {
        String oldUseSubjectCredsOnlyFlag = null;
        try {
            oldUseSubjectCredsOnlyFlag = getAndSetUseSubjectCredsOnlySystemProperty("true");
            LOGGER.info("SpnegoClient with userPrincipalName : {}", userPrincipalName);
            final GSSName gssUserPrincipalName = gssManager.createName(userPrincipalName, GSSName.NT_USER_NAME);
            final GSSName gssServicePrincipalName = gssManager.createName(servicePrincipalName, GSSName.NT_USER_NAME);
            loginContext = AccessController
                    .doPrivileged((PrivilegedExceptionAction<LoginContext>) () -> loginUsingPassword(userPrincipalName, password));
            // Test this if this is still applicable with latest IBM JVM
            // Ref: http://www-01.ibm.com/support/docview.wss?uid=swg1IZ54545
            // No bug found in the IBM DB: https://developer.ibm.com/javasdk/support/fixes/
            // But old Tomcat bug was fixed and the code is still present
            // https://bz.apache.org/bugzilla/show_bug.cgi?id=56013
            final int lifetime = (IS_IBM_JVM) ? GSSCredential.INDEFINITE_LIFETIME : GSSCredential.DEFAULT_LIFETIME;
            final GSSCredential userCreds =
                    KerberosTestCase.doAsWrapper(loginContext.getSubject(), (PrivilegedExceptionAction<GSSCredential>) () -> gssManager
                            .createCredential(gssUserPrincipalName, lifetime, SPNEGO_OID, GSSCredential.INITIATE_ONLY));
            gssContext = gssManager.createContext(gssServicePrincipalName.canonicalize(SPNEGO_OID), SPNEGO_OID, userCreds, lifetime);
            gssContext.requestMutualAuth(true);
        } catch (PrivilegedActionException pve) {
            LOGGER.error("privileged action exception, with root cause", pve.getException());
            throw pve;
        } finally {
            getAndSetUseSubjectCredsOnlySystemProperty(oldUseSubjectCredsOnlyFlag);
        }
    }

    /**
     * GSSContext initiator side handling, initiates context establishment and
     * returns the base64 encoded token to be sent to server.
     *
     * @return Base64 encoded token
     * @throws PrivilegedActionException
     */
    String getBase64EncodedTokenForSpnegoHeader() throws PrivilegedActionException {
        final byte[] outToken = KerberosTestCase.doAsWrapper(loginContext.getSubject(),
                (PrivilegedExceptionAction<byte[]>) () -> gssContext.initSecContext(new byte[0], 0, 0));
        return Base64.getEncoder().encodeToString(outToken);
    }

    /**
     * Handles server response and returns new token if any to be sent to server.
     *
     * @param base64Token inToken received from server passed to initSecContext for
     *            gss negotiation
     * @return Base64 encoded token to be sent to server. May return {@code null} if
     *         nothing to be sent.
     * @throws PrivilegedActionException
     */
    String handleResponse(final String base64Token) throws PrivilegedActionException {
        if (gssContext.isEstablished()) {
            throw new IllegalStateException("GSS Context has already been established");
        }
        final byte[] token = Base64.getDecoder().decode(base64Token);
        final byte[] outToken = KerberosTestCase.doAsWrapper(loginContext.getSubject(),
                (PrivilegedExceptionAction<byte[]>) () -> gssContext.initSecContext(token, 0, token.length));
        if (outToken == null || outToken.length == 0) {
            return null;
        }
        return Base64.getEncoder().encodeToString(outToken);
    }

    /**
     * Spnego Client after usage needs to be closed in order to logout from
     * {@link LoginContext} and dispose {@link GSSContext}
     */
    public void close() throws LoginException, GSSException, PrivilegedActionException {
        if (loginContext != null) {
            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                loginContext.logout();
                return null;
            });
        }
        if (gssContext != null) {
            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                gssContext.dispose();
                return null;
            });
        }
    }

    /**
     * @return {@code true} If the context was established
     */
    boolean isEstablished() {
        return gssContext.isEstablished();
    }

    /**
     * Performs authentication using provided principal name and password for client
     *
     * @param principal Principal name
     * @param password {@link SecureString}
     * @param settings {@link Settings}
     * @return authenticated {@link LoginContext} instance. Note: This needs to be
     *         closed {@link LoginContext#logout()} after usage.
     * @throws LoginException
     */
    private static LoginContext loginUsingPassword(final String principal, final SecureString password) throws LoginException {
        final Set<Principal> principals = Collections.singleton(new KerberosPrincipal(principal));

        final Subject subject = new Subject(false, principals, Collections.emptySet(), Collections.emptySet());

        final Configuration conf = new PasswordJaasConf(principal);
        final CallbackHandler callback = new KrbCallbackHandler(principal, password);
        final LoginContext loginContext = new LoginContext(CRED_CONF_NAME, subject, callback, conf);
        loginContext.login();
        return loginContext;
    }

    /**
     * Usually we would have a JAAS configuration file for login configuration.
     * Instead of an additional file setting as we do not want the options to be
     * customizable we are constructing it in memory.
     * <p>
     * As we are uing this instead of jaas.conf, this requires refresh of
     * {@link Configuration} and reqires appropriate security permissions to do so.
     */
    static class PasswordJaasConf extends Configuration {
        private final String principal;

        PasswordJaasConf(final String principal) {
            this.principal = principal;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("principal", principal);
            if (IS_IBM_JVM) {
                options.put("credsType", "initiator");
            } else {
                options.put("storeKey", Boolean.TRUE.toString());
                options.put("useTicketCache", Boolean.FALSE.toString());
                options.put("useKeyTab", Boolean.FALSE.toString());
                options.put("renewTGT", Boolean.FALSE.toString());
                options.put("refreshKrb5Config", Boolean.TRUE.toString());
                options.put("isInitiator", Boolean.TRUE.toString());
            }
            options.put("debug", Boolean.TRUE.toString());

            return new AppConfigurationEntry[] { new AppConfigurationEntry((IS_IBM_JVM) ? IBM_KRB5_LOGIN_MODULE : SUN_KRB5_LOGIN_MODULE,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, Collections.unmodifiableMap(options)) };
        }
    }

    /**
     * Jaas call back handler to provide credentials.
     */
    static class KrbCallbackHandler implements CallbackHandler {
        private final String principal;
        private final SecureString password;

        KrbCallbackHandler(final String principal, final SecureString password) {
            this.principal = principal;
            this.password = password;
        }

        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    if (pc.getPrompt().contains(principal)) {
                        pc.setPassword(password.getChars());
                        break;
                    }
                }
            }
        }
    }

    private static String getAndSetUseSubjectCredsOnlySystemProperty(final String value) {
        String retVal = null;
        try {
            retVal = AccessController.doPrivileged(new PrivilegedExceptionAction<String>() {

                @Override
                @SuppressForbidden(
                        reason = "For tests where we provide credentials, need to set and reset javax.security.auth.useSubjectCredsOnly")
                public String run() throws Exception {
                    String oldValue = System.getProperty("javax.security.auth.useSubjectCredsOnly");
                    if (value != null) {
                        System.setProperty("javax.security.auth.useSubjectCredsOnly", value);
                    }
                    return oldValue;
                }

            });
        } catch (PrivilegedActionException e) {
            throw ExceptionsHelper.convertToRuntime(e);
        }
        return retVal;
    }
}
