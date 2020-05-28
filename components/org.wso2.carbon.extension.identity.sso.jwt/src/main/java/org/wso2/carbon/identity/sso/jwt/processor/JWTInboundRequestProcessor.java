/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.jwt.processor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse.IdentityResponseBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.jwt.exception.JWTIdentityException;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundRequest;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse.JWTInboundResponseBuilder;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The processor class represents the core functionality od the inbound authenticator. Being a subclass of the
 * IdentityProcessor class, the developer is required to override certain methods which dictate the functional
 * elements.
 *
 * In the process method, the developer is able to leverage standard methods offered by the framework to send the
 * request on to the framework (buildResponseForFrameworkLogin()) as well as handle the response after going through
 * the authentication step (processResponseFromFrameworkLogin()).
 *
 * The getRelyingPartyId() method is used for correlating the protocol of the incoming authentication request
 * (i.e. the protocol represented by this processor) against a particular SP in the Identity Server which contains the
 * information related to the actual authentication, either through local and/or federated authenticators.
 *
 * This class is extensible either by implementing the IdentityProcessor or extending the
 * JWTInboundRequestProcessor. The customized class should be defined under
 * <JWTSSO><RequestProcessor></RequestProcessor></JWTSSO> in identity.xml. Otherwise JWTInboundRequestProcessor will be
 * used as the default request processor.
 */
public class JWTInboundRequestProcessor extends IdentityProcessor {

    private static Log log = LogFactory.getLog(JWTInboundRequestProcessor.class);

    private AbstractInboundAuthenticatorConfig jwtInboundAuthConfig = null;

    private String relyingParty;
    private String redirectUrl;
    private String errorUrl;
    private String endpointUrl;
    private String apiKey;
    private JWSAlgorithm jwsAlgorithm;

    public JWTInboundRequestProcessor(AbstractInboundAuthenticatorConfig jwtInboundAuthConfig) {

        this.jwtInboundAuthConfig = jwtInboundAuthConfig;
    }

    @Override
    public String getName() {

        return jwtInboundAuthConfig.getName();
    }

    @Override
    public String getCallbackPath(IdentityMessageContext identityMessageContext) {

        String endpoint = "identity";
        String tenantDomain = identityMessageContext.getRequest().getTenantDomain();
        if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
            endpoint = "t/" + tenantDomain + "/identity";
        }
        return IdentityUtil.getServerURL(endpoint, false, false);
    }

    @Override
    public String getRelyingPartyId() {

        return this.relyingParty;
    }

    @Override
    public String getRelyingPartyId(IdentityMessageContext identityMessageContext) {

        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        if (identityRequest instanceof JWTInboundRequest) {
            this.relyingParty = identityRequest.getParameter(JWTInboundConstants.SP_ID);
            if (log.isDebugEnabled()) {
                log.debug("Relying party: " + JWTInboundUtil.neutralize(this.relyingParty));
            }
        }
        return StringUtils.isNotBlank(this.relyingParty);
    }

    /**
     * This method represents the bulk of the functionality, where the developer chooses what should take place when
     * the authentication request reaches the processor. In this instance, a check is done first to determine if the
     * request is coming new from the /identity servlet.
     *
     * @param identityRequest the request object (or a subclass of it), which can be coming either from the /identity
     *                        servlet or from the framework after authentication).
     * @return an instance of IdentityResponse which may be further customised (similar to how an IdentityRequest can
     * be customised).
     */
    public IdentityResponseBuilder process(IdentityRequest identityRequest) {

        IdentityMessageContext messageContext = new IdentityMessageContext<>(identityRequest,
                new HashMap<String, String>());
        JWTInboundResponseBuilder respBuilder = new JWTInboundResponseBuilder(messageContext);

        String sessionId = identityRequest.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
        String logoutRequestPath = JWTInboundConstants.BASE_PATH + JWTInboundConstants.LOGOUT_PATH;

        if (isRelyingPartyExist(identityRequest)) {

            // Validate endpoint URL.
            if (!validateEndpointUrl(identityRequest)) {
                String msg = "Mandatory configuration: Endpoint API is not configured for the Relying Party: " +
                        JWTInboundUtil.neutralize(this.relyingParty);
                log.error(msg, new JWTIdentityException(msg));
                return JWTInboundUtil.sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                        JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
            }

            // Validate JWS Algorithm.
            if (!validateJwsAlgorithm(identityRequest)) {
                String msg = "Invalid JWT Signing Algorithm configured for the Relying Party: " +
                        JWTInboundUtil.neutralize(this.relyingParty);
                log.error(msg, new JWTIdentityException(msg));
                return JWTInboundUtil.sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                        JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
            }

            // Validate API Key
            if (!validateApiKey(identityRequest)) {
                String msg = "Mandatory configuration: API Key is not configured for the Relying Party: " +
                        JWTInboundUtil.neutralize(this.relyingParty);
                log.error(msg, new JWTIdentityException(msg));
                return JWTInboundUtil.sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                        JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
            }

            // Set and Validate Redirect URL.
            if (!handleRedirectUrl(identityRequest)) {
                log.error("Invalid redirect URL: " + JWTInboundUtil.neutralize(this.redirectUrl) +
                        " in the authentication request from the relying party: " +
                        JWTInboundUtil.neutralize(this.relyingParty));
                return JWTInboundUtil.sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                        JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
            }

            // Set and Validate Error URL.
            if (!handleErrorUrl(identityRequest)) {
                log.error("Invalid error URL: " + JWTInboundUtil.neutralize(this.errorUrl) +
                        " in the authentication request from the relying party: " +
                        JWTInboundUtil.neutralize(this.relyingParty));
                return JWTInboundUtil
                        .sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                                JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
            }

            if (StringUtils.isNotBlank(logoutRequestPath) &&
                    identityRequest.getRequestURI().contains(logoutRequestPath)) {
                // Handle logout request.
                if (log.isDebugEnabled()) {
                    log.debug("Handling logout request.");
                }
                return buildResponseForFrameworkLogout(messageContext);
            } else if (StringUtils.isNotBlank(sessionId)) {
                // A session exists - response coming from the framework after authentication or after logged out.
                return handleFrameworkResponse(messageContext, identityRequest, respBuilder);
            } else {
                // No session exists - send the request to the identity framework.
                if (log.isDebugEnabled()) {
                    log.debug("Session not exists. Sending request to identity framework for authentication.");
                }
                return buildResponseForFrameworkLogin(messageContext);
            }
        } else {
            String msg = "A Service Provider with the Relying Party '" + JWTInboundUtil.neutralize(this.relyingParty) +
                    "' is not registered. Service Provider should be registered in advance.";
            log.error(msg, new JWTIdentityException(msg));
            return JWTInboundUtil.sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                    JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
        }
    }

    /**
     * Validates the endpoint URL.
     *
     * @param identityRequest The identity request.
     * @return True if the endpoint URL is configured
     */
    private boolean validateEndpointUrl(IdentityRequest identityRequest) {

        this.endpointUrl = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.SITE_API_URL);
        if (StringUtils.isNotBlank(this.endpointUrl)) {
            if (log.isDebugEnabled()) {
                log.debug("Setting the endpoint URL: " + JWTInboundUtil.neutralize(this.endpointUrl) + " for the " +
                        "Relying Party: " + JWTInboundUtil.neutralize(this.relyingParty));
            }
            return true;
        }
        return false;
    }

    /**
     * Validates the JWS algorithm.
     *
     * @param identityRequest The identity request.
     * @return True if the JWS algorithm configured is supported
     */
    private boolean validateJwsAlgorithm(IdentityRequest identityRequest) {

        setJWSAlgorithm(getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.JWS_ALGORITHM));
        if (this.jwsAlgorithm != null) {
            if (log.isDebugEnabled()) {
                log.debug("Setting the JWS Algorithm: " + JWTInboundUtil.neutralize(this.jwsAlgorithm.getName()) +
                        " for the Relying Party: " + JWTInboundUtil.neutralize(this.relyingParty));
            }
            return true;
        }
        return false;
    }

    /**
     * Validates the API key configuration
     *
     * @param identityRequest The identity response
     * @return True if the API key is configured
     */
    private boolean validateApiKey(IdentityRequest identityRequest) {

        this.apiKey = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.API_KEY);
        return StringUtils.isNotBlank(this.apiKey);
    }

    /**
     * Setting the redirect URL parameter and validating against the regex configured in the SP configuration.
     *
     * @param identityRequest The identity request.
     * @return True if the redirect URL is valid or not provided. False if the validation failed against the regex.
     */
    private boolean handleRedirectUrl(IdentityRequest identityRequest) {

        // Set Redirect URL.
        String redirectUrlParamName = JWTInboundConstants.SPDefaultValueConfigs.REDIRECT_URL_DEFAULT_PARAM_VALUE;
        if (StringUtils.isNotBlank(getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                REDIRECT_URL_PARAM_NAME))) {
            // Get the redirect URL parameter name from the SP config if it is configured.
            redirectUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                    REDIRECT_URL_PARAM_NAME);
        }
        this.redirectUrl = identityRequest.getParameter(redirectUrlParamName);
        if (log.isDebugEnabled()) {
            log.debug("Redirect URL parameter name: " + JWTInboundUtil.neutralize(redirectUrlParamName) +
                    "\nRedirect URL: " + JWTInboundUtil.neutralize(this.redirectUrl) + " for the Relying Party: " +
                    JWTInboundUtil.neutralize(this.relyingParty));
        }

        // Validate Redirect URL.
        String redirectUrlRegex =
                getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.REDIRECT_URL_REGEX);
        if (StringUtils.isNotBlank(this.redirectUrl)) {
            if (validateRegexInput(redirectUrlRegex, this.redirectUrl)) {
                if (log.isDebugEnabled()) {
                    log.debug("Setting the Redirect URL: " + JWTInboundUtil.neutralize(this.redirectUrl) +
                            " for the Relying Party: " + JWTInboundUtil.neutralize(this.relyingParty));
                }
                // Valid Redirect URL.
                return true;
            }
            // Invalid Redirect URL.
            return false;
        }
        // Redirect URL not provided.
        return true;
    }

    /**
     * Setting the error URL parameter and validating against the regex configured in the SP configuration.
     *
     * @param identityRequest The identity request.
     * @return True if the error URL is valid or not provided. False if the validation failed against the regex.
     */
    private boolean handleErrorUrl(IdentityRequest identityRequest) {

        // Set Error URL.
        String errorUrlParamName = JWTInboundConstants.SPDefaultValueConfigs.ERROR_URL_PARAM_DEFAULT_VALUE;
        if (StringUtils.isNotBlank(getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                ERROR_URL_PARAM_NAME))) {
            errorUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                    ERROR_URL_PARAM_NAME);
        }
        this.errorUrl = identityRequest.getParameter(errorUrlParamName);
        if (log.isDebugEnabled()) {
            log.debug(
                    "Error URL parameter name: " + JWTInboundUtil.neutralize(errorUrlParamName) + "\nError URL: " +
                            JWTInboundUtil.neutralize(this.errorUrl) + " for the Relying Party: " +
                            JWTInboundUtil.neutralize(this.relyingParty));
        }

        // Validate Error URL.
        String errorUrlRegex = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                ERROR_URL_REGEX);
        if (StringUtils.isNotBlank(this.errorUrl)) {
            if (validateRegexInput(errorUrlRegex, this.errorUrl)) {
                if (log.isDebugEnabled()) {
                    log.debug("Setting the Error URL: " + JWTInboundUtil.neutralize(this.errorUrl) +
                            " for the Relying Party: " + JWTInboundUtil.neutralize(this.relyingParty));
                }
                // Valid Error URL.
                return true;
            }
            // Invalid Error URL.
            return false;
        }
        // Error URL not provided.
        return true;
    }

    /**
     * Handles the response coming from the framework and decides on whether the response is an authenticated
     * response or the logout response.
     *
     * @param messageContext  The message context.
     * @param identityRequest The identity request.
     * @param respBuilder     The response builder.
     * @return The response builder after setting the required options based on the response type
     */
    private JWTInboundResponseBuilder handleFrameworkResponse(IdentityMessageContext messageContext,
                                                              IdentityRequest identityRequest,
                                                              JWTInboundResponseBuilder respBuilder) {

        AuthenticationResult authenticationResult = processResponseFromFrameworkLogin(messageContext,
                identityRequest);
        if (log.isDebugEnabled()) {
            log.debug("Session ID exists.");
        }
        if (authenticationResult != null && authenticationResult.isAuthenticated()) {
            // Authenticated session - response coming from the framework after authentication.
            respBuilder = handleAuthenticationResult(identityRequest, authenticationResult, respBuilder);
        } else {
            // Non-authenticated session - response coming after logged out - redirecting the user to Logout URL.
            respBuilder = handleLogoutResult(identityRequest, respBuilder);
        }
        return respBuilder;
    }

    /**
     * Handles the response coming from the framework after authentication.
     *
     * @param identityRequest      The identity request.
     * @param authenticationResult The authentication result.
     * @param respBuilder          The response builder.
     * @return The response builder after setting the required options.
     */
    private JWTInboundResponseBuilder handleAuthenticationResult(IdentityRequest identityRequest,
                                                                 AuthenticationResult authenticationResult,
                                                                 JWTInboundResponseBuilder respBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Authenticated session exists. Treating as a request coming after the " +
                    "authentication.");
        }
        String userName = authenticationResult.getSubject().getUserName();
        if (log.isDebugEnabled()) {
            log.debug("Processing the request for the user: " + JWTInboundUtil.neutralize(userName));
        }

        // Validate API key and Generate JWT Token.
        Map<ClaimMapping, String> userAttributes = authenticationResult.getSubject().getUserAttributes();
        try {
            respBuilder.setToken(generateJWTToken(identityRequest, this.apiKey, userName,
                    userAttributes));
        } catch (JWTIdentityException e) {
            String msg = "Error while generating JWT Token for the Relying Party: " +
                    JWTInboundUtil.neutralize(this.relyingParty);
            log.error(msg, e);
            return JWTInboundUtil
                    .sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                            JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
        }

        // Set endpoint URL.
        respBuilder.setEndpointUrl(this.endpointUrl);

        // Set query parameter value: Redirect URL - If provided.
        respBuilder.setRedirectUrl(this.redirectUrl);

        // Set query parameter value: Error URL - If provided.
        respBuilder.setErrorUrl(this.errorUrl);

        // Set query parameter names.
        String jwtParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                JWT_PARAM_NAME);
        String redirectUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                REDIRECT_URL_PARAM_NAME);
        String errorUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                ERROR_URL_PARAM_NAME);
        if (log.isDebugEnabled()) {
            log.debug(
                    "Setting the query parameter names for the Relying Party: " +
                            JWTInboundUtil.neutralize(this.relyingParty) +
                            ". Default query parameter names will be used if the values are not set." +
                            "\nJWT query parameter: " + JWTInboundUtil.neutralize(jwtParamName) +
                            "\nRedirect URL query parameter: " + JWTInboundUtil.neutralize(redirectUrlParamName) +
                            "\nError URL query parameter: " + JWTInboundUtil.neutralize(errorUrlParamName));
        }
        respBuilder.setJwtParamName(jwtParamName);
        respBuilder.setRedirectUrlParamName(redirectUrlParamName);
        respBuilder.setErrorUrlParamName(errorUrlParamName);

        return respBuilder;
    }

    /**
     * Handles the response coming after logged out.
     *
     * @param identityRequest The identity request.
     * @param respBuilder     The response builder.
     * @return The response builder after setting the required options.
     */
    private JWTInboundResponseBuilder handleLogoutResult(IdentityRequest identityRequest,
                                                         JWTInboundResponseBuilder respBuilder) {

        String logoutUrl = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.LOGOUT_URL);
        if (log.isDebugEnabled()) {
            log.debug(
                    "Non-authenticated session. Treating as the request coming after logout." +
                            "\nSetting the logout URL: " + JWTInboundUtil.neutralize(logoutUrl) +
                            " for the Relying Party: " + JWTInboundUtil.neutralize(this.relyingParty));
        }
        // Validate and set Logout URL.
        if (StringUtils.isNotBlank(logoutUrl)) {
            respBuilder.setToken(null);
            respBuilder.setLogoutUrl(logoutUrl);
        } else {
            String msg = "Mandatory configuration: Logout URL is not configured for the Relying Party: " +
                    JWTInboundUtil.neutralize(this.relyingParty);
            log.error(msg, new JWTIdentityException(msg));
            return JWTInboundUtil.sendToRetryPage(JWTInboundConstants.ErrorMessages.MISCONFIGURATION_STATUS,
                    JWTInboundConstants.ErrorMessages.MISCONFIGURATION_MESSAGE);
        }
        return respBuilder;
    }

    private String getPropertyValue(IdentityRequest request, String property) {

        String propertyValue = null;
        Map<String, Property> props = getInboundAuthenticatorPropertyArray(request.getTenantDomain());
        for (Object obj : props.entrySet()) {
            Map.Entry pair = (Map.Entry) obj;
            if (property.equals(pair.getKey())) {
                Property prop = (Property) pair.getValue();
                propertyValue = prop.getValue();
            }
        }
        return propertyValue;
    }

    /**
     * This method is used for retrieving the values for the properties from JWTInboundAuthConfig which will
     * have been set in the Identity Server's Service Provider settings.
     *
     * @param tenantDomain The tenant domain
     * @return a map of available properties and their values.
     */
    private Map<String, Property> getInboundAuthenticatorPropertyArray(String tenantDomain) {

        try {
            Map<String, Property> properties = new HashMap<>();
            if (StringUtils.isNotBlank(this.relyingParty) && StringUtils.isNotBlank(this.getName())) {
                ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
                ServiceProvider application =
                        appInfo.getServiceProviderByClientId(this.relyingParty, this.getName(), tenantDomain);
                for (InboundAuthenticationRequestConfig authenticationRequestConfig : application
                        .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                    if (StringUtils.equals(authenticationRequestConfig.getInboundAuthType(), getName())
                            && StringUtils.equals(authenticationRequestConfig.getInboundAuthKey(), this.relyingParty)) {
                        for (Property property : authenticationRequestConfig.getProperties()) {
                            properties.put(property.getName(), property);
                        }
                    }
                }
            }
            return properties;
        } catch (IdentityApplicationManagementException e) {
            throw new RuntimeException("Error while reading inbound authenticator properties for the Relying Party: " +
                    JWTInboundUtil.neutralize(this.relyingParty), e);
        }
    }

    /**
     * This method is used to validate if the provided relying party is exist as an SP.
     *
     * @param request The Identity Request.
     * @return true if relying party exist.
     */
    private boolean isRelyingPartyExist(IdentityRequest request) {

        ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
        try {
            if (StringUtils.isNotBlank(this.relyingParty)) {
                ServiceProvider application =
                        appInfo.getServiceProviderByClientId(this.relyingParty, this.getName(),
                                request.getTenantDomain());
                for (InboundAuthenticationRequestConfig authenticationRequestConfig : application
                        .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                    if (StringUtils.equals(authenticationRequestConfig.getInboundAuthType(), getName())
                            && StringUtils.equals(authenticationRequestConfig.getInboundAuthKey(), this.relyingParty)) {
                        return true;
                    }
                }
            }

            return false;
        } catch (IdentityApplicationManagementException e) {
            throw new RuntimeException("Error while validating the Relying Party: " +
                    JWTInboundUtil.neutralize(this.relyingParty), e);
        }
    }

    /**
     * This method is used to generate a signed JWT token.
     *
     * @param identityRequest the IdentityRequest.
     * @param userName        the username to define the subject of the JWT token.
     * @param userAttributes  the user claims to generate the JWT token.
     * @return the signed JWT token.
     */
    private String generateJWTToken(IdentityRequest identityRequest, String apiKey, String userName,
                                    Map<ClaimMapping, String> userAttributes) throws JWTIdentityException {

        try {
            long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

            // Generate JWT Claims.
            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
            if (log.isDebugEnabled()) {
                log.debug("Generating JWT token for subject: " + JWTInboundUtil.neutralize(userName));
            }
            claimsSet.subject(userName);
            claimsSet.jwtID(UUID.randomUUID().toString());

            Date date = new Date(currentTimeInMillis);
            String expSeconds = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.JWT_EXP_TIME);
            if (StringUtils.isBlank(expSeconds)) {
                expSeconds = JWTInboundConstants.SPDefaultValueConfigs.JWT_EXP_TIME_DEFAULT_VALUE;
            }
            claimsSet.issueTime(date);
            claimsSet.expirationTime(new Date(date.getTime() + (long) Integer.parseInt(expSeconds) * 1000));

            // Add user attributes to JWT.
            if (MapUtils.isNotEmpty(userAttributes)) {
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    if (IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR.equals(entry.getKey().getRemoteClaim()
                            .getClaimUri())) {
                        continue;
                    }
                    String remoteClaimUri = entry.getKey().getRemoteClaim().getClaimUri();
                    String localClaimUri = entry.getKey().getLocalClaim().getClaimUri();
                    String claimValue = entry.getValue();
                    claimsSet.claim(remoteClaimUri, claimValue);
                    if (log.isDebugEnabled()) {
                        log.debug("Adding user claim for local URI: " + JWTInboundUtil.neutralize(localClaimUri) +
                                " with remote URI: " + JWTInboundUtil.neutralize(remoteClaimUri) + " and the value: " +
                                JWTInboundUtil.neutralize(claimValue));
                    }
                }
            }

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(this.jwsAlgorithm), claimsSet.build());
            JWSSigner signer = new MACSigner(apiKey);
            signedJWT.sign(signer);

            String jwtToken = signedJWT.serialize();
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(JWTInboundConstants.IdentityTokens.JWT_TOKEN)) {
                log.debug("JWT token generated: " + JWTInboundUtil.neutralize(jwtToken));
            }
            return jwtToken;
        } catch (NumberFormatException e) {
            throw new JWTIdentityException("Error while reading the token expiry time configuration", e);
        } catch (KeyLengthException e) {
            throw new JWTIdentityException("Error while generating JWT token signer", e);
        } catch (JOSEException e) {
            throw new JWTIdentityException("Error while signing JWT token", e);
        }
    }

    /**
     * This method is used to validate a string against a regex.
     *
     * @param regex The regex.
     * @param input The string to be validated against the regex.
     * @return True if the validation is success.
     */
    public boolean validateRegexInput(String regex, String input) {

        if (StringUtils.isNotBlank(regex) && StringUtils.isNotBlank((input))) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Validating regex for the input: " + JWTInboundUtil.neutralize(input) + " against the regex: " +
                                JWTInboundUtil.neutralize(regex));
            }
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(input);
            if (matcher.matches()) {
                if (log.isDebugEnabled()) {
                    log.debug("Regex validation success.");
                }
                return true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Regex validation failed for the input: " + JWTInboundUtil.neutralize(input));
        }
        return false;
    }

    /**
     * The method used to get the JWS Algorithm.
     *
     * @param algorithm The algorithm.
     */
    private void setJWSAlgorithm(String algorithm) {

        if (log.isDebugEnabled()) {
            log.debug("Algorithm provided: " + JWTInboundUtil.neutralize(algorithm) + " for the Relying Party: " +
                    JWTInboundUtil.neutralize(this.relyingParty));
        }
        if (StringUtils.isBlank(algorithm) || algorithm.equals("HS256")) {
            // Set default value as HS256.
            this.jwsAlgorithm = JWSAlgorithm.HS256;
        } else if (algorithm.equals("HS384")) {
            this.jwsAlgorithm = JWSAlgorithm.HS384;
        } else if (algorithm.equals("HS512")) {
            this.jwsAlgorithm = JWSAlgorithm.HS512;
        } else {
            this.jwsAlgorithm = null;
        }
        if (log.isDebugEnabled()) {
            log.debug("Algorithm set to : " + JWTInboundUtil.neutralize(this.jwsAlgorithm.getName()) +
                    " for the Relying Party: " + JWTInboundUtil.neutralize(this.relyingParty));
        }
    }
}
