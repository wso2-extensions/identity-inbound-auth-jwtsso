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
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
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
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundRequest;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundUtil;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
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

    public JWTInboundRequestProcessor(AbstractInboundAuthenticatorConfig jwtInboundAuthConfig) {

        this.jwtInboundAuthConfig = jwtInboundAuthConfig;
    }

    /**
     * This method represents the bulk of the functionality, where the developer chooses what should take place when
     * the authentication request reaches the processor. In this instance, a check is done first to determine if the
     * request is coming new from the /identity servlet.
     *
     * @param identityRequest the request object (or a subclass of it), which can be coming either from the /identity
     *                        servlet or from the framework after authentication)
     * @return an instance of IdentityResponse which may be further customised (similar to how an IdentityRequest can
     * be customised)
     * @throws FrameworkException if any abnormal conditions are encountered by the framework during authentication.
     */
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        IdentityMessageContext messageContext = new IdentityMessageContext<>(identityRequest,
                new HashMap<String, String>());
        JWTInboundResponse.JWTInboundResponseBuilder respBuilder =
                new JWTInboundResponse.JWTInboundResponseBuilder(messageContext);

        String sessionId = identityRequest.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
        String logoutRequestPath = JWTInboundConstants.BASE_PATH + JWTInboundConstants.LOGOUT_PATH;

        if (isRelyingPartyExist(identityRequest)) {

            if (StringUtils.isNotBlank(logoutRequestPath) &&
                    identityRequest.getRequestURI().contains(logoutRequestPath)) {
                // Handle logout request.
                if (log.isDebugEnabled()) {
                    log.debug("Handling logout request.");
                }
                return buildResponseForFrameworkLogout(messageContext);
            } else if (sessionId != null) {
                // A session already exists, which means that this is call is coming from the framework
                // after authentication or after logged out.
                AuthenticationResult authenticationResult = processResponseFromFrameworkLogin(messageContext,
                        identityRequest);
                if (log.isDebugEnabled()) {
                    log.debug("Session ID exists.");
                }
                if (authenticationResult != null && authenticationResult.isAuthenticated()) {
                    // An authenticated session exists, which means this call is coming from framework
                    // after authentication.
                    if (log.isDebugEnabled()) {
                        log.debug("Authenticated session exists. Treating as a request coming after the " +
                                "authentication.");
                    }
                    String userName = authenticationResult.getSubject().getUserName();
                    if (log.isDebugEnabled()) {
                        log.debug("Processing the request for the user: " + neutralize(userName));
                    }
                    Map<ClaimMapping, String> userAttributes = authenticationResult.getSubject().getUserAttributes();
                    respBuilder.setToken(generateJWTToken(identityRequest, userName, userAttributes));

                    // Set query parameter value: JWT query param - mandatory (From SP config).
                    String endpointUrl =
                            getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.SITE_API_URL);
                    if (log.isDebugEnabled()) {
                        log.debug("Setting the endpoint URL: " + neutralize(endpointUrl));
                    }
                    respBuilder.setEndpointUrl(endpointUrl);

                    // Set query parameter value: Redirect URL - If provided.
                    String redirectUrlRegex = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                            REDIRECT_URL_REGEX);
                    if (StringUtils.isNotBlank(this.redirectUrl)) {
                        if (validateRegexInput(redirectUrlRegex, this.redirectUrl)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Setting the Redirect URL: " + neutralize(this.redirectUrl));
                            }
                            respBuilder.setRedirectUrl(this.redirectUrl);
                        } else {
                            log.error("Invalid redirect URL: " + neutralize(this.redirectUrl) +
                                    " in the authentication request from the relying party: " +
                                    neutralize(this.relyingParty));
                            return JWTInboundUtil.sendToRetryPage();
                        }
                    }

                    // Set query parameter value: Error URL - If provided.
                    String errorUrlRegex = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                            ERROR_URL_REGEX);
                    if (StringUtils.isNotBlank(this.errorUrl)) {
                        if (validateRegexInput(errorUrlRegex, this.errorUrl)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Setting the Error URL: " + neutralize(this.errorUrl));
                            }
                            respBuilder.setErrorUrl(this.errorUrl);
                        } else {
                            log.error("Invalid error URL: " + neutralize(this.errorUrl) +
                                    " in the authentication request from the relying party: " +
                                    neutralize(this.relyingParty));
                            return JWTInboundUtil.sendToRetryPage();
                        }
                    }

                    // Set query parameter names.
                    String jwtParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                            JWT_PARAM_NAME);
                    String redirectUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                            REDIRECT_URL_PARAM_NAME);
                    String errorUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                            ERROR_URL_PARAM_NAME);
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "Setting the query parameter names.\nJWT query parameter: " + neutralize(jwtParamName) +
                                        "\nRedirect URL query parameter: " + neutralize(redirectUrlParamName) +
                                        "\nError URL query parameter: " + neutralize(errorUrlParamName));
                    }
                    respBuilder.setJwtParamName(jwtParamName);
                    respBuilder.setRedirectUrlParamName(redirectUrlParamName);
                    respBuilder.setErrorUrlParamName(errorUrlParamName);

                } else {
                    // Non-authenticated scenario, hence considering this request as coming after logged out
                    // Therefore redirecting the user to Logout URL of SP (Relying Party).
                    String logoutUrl = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.LOGOUT_URL);
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "Non-authenticated session. Treating as the request coming after logout.\n" +
                                        "Setting the logout URL: " + neutralize(logoutUrl));
                    }
                    respBuilder.setToken(null);
                    respBuilder.setLogoutUrl(logoutUrl);
                }
                return respBuilder;
            } else {
                // No session exists, so we will need to send the request through to the identity framework.
                if (log.isDebugEnabled()) {
                    log.debug("Session not exists. Sending request to identity framework for authentication.");
                }
                return buildResponseForFrameworkLogin(messageContext);

            }
        } else {
            log.error(
                    "A Service Provider with the Relying Party '" + neutralize(this.relyingParty) + "'" +
                            " is not registered. Service Provider should be registered in advance.");
            return JWTInboundUtil.sendToRetryPage();
        }
    }

    @Override
    public String getCallbackPath(IdentityMessageContext identityMessageContext) {

        return IdentityUtil.getServerURL("identity", false, false);
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
                log.debug("Relying party: " + neutralize(this.relyingParty));
            }

            String redirectUrlParamName = JWTInboundConstants.SPDefaultValueConfigs.REDIRECT_URL_DEFAULT_PARAM_VALUE;
            if (StringUtils.isNotBlank(getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                    REDIRECT_URL_PARAM_NAME))) {
                redirectUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                        REDIRECT_URL_PARAM_NAME);
            }
            this.redirectUrl = identityRequest.getParameter(redirectUrlParamName);
            if (log.isDebugEnabled()) {
                log.debug("Redirect URL parameter name: " + neutralize(redirectUrlParamName) +
                        "\nRedirect URL: " + neutralize(this.redirectUrl));
            }

            String errorUrlParamName = JWTInboundConstants.SPDefaultValueConfigs.ERROR_URL_PARAM_DEFAULT_VALUE;
            if (StringUtils.isNotBlank(getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                    ERROR_URL_PARAM_NAME))) {
                errorUrlParamName = getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.
                        ERROR_URL_PARAM_NAME);
            }
            this.errorUrl = identityRequest.getParameter(errorUrlParamName);
            if (log.isDebugEnabled()) {
                log.debug(
                        "Error URL parameter name: " + neutralize(errorUrlParamName) + "\nError URL: " +
                                neutralize(this.errorUrl));
            }
        }
        return StringUtils.isNotBlank(this.relyingParty);
    }

    @Override
    public String getName() {

        return jwtInboundAuthConfig.getName();
    }

    private String getPropertyValue(IdentityRequest request, String property) {

        String propertyValue = null;
        Map<String, Property> props = getInboundAuthenticatorPropertyArray(request);
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
     * @param request the identity request object
     * @return a map of available properties and their values
     */
    private Map<String, Property> getInboundAuthenticatorPropertyArray(IdentityRequest request) {

        try {
            Map<String, Property> properties = new HashMap<>();
            if (StringUtils.isNotBlank(this.relyingParty) && StringUtils.isNotBlank(this.getName())) {
                ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
                ServiceProvider application =
                        appInfo.getServiceProviderByClientId(this.relyingParty, this.getName(),
                                request.getTenantDomain());
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
            throw new RuntimeException("Error while reading inbound authenticator properties", e);
        }
    }

    /**
     * This method is used to validate if the provided relying party is exist as an SP.
     *
     * @param request
     * @return true if relying party exist
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
            throw new RuntimeException("Error while reading inbound authenticator properties", e);
        }
    }

    /**
     * This method is used to generate a signed JWT token
     *
     * @param identityRequest the IdentityRequest
     * @param userName        the username to define the subject of the JWT token
     * @param userAttributes  the user claims to generate the JWT token
     * @return the signed JWT token
     */
    private String generateJWTToken(IdentityRequest identityRequest, String userName,
                                    Map<ClaimMapping, String> userAttributes) {

        try {
            long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();

            // Generate JWT Claims.
            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
            if (log.isDebugEnabled()) {
                log.debug("Generating JWT token for subject: " + neutralize(userName));
            }
            claimsSet.subject(userName);

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
                        log.debug("Adding user claim for local URI: " + neutralize(localClaimUri) +
                                " with remote URI: " + neutralize(remoteClaimUri) + " and the value: " +
                                neutralize(claimValue));
                    }
                }
            }

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.build());
            JWSSigner signer =
                    new MACSigner(getPropertyValue(identityRequest, JWTInboundConstants.SPBasedConfigs.API_KEY));
            signedJWT.sign(signer);

            String jwtToken = signedJWT.serialize();
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(JWTInboundConstants.IdentityTokens.JWT_TOKEN)) {
                log.debug("JWT token generated: " + neutralize(jwtToken));
            }
            return jwtToken;
        } catch (KeyLengthException e) {
            throw new RuntimeException("Error while generating JWT token signer", e);
        } catch (JOSEException e) {
            throw new RuntimeException("Error while signing JWT token", e);
        }
    }

    /**
     * This method is used to validate a string against a regex
     *
     * @param regex
     * @param input
     * @return A boolean value
     */
    public boolean validateRegexInput(String regex, String input) {

        if (StringUtils.isNotBlank(regex) && StringUtils.isNotBlank((input))) {
            if (log.isDebugEnabled()) {
                log.debug("Validating regex for the input: " + neutralize(input) + " against the regex: " +
                        neutralize(regex));
            }
            Pattern p = Pattern.compile(regex);
            Matcher m = p.matcher(input);
            if (m.matches()) {
                if (log.isDebugEnabled()) {
                    log.debug("Regex validation success.");
                }
                return true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Regex validation failed.");
        }
        return false;
    }

    /**
     * The method used to prevent CRLF_INJECTION_LOGS. It neutralizes the given input.
     *
     * @param input The input string to be neutralized.
     * @return      neutralized output.
     */
    private String neutralize(String input) {

        if (StringUtils.isNotBlank(input)) {
            return input.replaceAll("[\r\n]", "");
        }
        return null;
    }
}
