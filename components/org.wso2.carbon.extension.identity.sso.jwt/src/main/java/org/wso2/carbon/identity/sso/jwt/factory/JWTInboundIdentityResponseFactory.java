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
package org.wso2.carbon.identity.sso.jwt.factory;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundUtil;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

/**
 * This class represents a factory for JWT IdentityResponse instances which will result from the framework,
 * after the authentication step.
 *
 * This class is extensible either by implementing the HttpIdentityResponseFactory or extending the
 * JWTInboundIdentityResponseFactory. The customized class should be defined under
 * <JWTSSO><ResponseFactory></ResponseFactory></JWTSSO> in identity.xml. Otherwise JWTInboundIdentityResponseFactory
 * will be used as the default request processor.
 */
public class JWTInboundIdentityResponseFactory extends HttpIdentityResponseFactory {

    private static Log log = LogFactory.getLog(JWTInboundIdentityResponseFactory.class);

    public String getName() {

        return "JWTSSOInboundIdentityResponseFactory";
    }

    /**
     * Checks if an incoming IdentityResponse from the framework can be handled by this particular factory.
     *
     * @param identityResponse incoming IdentityResponse from the identity framework
     * @return true if the incoming response is of the type handled by this factory
     */
    @Override
    public boolean canHandle(IdentityResponse identityResponse) {

        return identityResponse instanceof JWTInboundResponse;
    }

    /**
     * Converts the received IdentityResponse instance to an HTTPResponse so that it could be sent to the calling party.
     * This is where the logic for picking up and setting any parameters/headers/cookies etc is written.
     *
     * @param identityResponse The IdentityResponse instance
     * @return a corresponding HTTPResponse in the form of a builder, so that it could be built on demand
     */
    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder
                = new HttpIdentityResponse.HttpIdentityResponseBuilder();

        if (identityResponse instanceof JWTInboundResponse) {
            JWTInboundResponse inboundResponse = (JWTInboundResponse) identityResponse;

            String jwtToken = inboundResponse.getToken();
            String logoutUrl = inboundResponse.getLogoutUrl();
            if (isLogoutResponse(jwtToken)) {
                // Successful logout scenario.
                if (isValidLogoutResponse(logoutUrl)) {
                    // Successful logout and the Logout URL is configured, hence redirecting to Logout URL.
                    // Token not set and the logout URL is configured.
                    if (log.isDebugEnabled()) {
                        log.debug("Logout URL: " + JWTInboundUtil.neutralize(logoutUrl) +
                                " provided and the token is set" +
                                " to empty. Hence considering as successful logout scenario.");
                    }
                    builder.setStatusCode(HttpServletResponse.SC_FOUND);
                    // Redirect to Logout URL.
                    builder.setRedirectURL(logoutUrl);
                } else {
                    // Successful logout but the Logout URL is not configured, hence redirecting to error page.
                    // The token is not set and the logout URL is not configured.
                    String clientErrorPage = inboundResponse.getEndpointUrl();
                    if (StringUtils.isNotBlank(clientErrorPage)) {
                        builder.setStatusCode(HttpServletResponse.SC_FOUND);
                        builder.setRedirectURL(clientErrorPage);

                        Map<String, String[]> parameters = new HashMap<>();
                        if (inboundResponse.getParameters() != null) {
                            for (Map.Entry<String, String> entry : inboundResponse.getParameters().entrySet()) {
                                parameters.put(entry.getKey(), new String[]{entry.getValue()});
                            }
                            builder.setParameters(parameters);
                        }
                    } else {
                        // This else part will not be reached in the usual flow unless anyone bypassed the flow.
                        // This will be reached if the token is set to null, logout URL is not configured and the
                        // client error page is not defined. But anyway, if the token is not set and the logout URL
                        // is not defined, the client error page will be defined in the handleLogoutResult() method in
                        // the JWTInboundRequestProcessor class and the defined error page will be returned through
                        // above if scope.
                        builder.setStatusCode(HttpServletResponse.SC_BAD_REQUEST);
                    }
                }
            } else {
                // Successful authenticated scenario.
                if (log.isDebugEnabled()) {
                    log.debug("Successful authenticated scenario. Building the response to redirect.");
                }
                builder.setStatusCode(HttpServletResponse.SC_FOUND);
                String jwtParamName = inboundResponse.getJwtParamName();
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(JWTInboundConstants.IdentityTokens.JWT_TOKEN)) {
                    log.debug(
                            "Adding JWT parameter: '" + JWTInboundUtil.neutralize(jwtParamName) + "' with the value: " +
                                    JWTInboundUtil.neutralize(jwtToken));
                }
                builder.addParameter(jwtParamName, jwtToken);

                String redirectUrlParamName = inboundResponse.getRedirectUrlParamName();
                String redirectUrl = inboundResponse.getRedirectUrl();
                if (log.isDebugEnabled()) {
                    log.debug("Redirect URL parameter: " + JWTInboundUtil.neutralize(redirectUrlParamName) +
                            " with the value: " + JWTInboundUtil.neutralize(redirectUrl));
                }
                if (StringUtils.isNotBlank(redirectUrl)) {
                    // Add redirect URL parameter if provided.
                    builder.addParameter(redirectUrlParamName, redirectUrl);
                }

                String errorUrlParamName = inboundResponse.getErrorUrlParamName();
                String errorUrl = inboundResponse.getErrorUrl();
                if (log.isDebugEnabled()) {
                    log.debug("Error URL parameter: " + JWTInboundUtil.neutralize(errorUrlParamName) +
                            " with the value: " + JWTInboundUtil.neutralize(errorUrl));
                }
                if (StringUtils.isNotBlank(errorUrl)) {
                    // Add error URL parameter if provided.
                    builder.addParameter(errorUrlParamName, errorUrl);
                }
                // Redirect to API endpoint.
                String endpointUrl = inboundResponse.getEndpointUrl();
                if (log.isDebugEnabled()) {
                    log.debug("Defining the Endpoint URL: " + JWTInboundUtil.neutralize(endpointUrl) +
                            " as the redirection endpoint.");
                }
                builder.setRedirectURL(endpointUrl);
            }
        }
        return builder;
    }

    /**
     * Check if the response received is a logout response.
     *
     * @param jwtToken The JWT token
     * @return
     */
    private boolean isLogoutResponse(String jwtToken) {

        // Consider as logout response if the token is set to empty.
        if (StringUtils.isBlank(jwtToken)) {
            return true;
        }
        return false;
    }

    /**
     * Check if the logout response received can be completed by ensuring if the Logout URL is configured.
     *
     * @param logoutUrl The logout URL to redirect to.
     * @return
     */
    private boolean isValidLogoutResponse(String logoutUrl) {

        // Check if the Logout URL is configured in the SP configuration
        if (StringUtils.isNotBlank(logoutUrl)) {
            return true;
        }
        return false;
    }

    @Override
    public void create(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        this.create(identityResponse);
    }
}
