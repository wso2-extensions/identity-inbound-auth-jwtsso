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

package org.wso2.carbon.identity.sso.jwt.util;

import org.wso2.carbon.identity.application.common.model.InboundProvisioningConnector;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;

/**
 * This class is used for populating the GUI elements for the JWT SSO inbound authenticator in the Identity Server's
 * SP configuration
 *
 * This class is extensible either by implementing the AbstractInboundAuthenticatorConfig or extending the
 * JWTInboundAuthConfig. The customized class should be defined under
 * <JWTSSO><AuthConfig></AuthConfig></JWTSSO> in identity.xml. Otherwise JWTInboundAuthConfig will be
 * used as the default request processor.
 */
public class JWTInboundAuthConfig extends AbstractInboundAuthenticatorConfig
        implements InboundProvisioningConnector {

    private static final String NAME = "jwt-sso-inbound-auth";

    public JWTInboundAuthConfig() {

    }

    @Override
    public String getName() {

        return NAME;
    }

    @Override
    public String getConfigName() {

        return NAME;
    }

    @Override
    public String getFriendlyName() {
        // The human-readable name that gets printed in the SP config.
        return "JWT SSO Configuration";
    }

    @Override
    public String getRelyingPartyKey() {

        return JWTInboundConstants.SPBasedConfigs.RELYING_PARTY;
    }

    @Override
    public Property[] getConfigurationProperties() {

        Property relParty = new Property();
        relParty.setName(JWTInboundConstants.SPBasedConfigs.RELYING_PARTY);
        relParty.setDisplayName("Relying Party");
        relParty.setRequired(true);
        relParty.setDescription("The Relying Party ID to uniquely identify the service provider " +
                "which should be sent along with the login request.");
        relParty.setDisplayOrder(0);

        Property siteAPIUrl = new Property();
        siteAPIUrl.setName(JWTInboundConstants.SPBasedConfigs.SITE_API_URL);
        siteAPIUrl.setDisplayName("Endpoint API");
        siteAPIUrl.setDescription("Ex: https://sub.domain.com/api/sso/v2/sso");
        siteAPIUrl.setRequired(true);
        siteAPIUrl.setDisplayOrder(1);

        Property apiKey = new Property();
        apiKey.setName(JWTInboundConstants.SPBasedConfigs.API_KEY);
        apiKey.setDisplayName("API Key");
        apiKey.setRequired(true);
        apiKey.setConfidential(true);
        apiKey.setDescription("The API Key to sign the JWT token which can be found in the Relying Party " +
                "Configurations.");
        apiKey.setDisplayOrder(2);

        Property jwtExp = new Property();
        jwtExp.setName(JWTInboundConstants.SPBasedConfigs.JWT_EXP_TIME);
        jwtExp.setDisplayName("JWT Token Expiration Period");
        jwtExp.setDescription("Time in seconds to define the exp claim of JWT token from the token generated time " +
                "(Default value: 120).");
        jwtExp.setDisplayOrder(3);

        Property jwtAlgorithm = new Property();
        jwtAlgorithm.setName(JWTInboundConstants.SPBasedConfigs.JWS_ALGORITHM);
        jwtAlgorithm.setDisplayName("JWT Signing Algorithm");
        jwtAlgorithm.setDefaultValue("HS256");
        jwtAlgorithm.setDescription("Supported algorithms: HS256, HS384, HS512 (Default value: HS256).");
        jwtAlgorithm.setDisplayOrder(4);

        Property redirectUrl = new Property();
        redirectUrl.setName(JWTInboundConstants.SPBasedConfigs.REDIRECT_URL_REGEX);
        redirectUrl.setDisplayName("Redirect URL Regex");
        redirectUrl.setDisplayOrder(5);

        Property errorUrl = new Property();
        errorUrl.setName(JWTInboundConstants.SPBasedConfigs.ERROR_URL_REGEX);
        errorUrl.setDisplayName("Error URL Regex");
        errorUrl.setDisplayOrder(6);

        Property logoutUrl = new Property();
        logoutUrl.setName(JWTInboundConstants.SPBasedConfigs.LOGOUT_URL);
        logoutUrl.setDisplayName("Logout URL");
        logoutUrl.setRequired(true);
        logoutUrl.setDisplayOrder(7);

        Property jwtParamName = new Property();
        jwtParamName.setName(JWTInboundConstants.SPBasedConfigs.JWT_PARAM_NAME);
        jwtParamName.setDisplayName("JWT Parameter Name");
        jwtParamName.setDescription("Defines the URL query parameter name of the JWT token to be sent (Default " +
                "value: jwt).");
        jwtParamName.setDisplayOrder(8);

        Property redirectUrlParamName = new Property();
        redirectUrlParamName.setName(JWTInboundConstants.SPBasedConfigs.REDIRECT_URL_PARAM_NAME);
        redirectUrlParamName.setDisplayName("Redirect URL Parameter Name");
        redirectUrlParamName.setDescription("Defines the URL query parameter name of the Redirect URL - Applicable " +
                "only if the Redirect URL is provided in the SSO request (Default value: return_to).");
        redirectUrlParamName.setDisplayOrder(9);

        Property errorUrlParamName = new Property();
        errorUrlParamName.setName(JWTInboundConstants.SPBasedConfigs.ERROR_URL_PARAM_NAME);
        errorUrlParamName.setDisplayName("Error URL Parameter Name");
        errorUrlParamName.setDescription("Defines the URL query parameter name of the Error URL - Applicable only if " +
                "the Error URL is provided in the SSO request (Default value: error_url).");
        errorUrlParamName.setDisplayOrder(10);

        return new Property[]{relParty, siteAPIUrl, apiKey, jwtExp, jwtAlgorithm, redirectUrl, errorUrl, logoutUrl,
                jwtParamName, redirectUrlParamName, errorUrlParamName};
    }
}
