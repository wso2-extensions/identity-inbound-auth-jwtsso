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

/**
 * Class for maintaining the constant definitions.
 */
public class JWTInboundConstants {

    public static final String SP_ID = "jwtRP";
    public static final String LOGOUT_PATH = "/logout";
    public static final String BASE_PATH = "/jwtsso";
    public static final String FRIENDLY_NAME = "JWT SSO Configuration";

    /**
     * Defines the SP configuration elements.
     */
    public static class SPBasedConfigs {

        public static final String RELYING_PARTY = "RelyingParty";
        public static final String SITE_API_URL = "SiteAPIURL";
        public static final String API_KEY = "APIKey";
        public static final String JWT_EXP_TIME = "JWTExpiryTime";
        public static final String JWS_ALGORITHM = "JWTAlgorithm";
        public static final String REDIRECT_URL_REGEX = "ReturnToURLRegex";
        public static final String ERROR_URL_REGEX = "ErrorURLRegex";
        public static final String LOGOUT_URL = "LogoutURL";
        public static final String JWT_PARAM_NAME = "JWTParamName";
        public static final String REDIRECT_URL_PARAM_NAME = "ReturnURLParamName";
        public static final String ERROR_URL_PARAM_NAME = "ErrorURLParamName";
    }

    /**
     * Defines the default values for the SP configurations.
     */
    public static class SPDefaultValueConfigs {

        public static final String JWT_PARAM_DEFAULT_VALUE = "jwt";
        public static final String REDIRECT_URL_DEFAULT_PARAM_VALUE = "return_to";
        public static final String ERROR_URL_PARAM_DEFAULT_VALUE = "error_url";
        public static final String JWT_EXP_TIME_DEFAULT_VALUE = "120";
    }

    /**
     * Defines name of the Token loggable configuration in identity_log_tokens.properties.
     */
    public static class IdentityTokens {

        public static final String JWT_TOKEN = "JWT_Token";
    }

    /**
     * Defines the error messages defined in Resources.properties file of the authentication endpoint.
     */
    public static class ErrorMessages {

        public static final String MISCONFIGURATION_STATUS = "misconfiguration.error";
        public static final String MISCONFIGURATION_MESSAGE = "something.went.wrong.contact.admin";
        public static final String ERROR_STATUS = "status";
        public static final String ERROR_MESSAGE = "statusMsg";
    }
}
