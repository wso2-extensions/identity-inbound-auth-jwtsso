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

package org.wso2.carbon.identity.sso.jwt.message;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;

import java.util.Map;

/**
 * Similar to the class for the JWT request, this class represents a subclass of IdentityResponse, which results from
 * the Identity Framework after the authentication steps(s).
 */
public class JWTInboundResponse extends IdentityResponse {

    private static final long serialVersionUID = -5259491409766665970L;
    private String endpointUrl;
    private String token;
    private String redirectUrl;
    private String errorUrl;
    private String logoutUrl;
    private String jwtParamName;
    private String redirectUrlParamName;
    private String errorUrlParamName;
    private Map<String, String> parameters;

    protected JWTInboundResponse(IdentityResponseBuilder builder) {

        super(builder);
        if (builder instanceof JWTInboundResponseBuilder) {
            this.endpointUrl = ((JWTInboundResponseBuilder) builder).endpointUrl;
            this.token = ((JWTInboundResponseBuilder) builder).token;
            this.redirectUrl = ((JWTInboundResponseBuilder) builder).redirectUrl;
            this.errorUrl = ((JWTInboundResponseBuilder) builder).errorUrl;
            this.logoutUrl = ((JWTInboundResponseBuilder) builder).logoutUrl;
            this.jwtParamName = ((JWTInboundResponseBuilder) builder).jwtParamName;
            this.redirectUrlParamName = ((JWTInboundResponseBuilder) builder).redirectUrlParamName;
            this.errorUrlParamName = ((JWTInboundResponseBuilder) builder).errorUrlParamName;
            this.parameters = ((JWTInboundResponseBuilder) builder).parameters;
        }
    }

    public String getEndpointUrl() {

        return endpointUrl;
    }

    public String getToken() {

        return token;
    }

    public String getRedirectUrl() {

        return redirectUrl;
    }

    public String getErrorUrl() {

        return errorUrl;
    }

    public String getLogoutUrl() {

        return logoutUrl;
    }

    public String getJwtParamName() {

        if (StringUtils.isNotBlank(jwtParamName)) {
            return jwtParamName;
        } else {
            return JWTInboundConstants.SPDefaultValueConfigs.JWT_PARAM_DEFAULT_VALUE;
        }
    }

    public String getRedirectUrlParamName() {

        if (StringUtils.isNotBlank(redirectUrlParamName)) {
            return redirectUrlParamName;
        } else {
            return JWTInboundConstants.SPDefaultValueConfigs.REDIRECT_URL_DEFAULT_PARAM_VALUE;
        }
    }

    public String getErrorUrlParamName() {

        if (StringUtils.isNotBlank(errorUrlParamName)) {
            return errorUrlParamName;
        } else {
            return JWTInboundConstants.SPDefaultValueConfigs.ERROR_URL_PARAM_DEFAULT_VALUE;
        }
    }

    public Map<String, String> getParameters() {

        return parameters;
    }

    /**
     * Here also, the builder class for the IdentityResponse subclass can be found within the class itself.
     * Here, the parameters found in the HTTP response can be picked up and set to the response object as per the need.
     */
    public static class JWTInboundResponseBuilder extends IdentityResponseBuilder {

        private String endpointUrl;
        private String token;
        private String redirectUrl;
        private String errorUrl;
        private String logoutUrl;
        private String jwtParamName;
        private String redirectUrlParamName;
        private String errorUrlParamName;
        private Map<String, String> parameters;

        public JWTInboundResponseBuilder(IdentityMessageContext context) {

            super(context);
        }

        public JWTInboundResponseBuilder() {

            super();
        }

        public void setEndpointUrl(String endpointUrl) {

            this.endpointUrl = endpointUrl;
        }

        public void setToken(String token) {

            this.token = token;
        }

        public void setRedirectUrl(String redirectUrl) {

            this.redirectUrl = redirectUrl;
        }

        public void setErrorUrl(String errorUrl) {

            this.errorUrl = errorUrl;
        }

        public void setLogoutUrl(String logoutUrl) {

            this.logoutUrl = logoutUrl;
        }

        public void setJwtParamName(String jwtParamName) {

            this.jwtParamName = jwtParamName;
        }

        public void setRedirectUrlParamName(String redirectUrlParamName) {

            this.redirectUrlParamName = redirectUrlParamName;
        }

        public void setErrorUrlParamName(String errorUrlParamName) {

            this.errorUrlParamName = errorUrlParamName;
        }

        public JWTInboundResponse build() {

            return new JWTInboundResponse(this);
        }

        public void setParameters(Map<String, String> parameters) {

            this.parameters = parameters;
        }
    }
}
