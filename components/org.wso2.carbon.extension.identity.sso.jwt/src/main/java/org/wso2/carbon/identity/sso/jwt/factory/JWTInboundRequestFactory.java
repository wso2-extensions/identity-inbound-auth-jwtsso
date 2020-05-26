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
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundRequest;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class represents a factory for JWT IdentityRequest instances which will be passed to the framework for
 * authentication.
 *
 * Essentially, the conversion of the protocol-specific HTTP request to the framework-understood IdentityRequest takes
 * place here.
 *
 * This class is extensible either by implementing the HttpIdentityRequestFactory or extending the
 * JWTInboundRequestFactory. The customized class should be defined under
 * <JWTSSO><RequestFactory></RequestFactory></JWTSSO> in identity.xml. Otherwise JWTInboundRequestFactory will be
 * used as the default request processor.
 */
public class JWTInboundRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(JWTInboundRequestFactory.class);

    /**
     * Checks whether or not an incoming request hitting the "/identity" servlet should be handled by this
     * particular JWT IdentityRequest factory.
     *
     * @param request  the request parameter coming from the servlet.
     * @param response the response parameter coming from the servlet.
     * @return true if the request is of a type which can be handled by this particular IdentityRequest factory.
     */
    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        // Return true if the incoming request to the identity servlet in the form of : "/identity/BASE_PATH".
        String requestUri = request.getRequestURI();
        if (log.isDebugEnabled()) {
            log.debug("Request URI: " + JWTInboundUtil.neutralize(requestUri));
        }
        if (StringUtils.isNotBlank(requestUri) && requestUri.contains(JWTInboundConstants.BASE_PATH)) {
            if (log.isDebugEnabled()) {
                log.debug("Request URI contains the base path: " + JWTInboundConstants.BASE_PATH +
                        "\nHandling authentication request through JWT Inbound Authenticator.");
            }
            return true;
        }
        return false;
    }

    /**
     * Returns a new instance of the JWT IdentityRequest object, which will then be passed to the processor.
     *
     * @param request  the HTTP request from the servlet.
     * @param response the response parameter coming from the servlet.
     * @return a builder for JWTInboundRequest, which is a subclass of JWTInboundRequest.
     * @throws FrameworkClientException
     */
    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws FrameworkClientException {

        JWTInboundRequest.JWTInboundRequestBuilder builder;
        builder = new JWTInboundRequest.JWTInboundRequestBuilder(request, response);
        super.create(builder, request, response);
        return builder;
    }
}

