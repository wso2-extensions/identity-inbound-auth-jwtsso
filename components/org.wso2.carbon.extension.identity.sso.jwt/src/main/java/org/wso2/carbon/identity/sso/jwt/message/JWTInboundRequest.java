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

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class represents a subclass IdentityRequest, which can be used to inject additional properties and parameters
 * from the HTTP request coming from the servlet to the IdentityRequest bound for the authentication framework.
 */
public class JWTInboundRequest extends IdentityRequest {

    private static final long serialVersionUID = 7511153346178366267L;

    protected JWTInboundRequest(IdentityRequestBuilder builder) throws FrameworkClientException {

        super(builder);
    }

    /**
     * The builder for the request class is maintained here as a subclass. The builder is required because once it
     * is built, the IdentityRequest object is treated as immutable within the framework and cannot be used for adding
     * additional properties from the HTTP request.
     */
    public static class JWTInboundRequestBuilder extends IdentityRequestBuilder {

        public JWTInboundRequestBuilder(HttpServletRequest request, HttpServletResponse response) {

            super(request, response);
        }

        @Override
        public JWTInboundRequest build() throws FrameworkClientException {

            return new JWTInboundRequest(this);
        }
    }
}
