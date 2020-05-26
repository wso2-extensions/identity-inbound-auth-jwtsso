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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse.HttpIdentityResponseBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse.JWTInboundResponseBuilder;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.testng.Assert.assertEquals;

/**
 * Test class for the JWTInboundIdentityResponseFactory
 */
public class JWTInboundIdentityResponseFactoryTest {

    private JWTInboundIdentityResponseFactory jwtInboundIdentityResponseFactory;

    @BeforeMethod
    public void setUp() {

        jwtInboundIdentityResponseFactory = new JWTInboundIdentityResponseFactory();
    }

    @DataProvider(name = "getHandleStatus")
    public Object[][] getStatus() {

        IdentityMessageContext identityMessageContext = mock(IdentityMessageContext.class);
        IdentityResponse jwtInboundResponse1 = new IdentityResponse.IdentityResponseBuilder().build();
        JWTInboundResponseBuilder jwtInboundResponse2 = new JWTInboundResponseBuilder(identityMessageContext);
        return new Object[][]{
                {null, false},
                {jwtInboundResponse1, false},
                {jwtInboundResponse2.build(), true}
        };
    }

    @Test(dataProvider = "getHandleStatus")
    public void testCanHandle(IdentityResponse identityResponse, boolean expected) {

        boolean canHandle = jwtInboundIdentityResponseFactory.canHandle(identityResponse);
        assertEquals(canHandle, expected);
    }

    @DataProvider(name = "BuildResponseBuilderData")
    public Object[][] buildResponseBuilderData() {

        return new Object[][]{
                {null, "http://localhost/logout", null, "http://localhost/logout"},
                {null, null, null, ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL()},
                {"dummyToken", null, "http://localhost/endpointUrl", "http://localhost/endpointUrl"}
        };
    }

    @Test(dataProvider = "BuildResponseBuilderData")
    public void testCreate(String jwtToken, String logoutUrl, String endpointUrl, String expected) {

        IdentityMessageContext identityMessageContext = mock(IdentityMessageContext.class);
        JWTInboundResponseBuilder inboundResponse = new JWTInboundResponseBuilder(identityMessageContext);
        inboundResponse.setToken(jwtToken);
        inboundResponse.setLogoutUrl(logoutUrl);
        inboundResponse.setEndpointUrl(endpointUrl);
        HttpIdentityResponseBuilder builder = jwtInboundIdentityResponseFactory.create(inboundResponse.build());
        assertEquals(builder.build().getRedirectURL(), expected);
    }
}
