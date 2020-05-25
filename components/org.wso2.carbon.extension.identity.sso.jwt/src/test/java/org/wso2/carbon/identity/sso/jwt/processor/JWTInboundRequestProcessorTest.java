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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundRequest;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.testng.Assert.assertEquals;

/**
 * Test class for the JWTInboundRequestProcessor
 */
public class JWTInboundRequestProcessorTest {

    private JWTInboundRequestProcessor jwtInboundRequestProcessor;
    private HttpServletRequest request;
    private HttpServletResponse response;

    @BeforeMethod
    public void setUp() {

        AbstractInboundAuthenticatorConfig jwtInboundAuthConfig = mock(AbstractInboundAuthenticatorConfig.class);
        jwtInboundRequestProcessor = new JWTInboundRequestProcessor(jwtInboundAuthConfig);

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
    }

    @DataProvider(name = "getHandleStatus")
    public Object[][] getStatus() throws FrameworkClientException {

        JWTInboundRequest jwtInboundRequest1 =
                (JWTInboundRequest) new JWTInboundRequest.JWTInboundRequestBuilder(request, response)
                        .setParameters(new HashMap<String, String[]>() {
                            {
                                put(JWTInboundConstants.SP_ID, new String[]{"testSP"});
                            }
                        }).build();
        JWTInboundRequest jwtInboundRequest2 =
                new JWTInboundRequest.JWTInboundRequestBuilder(request, response).build();

        return new Object[][]{
                {null, false},
                {jwtInboundRequest1, true},
                {jwtInboundRequest2, false}
        };
    }

    @Test(dataProvider = "getHandleStatus")
    public void testCanHandle(IdentityRequest identityRequest, boolean expected)
            throws Exception {

        boolean canHandle = jwtInboundRequestProcessor.canHandle(identityRequest);
        assertEquals(canHandle, expected);
    }

    @DataProvider(name = "BuildRegexInput")
    public Object[][] buildRegexInput() {

        return new Object[][]{
                {"http://localhost", "http://localhost", true},
                {"(http://localhost|http://example.com)", "http://example.com", true},
                {"http://localhost/.*", "http://localhost/error", true},
                {"http://localhost", "http://test.com", false},
                {"(http://localhost|http://example.com)", "http://example1.com", false},
                {"http://localhost/.*", "http://localhost", false}
        };
    }

    @Test(dataProvider = "BuildRegexInput")
    public void testValidateRegexInput(String regex, String input, boolean response) {

        assertEquals(jwtInboundRequestProcessor.validateRegexInput(regex, input), response);
    }
}
