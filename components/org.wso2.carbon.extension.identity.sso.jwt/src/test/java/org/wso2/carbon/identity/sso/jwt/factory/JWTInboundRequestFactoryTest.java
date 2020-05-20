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
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

public class JWTInboundRequestFactoryTest {

    private JWTInboundRequestFactory jwtInboundRequestFactory;
    private HttpServletRequest request;
    private HttpServletResponse response;

    @BeforeMethod
    public void setUp() {

        jwtInboundRequestFactory = new JWTInboundRequestFactory();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
    }

    @DataProvider(name = "getHandleStatus")
    public Object[][] getStatus() {

        return new Object[][]{
                {null, false},
                {"http://localhost:9443/identity/", false},
                {"http://localhost:9443/identity" + JWTInboundConstants.BASE_PATH, true},
                {"http://localhost:9443/identity" + JWTInboundConstants.BASE_PATH + "/dummy", true}
        };
    }

    @Test(dataProvider = "getHandleStatus")
    public void testCanHandle(String requestURI, boolean expected) {

        when(request.getRequestURI()).thenReturn(requestURI);
        boolean canHandle = jwtInboundRequestFactory.canHandle(request, response);
        assertEquals(canHandle, expected);
    }
}
