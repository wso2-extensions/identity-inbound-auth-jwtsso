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
