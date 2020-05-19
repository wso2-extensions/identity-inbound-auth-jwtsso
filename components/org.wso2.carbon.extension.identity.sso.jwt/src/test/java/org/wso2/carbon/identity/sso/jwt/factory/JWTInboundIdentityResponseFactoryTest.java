package org.wso2.carbon.identity.sso.jwt.factory;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.testng.Assert.assertEquals;

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
        JWTInboundResponse jwtInboundResponse2 =
                new JWTInboundResponse.JWTInboundResponseBuilder(identityMessageContext).build();
        return new Object[][]{
                {null, false},
                {jwtInboundResponse1, false},
                {jwtInboundResponse2, true}
        };
    }

    @Test(dataProvider = "getHandleStatus")
    public void testCanHandle(IdentityResponse identityResponse, boolean expected) {

        boolean canHandle = jwtInboundIdentityResponseFactory.canHandle(identityResponse);
        assertEquals(canHandle, expected);
    }
}
