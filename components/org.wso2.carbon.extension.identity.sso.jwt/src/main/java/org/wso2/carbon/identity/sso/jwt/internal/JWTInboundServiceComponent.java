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

package org.wso2.carbon.identity.sso.jwt.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.jwt.factory.JWTInboundIdentityResponseFactory;
import org.wso2.carbon.identity.sso.jwt.factory.JWTInboundRequestFactory;
import org.wso2.carbon.identity.sso.jwt.processor.JWTInboundRequestProcessor;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundAuthConfig;
import org.wso2.carbon.identity.sso.jwt.util.JWTInboundUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.Hashtable;

/**
 * This is the OSGi service component for the JWT inbound authenticator. This will enable the bundle (jar) to
 * activate the specified service and register themselves so that the IS is able to see them and use them when a
 * matching request arrives.
 */
@Component(
        name = "org.wso2.carbon.identity.sso.jwt",
        immediate = true
)
public class JWTInboundServiceComponent {

    private static Log log = LogFactory.getLog(JWTInboundServiceComponent.class);

    protected void activate(ComponentContext ctxt) {

        try {
            IdentityUtil.populateProperties();

            JWTInboundAuthConfig jwtInboundAuthConfig = new JWTInboundAuthConfig();
            Hashtable<String, String> props = new Hashtable<>();
            ctxt.getBundleContext().registerService(AbstractInboundAuthenticatorConfig.class,
                    jwtInboundAuthConfig, props);

            ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(),
                    new JWTInboundRequestProcessor(jwtInboundAuthConfig), null);

            ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                    new JWTInboundIdentityResponseFactory(), null);

            ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                    new JWTInboundRequestFactory(), null);
            log.info("JWT inbound authenticator bundle is activated.");
        } catch (Exception e) {
            log.error("Error Activating JWT Inbound Auth Package.", e);
            throw new RuntimeException(e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {

        JWTInboundUtil.setBundleContext(null);
        if (log.isDebugEnabled()) {
            log.debug("JWT inbound authenticator bundle is deactivated.");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the JWT inbound authenticator bundle.");
        }
        JWTInboundUtil.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the JWT inbound authenticator bundle.");
        }
        JWTInboundUtil.setRealmService(null);
    }

    @Reference(
            name = "config.context.service",
            service = org.wso2.carbon.utils.ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService"
    )
    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {

        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the JWT inbound authenticator bundle.");
        }
        JWTInboundUtil.setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {

        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the JWT inbound authenticator bundle.");
        }
        JWTInboundUtil.setConfigCtxService(null);
    }

    @Reference(
            name = "osgi.httpservice",
            service = org.osgi.service.http.HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the JWT inbound authenticator bundle.");
        }
        JWTInboundUtil.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the JWT inbound authenticator bundle.");
        }
        JWTInboundUtil.setHttpService(null);
    }
}
