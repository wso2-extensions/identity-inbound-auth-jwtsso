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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.HashMap;

/**
 * Class for storing OSGi services and their related context information.
 */
public class JWTInboundUtil {

    private static Log log = LogFactory.getLog(JWTInboundUtil.class);

    private static BundleContext bundleContext;
    private static RealmService realmService;
    private static ConfigurationContextService configCtxService;
    private static HttpService httpService;

    public static BundleContext getBundleContext() {

        return bundleContext;
    }

    public static RealmService getRealmService() {

        return realmService;
    }

    public static ConfigurationContextService getConfigCtxService() {

        return configCtxService;
    }

    public static HttpService getHttpService() {

        return httpService;
    }

    public static void setBundleContext(BundleContext bundleContext) {

        JWTInboundUtil.bundleContext = bundleContext;
    }

    public static void setRealmService(RealmService realmService) {

        JWTInboundUtil.realmService = realmService;
    }

    public static void setConfigCtxService(ConfigurationContextService configCtxService) {

        JWTInboundUtil.configCtxService = configCtxService;
    }

    public static void setHttpService(HttpService httpService) {

        JWTInboundUtil.httpService = httpService;
    }

    /**
     * The method used to prevent CRLF_INJECTION_LOGS. It neutralizes the given input.
     *
     * @param input The input string to be neutralized.
     * @return neutralized output.
     */
    public static String neutralize(String input) {

        if (StringUtils.isNotBlank(input)) {
            return input.replaceAll("[\r\n]", "");
        }
        return null;
    }

    /**
     * The method used to build the client side error page to be redirected to retry.do
     * Default status: authentication.error (Authentication Error!)
     * Default message: something.went.wrong.during.authentication (Something went wrong during the authentication
     * process. Please try signing in again.)
     *
     * @return
     */
    public static JWTInboundResponse.JWTInboundResponseBuilder sendToRetryPage() {

        JWTInboundResponse.JWTInboundResponseBuilder respBuilder = new JWTInboundResponse.JWTInboundResponseBuilder();
        respBuilder.setEndpointUrl(ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL());
        return respBuilder;
    }

    /**
     * The method used to build the client side error page to be redirected to retry.do
     *
     * @param status    The status of the message defined in Resources.properties file of the authentication endpoint.
     *                  Ex: misconfiguration.error
     * @param statusMsg The message defined in Resources.properties file of the authentication endpoint.
     *                  Ex: something.went.wrong.contact.admin
     * @return
     */
    public static JWTInboundResponse.JWTInboundResponseBuilder sendToRetryPage(String status, String statusMsg) {

        JWTInboundResponse.JWTInboundResponseBuilder respBuilder = new JWTInboundResponse.JWTInboundResponseBuilder();
        respBuilder.setParameters(new HashMap<String, String>() {
            {
                put("status", status);
                put("statusMsg", statusMsg);
            }
        });
        respBuilder.setEndpointUrl(ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL());
        return respBuilder;
    }
}
