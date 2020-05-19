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
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.sso.jwt.exception.JWTIdentityException;
import org.wso2.carbon.identity.sso.jwt.factory.JWTInboundIdentityResponseFactory;
import org.wso2.carbon.identity.sso.jwt.factory.JWTInboundRequestFactory;
import org.wso2.carbon.identity.sso.jwt.message.JWTInboundResponse;
import org.wso2.carbon.identity.sso.jwt.processor.JWTInboundRequestProcessor;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.lang.reflect.InvocationTargetException;
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
    private static String authConfigClass = null;
    private static String requestProcessorClass = null;
    private static String responseFactoryClass = null;
    private static String requestFactoryClass = null;

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

    /**
     * This method returns the Authenticator Config instance based on the configuration defined in identity.xml.
     *
     * @return an instance of AbstractInboundAuthenticatorConfig
     * @throws JWTIdentityException
     */
    public static AbstractInboundAuthenticatorConfig getAuthConfigClass() throws JWTIdentityException {

        if (StringUtils.isBlank(authConfigClass)) {
            if (log.isDebugEnabled()) {
                log.debug("Using the default inbound authenticator config: JWTInboundAuthConfig");
            }
            return new JWTInboundAuthConfig();
        } else {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Inbound authenticator defined: " + JWTInboundUtil.neutralize(authConfigClass));
                }
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(authConfigClass);
                return (AbstractInboundAuthenticatorConfig) clazz.getConstructor().newInstance();

            } catch (ClassNotFoundException e) {
                throw new JWTIdentityException("Error while loading the class: " + authConfigClass, e);
            } catch (InstantiationException e) {
                throw new JWTIdentityException("Error while instantiating the class: " + authConfigClass, e);
            } catch (IllegalAccessException e) {
                throw new JWTIdentityException("Cannot access the class while instantiating " + authConfigClass, e);
            } catch (NoSuchMethodException e) {
                throw new JWTIdentityException("Error while accessing the constructor while instantiating " +
                        authConfigClass, e);
            } catch (InvocationTargetException e) {
                throw new JWTIdentityException("Error invoking while instantiating the class: " +
                        authConfigClass, e);
            }
        }
    }

    /**
     * This method returns the Request Processor instance based on the configuration defined in identity.xml.
     *
     * @param jwtInboundAuthConfig
     * @return an instance of IdentityProcessor
     * @throws JWTIdentityException
     */
    public static IdentityProcessor getRequestProcessorClass(AbstractInboundAuthenticatorConfig jwtInboundAuthConfig)
            throws JWTIdentityException {

        if (StringUtils.isBlank(requestProcessorClass)) {
            if (log.isDebugEnabled()) {
                log.debug("Using the default request processor: JWTInboundRequestProcessor");
            }
            return new JWTInboundRequestProcessor(jwtInboundAuthConfig);
        } else {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Request processor defined: " + JWTInboundUtil.neutralize(requestProcessorClass));
                }
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(requestProcessorClass);
                Class[] cArg = new Class[]{AbstractInboundAuthenticatorConfig.class};
                return (IdentityProcessor) clazz.getDeclaredConstructor(cArg).newInstance(jwtInboundAuthConfig);

            } catch (ClassNotFoundException e) {
                throw new JWTIdentityException("Error while loading the class: " + requestProcessorClass, e);
            } catch (InstantiationException e) {
                throw new JWTIdentityException("Error while instantiating the class: " + requestProcessorClass, e);
            } catch (IllegalAccessException e) {
                throw new JWTIdentityException("Cannot access the class while instantiating " +
                        requestProcessorClass, e);
            } catch (NoSuchMethodException e) {
                throw new JWTIdentityException("Error while accessing the constructor while instantiating " +
                        requestProcessorClass, e);
            } catch (InvocationTargetException e) {
                throw new JWTIdentityException("Error invoking while instantiating the class: " +
                        requestProcessorClass, e);
            }
        }
    }

    /**
     * This method returns the Response Factory instance based on the configuration defined in identity.xml.
     *
     * @return an instance of HttpIdentityResponseFactory
     * @throws JWTIdentityException
     */
    public static HttpIdentityResponseFactory getResponseFactoryClass() throws JWTIdentityException {

        if (StringUtils.isBlank(responseFactoryClass)) {
            if (log.isDebugEnabled()) {
                log.debug("Using the default response factory: JWTInboundIdentityResponseFactory");
            }
            return new JWTInboundIdentityResponseFactory();
        } else {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Response factory defined: " + JWTInboundUtil.neutralize(responseFactoryClass));
                }
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(responseFactoryClass);
                return (HttpIdentityResponseFactory) clazz.getConstructor().newInstance();

            } catch (ClassNotFoundException e) {
                throw new JWTIdentityException("Error while loading the class: " + responseFactoryClass, e);
            } catch (InstantiationException e) {
                throw new JWTIdentityException("Error while instantiating the class: " + responseFactoryClass, e);
            } catch (IllegalAccessException e) {
                throw new JWTIdentityException("Cannot access the class while instantiating " +
                        responseFactoryClass, e);
            } catch (NoSuchMethodException e) {
                throw new JWTIdentityException("Error while accessing the constructor while instantiating " +
                        responseFactoryClass, e);
            } catch (InvocationTargetException e) {
                throw new JWTIdentityException("Error invoking while instantiating the class: " +
                        responseFactoryClass, e);
            }
        }
    }

    /**
     * This method returns the Request Factory instance based on the configuration defined in identity.xml.
     *
     * @return an instance of HttpIdentityRequestFactory
     * @throws JWTIdentityException
     */
    public static HttpIdentityRequestFactory getRequestFactoryClass() throws JWTIdentityException {

        if (StringUtils.isBlank(requestFactoryClass)) {
            if (log.isDebugEnabled()) {
                log.debug("Using the default request factory: JWTInboundRequestFactory");
            }
            return new JWTInboundRequestFactory();
        } else {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Request factory defined: " + JWTInboundUtil.neutralize(requestFactoryClass));
                }
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(requestFactoryClass);
                return (HttpIdentityRequestFactory) clazz.getConstructor().newInstance();
            } catch (ClassNotFoundException e) {
                throw new JWTIdentityException("Error while loading the class: " + requestFactoryClass, e);
            } catch (InstantiationException e) {
                throw new JWTIdentityException("Error while instantiating the class: " + requestFactoryClass, e);
            } catch (IllegalAccessException e) {
                throw new JWTIdentityException("Cannot access the class while instantiating " +
                        requestFactoryClass, e);
            } catch (NoSuchMethodException e) {
                throw new JWTIdentityException("Error while accessing the constructor while instantiating " +
                        requestFactoryClass, e);
            } catch (InvocationTargetException e) {
                throw new JWTIdentityException("Error invoking while instantiating the class: " +
                        requestFactoryClass, e);
            }
        }
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

    public static void setResponseFactoryClass(String responseFactoryClass) {

        JWTInboundUtil.responseFactoryClass = responseFactoryClass;
    }

    public static void setRequestFactoryClass(String requestFactoryClass) {

        JWTInboundUtil.requestFactoryClass = requestFactoryClass;
    }

    public static void setRequestProcessorClass(String requestProcessorClass) {

        JWTInboundUtil.requestProcessorClass = requestProcessorClass;
    }

    public static void setAuthConfigClass(String authConfigClass) {

        JWTInboundUtil.authConfigClass = authConfigClass;
    }

    /**
     * The method used to prevent CRLF_INJECTION_LOGS. It neutralizes the given input.
     *
     * @param input The input string to be neutralized.
     * @return      neutralized output.
     */
    public static String neutralize(String input) {

        if (StringUtils.isNotBlank(input)) {
            return input.replaceAll("[\r\n]", "");
        }
        return null;
    }

    /**
     * The method used to build the client side error page to be redirected to retry.do
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
