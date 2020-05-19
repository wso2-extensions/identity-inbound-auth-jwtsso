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

package org.wso2.carbon.identity.sso.jwt.exception;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;

/**
 * The exception class
 */
public class JWTClientException extends FrameworkClientException {

    private String exceptionStatus;
    private String exceptionMessage;

    protected JWTClientException(String errorDescription) {

        super(errorDescription);
    }

    protected JWTClientException(String errorDescription, String exceptionStatus, String exceptionMessage) {

        super(errorDescription);
        this.exceptionMessage = exceptionMessage;
        this.exceptionStatus = exceptionStatus;
    }

    protected JWTClientException(String errorDescription, Throwable cause) {

        super(errorDescription, cause);
    }

    public static JWTClientException error(String errorDescription) {

        return new JWTClientException(errorDescription);
    }

    public static JWTClientException error(String errorDescription, Throwable cause) {

        return new JWTClientException(errorDescription, cause);
    }

    public static JWTClientException error(String errorDescription, String exceptionStatus, String exceptionMessage) {

        return new JWTClientException(errorDescription, exceptionStatus, exceptionMessage);
    }

    public String getExceptionStatus() {

        return exceptionStatus;
    }

    public String getExceptionMessage() {

        return exceptionMessage;
    }
}
