/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *
 */
package org.wso2.carbon.esb.connector.logging;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.connector.core.AbstractConnector;
import org.wso2.carbon.connector.core.ConnectException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * AuditLog mediator logs the current timestamp, request path and invoker's
 * address and user agent.
 */
public class AuditLog extends AbstractConnector {

    private static final Log log = LogFactory.getLog(AuditLog.class);
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        try {
            // Get current timestamp
            String timestamp = LocalDateTime.now().format(DATE_FORMAT);

            // Get request path from context
            String requestPath = getRequestPath(messageContext);

            // Get invoker's address
            String correlationId = getCorrelationId(messageContext);

            // Get user agent
            String userAgent = getUserAgent(messageContext);

            // Log the audit information
            String auditMessage = String.format(
                    "AUDIT LOG - Timestamp: %s, Request Path: %s, Correlation ID: %s, User Agent: %s",
                    timestamp, requestPath, correlationId, userAgent);

            log.info(auditMessage);

        } catch (Exception e) {
            log.error("Error in AuditLog mediator", e);
            throw new ConnectException("Error in AuditLog mediator: " + e.getMessage());
        }
    }

    private String getRequestPath(MessageContext messageContext) {
        try {
            String toAddress = (String) messageContext.getTo().getAddress();
            return toAddress != null ? toAddress : "Unknown";
        } catch (Exception e) {
            log.warn("Unable to extract request path", e);
            return "Unknown";
        }
    }

    private String getCorrelationId(MessageContext messageContext) {
        try {
            String correlationId = (String) messageContext.getProperty("correlation_id");
            return correlationId != null ? correlationId : "Unknown";
        } catch (Exception e) {
            log.warn("Unable to extract correlation ID", e);
            return "Unknown";
        }
    }

    private String getUserAgent(MessageContext messageContext) {
        try {

            org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                    .getAxis2MessageContext();
            @SuppressWarnings("unchecked")
            Map<String, Object> transportHeaders = (Map<String, Object>) axis2MessageContext
                    .getProperty("TRANSPORT_HEADERS");
            if (transportHeaders != null) {
                String userAgent = (String) transportHeaders.get("User-Agent");
                return userAgent != null ? userAgent : "Unknown";
            }
            return "Unknown";
        } catch (Exception e) {
            log.warn("Unable to extract user agent", e);
            return "Unknown";
        }
    }
}