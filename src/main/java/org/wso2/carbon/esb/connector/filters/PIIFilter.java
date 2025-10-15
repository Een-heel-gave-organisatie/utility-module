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
package org.wso2.carbon.esb.connector.filters;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.connector.core.AbstractConnector;
import org.wso2.carbon.connector.core.ConnectException;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * PIIFilter mediator filters out sensitive headers and response payload containing sensitive information.
 */
public class PIIFilter extends AbstractConnector {

    private static final Log log = LogFactory.getLog(PIIFilter.class);

    // Common PII patterns
    private static final List<Pattern> PII_PATTERNS = Arrays.asList(
        Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"), // Credit card
        Pattern.compile("\\b\\d{3}[\\s-]?\\d{2}[\\s-]?\\d{4}\\b"), // SSN
        Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"), // Email
        Pattern.compile("\\b(?:\\+?1[-\\s]?)?\\(?[0-9]{3}\\)?[-\\s]?[0-9]{3}[-\\s]?[0-9]{4}\\b") // Phone
    );

    // Sensitive headers to filter
    private static final List<String> SENSITIVE_HEADERS = Arrays.asList(
        "Authorization", "Cookie", "Set-Cookie", "X-API-Key", "X-Auth-Token",
        "Authentication", "Bearer", "Proxy-Authorization", "WWW-Authenticate"
    );

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        try {
            boolean hasSensitiveData = false;

            // Check for sensitive headers
            if (hasSensitiveHeaders(messageContext)) {
                log.warn("Sensitive headers detected - filtering request");
                filterSensitiveHeaders(messageContext);
                hasSensitiveData = true;
            }

            // Check response payload for PII
            if (hasPIIInPayload(messageContext)) {
                log.warn("PII detected in payload - dropping payload");
                clearPayload(messageContext);
                hasSensitiveData = true;
            }

            // Set a property to indicate if filtering occurred
            messageContext.setProperty("pii.filtered", hasSensitiveData);

            if (hasSensitiveData) {
                log.info("PII filtering applied to the message");
            }

        } catch (Exception e) {
            log.error("Error in PIIFilter mediator", e);
            throw new ConnectException("Error in PIIFilter mediator: " + e.getMessage());
        }
    }

    private boolean hasSensitiveHeaders(MessageContext messageContext) {
        try {
            org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                    .getAxis2MessageContext();
            @SuppressWarnings("unchecked")
            Map<String, Object> transportHeaders = (Map<String, Object>) axis2MessageContext.getProperty("TRANSPORT_HEADERS");
            
            if (transportHeaders != null) {
                for (String sensitiveHeader : SENSITIVE_HEADERS) {
                    for (String headerName : transportHeaders.keySet()) {
                        if (headerName.equalsIgnoreCase(sensitiveHeader)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.warn("Error checking sensitive headers", e);
            return false;
        }
    }

    private void filterSensitiveHeaders(MessageContext messageContext) {
        try {
            org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                    .getAxis2MessageContext();
            @SuppressWarnings("unchecked")
            Map<String, Object> transportHeaders = (Map<String, Object>) axis2MessageContext.getProperty("TRANSPORT_HEADERS");
            if (transportHeaders != null) {
                // Remove sensitive headers
                for (String sensitiveHeader : SENSITIVE_HEADERS) {
                    transportHeaders.entrySet().removeIf(entry -> 
                        entry.getKey().equalsIgnoreCase(sensitiveHeader));
                }
            }
        } catch (Exception e) {
            log.warn("Error filtering sensitive headers", e);
        }
    }

    private boolean hasPIIInPayload(MessageContext messageContext) {
        try {
            String payload = getPayloadAsString(messageContext);
            if (payload != null && !payload.trim().isEmpty()) {
                for (Pattern pattern : PII_PATTERNS) {
                    if (pattern.matcher(payload).find()) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.warn("Error checking PII in payload", e);
            return false;
        }
    }

    private String getPayloadAsString(MessageContext messageContext) {
        try {
            if (messageContext.getEnvelope() != null && 
                messageContext.getEnvelope().getBody() != null) {
                return messageContext.getEnvelope().getBody().toString();
            }
            return null;
        } catch (Exception e) {
            log.warn("Error extracting payload", e);
            return null;
        }
    }

    private void clearPayload(MessageContext messageContext) {
        try {
            if (messageContext.getEnvelope() != null && 
                messageContext.getEnvelope().getBody() != null) {
                // Clear the body content
                messageContext.getEnvelope().getBody().getFirstElement().detach();
                log.info("Payload cleared due to PII detection");
            }
        } catch (Exception e) {
            log.warn("Error clearing payload", e);
        }
    }
}