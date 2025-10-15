# Utility Module Overview

The Utility Module provides logging and filtering capabilities for WSO2 integration scenarios. This module focuses on auditing and security features to help monitor and protect sensitive data in your integration flows.

| Package | Functions                                                                                                    |
|---------|--------------------------------------------------------------------------------------------------------------|
| Logging | Audit Log - Logs timestamp, request path, invoker address, and user agent from message context             |
| Filters | PII Filter - Filters sensitive headers and payload data containing personally identifiable information (PII) |

## Features

### Logging Set
- **Audit Log**: Automatically captures and logs:
  - Current timestamp
  - Request path from message context
  - Invoker's IP address
  - User agent information
  - No parameters required - all data extracted from context

### Filters Set  
- **PII Filter**: Security-focused filtering that:
  - Removes sensitive headers (Authorization, Cookie, API keys, etc.)
  - Detects and filters PII in response payloads (credit cards, SSNs, emails, phone numbers)
  - Drops sensitive data to prevent data leaks
  - No configuration needed - uses built-in pattern matching

## Compatibility

| Connector version | Supported product versions |
|-------------------|----------------------------|
| 2.0.2-SNAPSHOT    | MI 4.x                    |

## Building from the source

Follow the steps given below to build the Utility module from the source code.

1. Get a clone or download the source from [Github](https://github.com/wso2-extensions/mediation-utility-module).
2. Run the following Maven command from the `mediation-utility-module` directory: `mvn clean install`.
3. The ZIP file of the connector is created in the `mediation-utility-module/target` directory.

## How to contribute

As an open source project, WSO2 extensions welcome contributions from the community.

To contribute to the code for this connector, please create a pull request in the following repository.

* [Utility Module GitHub repository](https://github.com/wso2-extensions/mediation-utility-module)

Check the issue tracker for open issues that interest you. We look forward to receiving your contributions.
