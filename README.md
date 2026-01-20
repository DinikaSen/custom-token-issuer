# Custom Token Issuer for WSO2 Identity Server

This project implements a custom OAuth token issuer for WSO2 Identity Server by extending the `OauthTokenIssuerImpl` class.

## Project Structure

```
custom-token-issuer/
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   ├── java/
    │   │   └── org/
    │   │       └── wso2/
    │   │           └── custom/
    │   │               └── token/
    │   │                   └── issuer/
    │   │                       └── CustomTokenIssuer.java
    │   │                       └── ExtendedJWTTokenIssuer.java
    │   └── resources/
    └── test/
        ├── java/
        └── resources/
```

## Project Information

- **Group ID**: org.wso2.custom.token.issuer
- **Artifact ID**: custom-token-issuer
- **Version**: 1.0.0
- **Java Version**: 11

## CustomTokenIssuer Class

The `CustomTokenIssuer` class extends `OauthTokenIssuerImpl` and provides customized opaque token generation functionality.
The `ExtendedJWTTokenIssuer` class extends `JWTTokenIssuer` and provides customized JWT token generation functionality.

### Features

#### Custom Access Token Expiry Time

The implementation supports dynamic access token expiry time configuration through request parameters. When requesting an access token, clients can specify a custom expiry time by including the `expiryTime` parameter in the token request.

**How it works:**
- The token issuer checks for an `expiry_time` parameter in the **OAuth token request**
- If present and valid, it sets the token validity period to the specified value
- If the parameter is missing or invalid, the default validity period is used
- Invalid formats are logged with a warning and gracefully fall back to defaults

## Building the Project

To build the project, run:

```bash
mvn clean install
```

This will generate a JAR file in the `target/` directory.

## Deployment to WSO2 Identity Server

1. Build the project using Maven
2. Copy the generated JAR file from `target/` to `<IS_HOME>/repository/components/lib/`
3. Configure the token issuer in `<IS_HOME>/repository/conf/deployment.toml`:

```toml
[oauth.extensions]
token_generator = "org.wso2.custom.token.issuer.CustomTokenIssuer"

[oauth.extensions.token_types.token_type]
name="JWT"
issuer="org.wso2.custom.token.issuer.ExtendedJWTTokenIssuer"
```

4. Restart the WSO2 Identity Server

## Usage

### Setting Custom Token Expiry Time

To request an access token with a custom expiry time, include the `expiry_time` (in seconds) parameter in your token request:

**Example using cURL:**

```bash
curl -X POST https://localhost:9443/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "redirect_uri=YOUR_REDIRECT_URI" \
  -d "code=YOUR_AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "expiry_time=7200"
```

**Parameters:**
- `expiry_time`: Token validity period in seconds (e.g., 3600 for 1 hour, 7200 for 2 hours)

**Note:** If the `expiry_time` parameter is not provided or contains an invalid value, the default application token expiry time configured in WSO2 Identity Server will be used.



