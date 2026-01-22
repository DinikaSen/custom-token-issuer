package org.wso2.custom.token.issuer;

import com.nimbusds.jose.Algorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;

import java.util.List;
import java.util.Optional;

/**
 * Custom JWT Token Issuer implementation that extends JWTTokenIssuer.
 * This class can be used to customize JWT token generation logic in WSO2 Identity Server.
 */
public class CustomJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(CustomJWTTokenIssuer.class);
    private Algorithm signatureAlgorithm = null;
    private static final String EXPIRY_TIME_PARAM = "expiry_time";

    public CustomJWTTokenIssuer() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Custom JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    /**
     * Issue access token using the provided token request message context.
     * This method can be overridden to customize the access token generation logic.
     *
     * @param oAuthTokenReqMessageContext OAuth token request message context
     * @return Generated access token
     * @throws OAuthSystemException if an error occurs during token generation
     */
    @Override
    public String accessToken(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws OAuthSystemException {

        long expiryTime = getExpiryTimeFromRequest(oAuthTokenReqMessageContext);
        if (expiryTime != 0) {
            oAuthTokenReqMessageContext.setValidityPeriod(expiryTime);
            log.debug("Custom expiry time set to: " + expiryTime + " millis");
        }

        // Call the parent implementation to generate the access token
        return super.accessToken(oAuthTokenReqMessageContext);
    }

    /**
     * Get token validity period for the Self contained JWT Access Token.
     *
     * @param tokenReqMessageContext
     * @param oAuthAppDO
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected long getAccessTokenLifeTimeInMillis(OAuthTokenReqMessageContext tokenReqMessageContext,
                                                  OAuthAppDO oAuthAppDO,
                                                  String consumerKey) throws IdentityOAuth2Exception {

        long lifetimeInMillis = getExpiryTimeFromRequest(tokenReqMessageContext);

        if (lifetimeInMillis != 0) {
            log.debug("Custom expiry time set to: " + lifetimeInMillis + " millis");
            return lifetimeInMillis;
        }

        if (tokenReqMessageContext.isPreIssueAccessTokenActionsExecuted()) {
            lifetimeInMillis = tokenReqMessageContext.getValidityPeriod();
            log.debug("Access token life time is set from OAuthTokenReqMessageContext. Token Lifetime : " +
                    lifetimeInMillis + "ms.");

            return lifetimeInMillis;
        }

        boolean isUserAccessTokenType =
                isUserAccessTokenType(tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType(),
                        tokenReqMessageContext);

        if (isUserAccessTokenType) {
            lifetimeInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("User Access Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        } else {
            lifetimeInMillis = oAuthAppDO.getApplicationAccessTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("Application Access Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        }

        if (lifetimeInMillis == 0) {
            if (isUserAccessTokenType) {
                lifetimeInMillis =
                        OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds() * 1000;
                if (log.isDebugEnabled()) {
                    log.debug("User access token time was 0ms. Setting default user access token lifetime : "
                            + lifetimeInMillis + "ms.");
                }
            } else {
                lifetimeInMillis =
                        OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds() *
                                1000;
                if (log.isDebugEnabled()) {
                    log.debug("Application access token time was 0ms. Setting default Application access token " +
                            "lifetime : " + lifetimeInMillis + "ms.");
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Access Token Life time set to : " + lifetimeInMillis + "ms.");
        }
        return lifetimeInMillis;
    }

    private boolean isUserAccessTokenType(String grantType, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        AuthorizationGrantHandler grantHandler =
                OAuthServerConfiguration.getInstance().getSupportedGrantTypes().get(grantType);
        // If grant handler is null ideally we would not come to this point as the flow will be broken before. So we
        // can guarantee grantHandler will not be null
        return grantHandler.isOfTypeApplicationUser(tokReqMsgCtx);
    }

    private long getExpiryTimeFromRequest(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) {

        List<RequestParameter> requestParams =
                List.of(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters());
        Optional<RequestParameter> expiryTimeParam = requestParams.stream().filter(param ->
                EXPIRY_TIME_PARAM.equals(param.getKey()) && param.getValue()[0] != null).findFirst();

        if (expiryTimeParam.isPresent()) {
            try {
                long expiryTime = Long.parseLong(expiryTimeParam.get().getValue()[0]) * 1000;
                if (log.isDebugEnabled()) {
                    log.debug("Custom expiry time extracted from request: " + expiryTime + " millis");
                }
                return expiryTime;
            } catch (NumberFormatException e) {
                log.warn("Invalid expiry time format: " + expiryTimeParam.get().getValue()[0]
                        + ". Using default validity period.");
            }
        }

    return 0L;
    }
}