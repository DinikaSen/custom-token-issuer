package org.wso2.custom.token.issuer;

import com.nimbusds.jose.Algorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.List;
import java.util.Optional;

/**
 * Custom JWT Token Issuer implementation that extends JWTTokenIssuer.
 * This class can be used to customize JWT token generation logic in WSO2 Identity Server.
 */
public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);
    private Algorithm signatureAlgorithm = null;
    private static final String EXPIRY_TIME_PARAM = "expiry_time";

    public ExtendedJWTTokenIssuer() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Extended JWT Access token builder is initiated");
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

        List<RequestParameter> requestParams =
                List.of(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters());
        Optional<RequestParameter> expiryTimeParam = requestParams.stream().filter(param ->
                EXPIRY_TIME_PARAM.equals(param.getKey()) && param.getValue()[0] != null).findFirst();

        if (expiryTimeParam.isPresent()) {
            try {
                long expiryTime = Long.parseLong(expiryTimeParam.get().getValue()[0]) * 1000;
                oAuthTokenReqMessageContext.setValidityPeriod(expiryTime);
                if (log.isDebugEnabled()) {
                    log.debug("Custom expiry time set to: " + expiryTime + " seconds");
                }
            } catch (NumberFormatException e) {
                log.warn("Invalid expiry time format: " + expiryTimeParam.get().getValue()[0]
                        + ". Using default validity period.");
            }
        }

        // Call the parent implementation to generate the access token
        return super.accessToken(oAuthTokenReqMessageContext);
    }
}