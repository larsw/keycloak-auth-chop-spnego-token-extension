package org.sral.keycloak.extensions.authn.spnego.chopper;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;

import java.net.URI;
import java.util.Map;

/**
 * Most of this code is shamelessly ripped from the keycloak codebase;
 * org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator.
 */
public class SpnegoChopperAuthenticator extends AbstractFormAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(SpnegoAuthenticator.class);
    private final int numberOfBytesToChopOff;

    SpnegoChopperAuthenticator(int numberOfBytesToChopOff) {
        this.numberOfBytesToChopOff = numberOfBytesToChopOff;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.attempted();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpRequest request = context.getHttpRequest();
        String authHeader = request.getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            if (context.getAuthenticationSession().getAuthNote(AuthenticationProcessor.FORKED_FROM) != null) {
                // skip spnego authentication if it was forked (reset-credentials)
                context.attempted();
                return;
            }
            Response challenge = challengeNegotiation(context, null);
            context.forceChallenge(challenge);
            return;
        }

        String[] tokens = authHeader.split(" ");
        if (tokens.length == 0) { // assume not supported
            logger.debug("Invalid length of tokens: " + tokens.length);
            context.attempted();
            return;
        }
        if (!KerberosConstants.NEGOTIATE.equalsIgnoreCase(tokens[0])) {
            logger.debug("Unknown scheme " + tokens[0]);
            context.attempted();
            return;
        }
        if (tokens.length != 2) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        String spnegoToken = tokens[1];

        // CHOP CHOP CHOP
        spnegoToken = chopIfItDoesntStartWithAGSSHeader(spnegoToken);
        // CHOP CHOP CHOP

        UserCredentialModel spnegoCredential = UserCredentialModel.kerberos(spnegoToken);

        CredentialValidationOutput output = context.getSession().users().getUserByCredential(context.getRealm(), spnegoCredential);

        if (output == null) {
            logger.warn("Received kerberos token, but there is no user storage provider that handles kerberos credentials.");
            context.attempted();
            return;
        }
        if (output.getAuthStatus() == CredentialValidationOutput.Status.AUTHENTICATED) {
            context.setUser(output.getAuthenticatedUser());
            if (output.getState() != null && !output.getState().isEmpty()) {
                for (Map.Entry<String, String> entry : output.getState().entrySet()) {
                    context.getAuthenticationSession().setUserSessionNote(entry.getKey(), entry.getValue());
                }
            }
            context.success();
        } else if (output.getAuthStatus() == CredentialValidationOutput.Status.CONTINUE) {
            String spnegoResponseToken = (String) output.getState().get(KerberosConstants.RESPONSE_TOKEN);
            Response challenge =  challengeNegotiation(context, spnegoResponseToken);
            context.challenge(challenge);
        } else {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        }
    }

    private String chopIfItDoesntStartWithAGSSHeader(String spnegoToken) {
        // Decode from Base64
        byte[] decodedBytes;
        try {
            decodedBytes = java.util.Base64.getDecoder().decode(spnegoToken);
        } catch (IllegalArgumentException e) {
            logger.warn("Failed to decode the SPNEGO token from Base64", e);
            return spnegoToken; // Return the original token if decoding fails
        }

        // Check if the decoded byte array starts with 0x60; the ASN.1 tag that the GSSHeader starts with.
        if (decodedBytes.length > 0 && decodedBytes[0] != 0x60) {
            // Chop off the specified number of bytes if it doesn't start with 0x60
            if (numberOfBytesToChopOff < decodedBytes.length) {
                decodedBytes = java.util.Arrays.copyOfRange(decodedBytes, numberOfBytesToChopOff, decodedBytes.length);
            } else {
                logger.warn("Number of bytes to chop off exceeds the token length. Returning original token.");
                return spnegoToken; // Return the original token if chopping would remove all bytes
            }
        }

        // Encode the modified byte array back to Base64
        return java.util.Base64.getEncoder().encodeToString(decodedBytes);
    }
    private Response challengeNegotiation(AuthenticationFlowContext context, final String negotiateToken) {
        String negotiateHeader = negotiateToken == null ? KerberosConstants.NEGOTIATE : KerberosConstants.NEGOTIATE + " " + negotiateToken;

        if (logger.isTraceEnabled()) {
            logger.trace("Sending back " + HttpHeaders.WWW_AUTHENTICATE + ": " + negotiateHeader);
        }
        if (context.getExecution().isRequired()) {
            return context.getSession().getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(context.getAuthenticationSession())
                    .setResponseHeader(HttpHeaders.WWW_AUTHENTICATE, negotiateHeader)
                    .setError(Messages.KERBEROS_NOT_ENABLED).createErrorPage(Response.Status.UNAUTHORIZED);
        } else {
            return optionalChallengeRedirect(context, negotiateHeader);
        }
    }

    // This is used for testing only.  Selenium will execute the HTML challenge sent back which results in the javascript
    // redirecting.  Our old Selenium tests expect that the current URL will be the original openid redirect.
    public static boolean bypassChallengeJavascript = false;

    /**
     * 401 challenge sent back that bypasses
     * @param context
     * @param negotiateHeader
     * @return
     */
    protected Response optionalChallengeRedirect(AuthenticationFlowContext context, String negotiateHeader) {
        String accessCode = context.generateAccessCode();
        URI action = context.getActionUrl(accessCode);

        StringBuilder builder = new StringBuilder();

        builder.append("<HTML>");
        builder.append("<HEAD>");

        builder.append("<TITLE>Kerberos Unsupported</TITLE>");
        builder.append("</HEAD>");
        if (bypassChallengeJavascript) {
            builder.append("<BODY>");

        } else {
            builder.append("<BODY Onload=\"document.forms[0].submit()\">");
        }
        builder.append("<FORM METHOD=\"POST\" ACTION=\"" + action.toString() + "\">");
        builder.append("<NOSCRIPT>");
        builder.append("<P>JavaScript is disabled. We strongly recommend to enable it. You were unable to login via Kerberos.  Click the button below to login via an alternative method .</P>");
        builder.append("<INPUT name=\"continue\" TYPE=\"SUBMIT\" VALUE=\"CONTINUE\" />");
        builder.append("</NOSCRIPT>");

        builder.append("</FORM></BODY></HTML>");
        return Response.status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, negotiateHeader)
                .type(MediaType.TEXT_HTML_TYPE)
                .entity(builder.toString()).build();
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }
}
