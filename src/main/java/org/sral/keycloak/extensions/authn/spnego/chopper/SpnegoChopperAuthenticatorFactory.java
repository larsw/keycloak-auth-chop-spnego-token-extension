package org.sral.keycloak.extensions.authn.spnego.chopper;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class SpnegoChopperAuthenticatorFactory implements AuthenticatorFactory {

    private String PROVIDER_ID = "auth-spnego-chopper";

    public static SpnegoChopperAuthenticator SINGLETON;
    public static final SpnegoChopperAuthenticator SINGLETON_DISABLED = new SpnegoChopperAuthenticator(0) {

        @Override
        public void authenticate(AuthenticationFlowContext context) {
            throw new IllegalStateException("Not possible to authenticate as Kerberos feature is disabled");
        }
    };

    @Override
    public String getDisplayType() {
        return "Kerberos";
    }

    @Override
    public String getReferenceCategory() {
        return "Kerberos SPNEGO Chopper";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public org.keycloak.models.AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return isKerberosFeatureEnabled() ? REQUIREMENT_CHOICES : new AuthenticationExecutionModel.Requirement[]{ AuthenticationExecutionModel.Requirement.DISABLED };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return isKerberosFeatureEnabled()
                ? "Initiates the SPNEGO protocol, and optionally chops of bytes from the token. Most often used with Kerberos."
                : "DISABLED. Please enable Kerberos feature and make sure Kerberos available in your platform. Initiates the SPNEGO protocol. Most often used with Kerberos.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<String> options = List.of();
        return ProviderConfigurationBuilder.create()
                .property("numberOfBytesToChopOff",
                          "Bytes to chop off",
                        "How many bytes should be chopped off (from the beginning)",
                        ProviderConfigProperty.STRING_TYPE, "20", options)
                .build();
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return null;
    }

    @Override
    public void init(Config.Scope scope) {
        SINGLETON = new SpnegoChopperAuthenticator(scope.getInt("numberOfBytesToChopOff", 20));
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    private boolean isKerberosFeatureEnabled() {
        return Profile.isFeatureEnabled(Profile.Feature.KERBEROS);
    }
}

