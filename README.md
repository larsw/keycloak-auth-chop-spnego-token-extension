# SPNEGO Chopper Authenticator for Keycloak

## Build

```bash
mvn package

docker run --rm -it -p 8080:8080 -v ./target:/opt/keycloak/providers \
        -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
        quay.io/keycloak/keycloak:latest \
        start-dev
```

## Install

1. Create a copy of the Browser flow.
2. Remove the original Kerberos action.
3. Add the Kerberos action from this extension. Look for "... and optionally chops of bytes from the token." in the help text.
4. Configure it (gear icon); adjust the number of bytes to chop off.
5. Voila.

## Author

Lars Wilhelmsen

## License

MIT
