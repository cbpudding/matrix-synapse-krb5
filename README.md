# Kerberos Auth Provider for Matrix Synapse

This is a simple module for Synapse that verifies and creates Matrix accounts on your homeserver using Kerberos as the backend. I created this for my online community in order to keep management of my domain as simple as possible. I have made it open source with the hope that this will be useful to someone other than myself.

To install the module, copy it under the `site-packages` folder in the Python environment used by Synapse, and add the following to the `modules` section of your `homeserver.yaml`:
```YAML
modules:
  - module: "krb5_auth_provider.KerberosAuthProvider"
    config: {}
```

If you would like to make a contribution, feel free to open a pull request.

Please report any security vulnerabilities to ahill@breadpudding.dev rather than opening a public issue.

## Requirements

- MIT Kerberos 5.1.17 or greater (other implementations may work)
- py3-krb5 0.5.1 or greater
- Synapse 1.46.0 or greater