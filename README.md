# Vault Webauthn auth plugin (non-prod)

Mock is an example secrets engine plugin for [HashiCorp Vault](https://www.vaultproject.io/). It is meant for demonstration purposes only and should never be used in production.

## Usage

All commands can be run using the provided [Makefile](./Makefile). However, it may be instructive to look at the commands to gain a greater understanding of how Vault registers plugins. Using the Makefile will result in running the Vault server in `dev` mode. Do not run Vault in `dev` mode in production. The `dev` server allows you to configure the plugin directory as a flag, and automatically registers plugin binaries in that directory. In production, plugin binaries must be manually registered.

This will build the plugin binary and start the Vault dev server:

```
# Build Mock plugin and start Vault dev server with plugin automatically registered
$ make
```

Now open a new terminal window and run the following commands:

```
# Open a new terminal window and export Vault dev server http address
$ export VAULT_ADDR='http://127.0.0.1:8200'

# Enable the Mock plugin
$ make enable
#

# Enable CORS in vault so that cross domain calls from web browser to vault can be allowed.
$
$ curl -s \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @cors.json \
    http://127.0.0.1:8200/v1/sys/config/cors | jq .

```

# register platform authenticator (biometric key)
- log into vault using any available auth (- use root token for example)
- register your platform authenticator key

# log into vault using platform authenticator


# test web server
This project has a super dumb webserver packaged. In order to test the server with the
plugin ensure backend.go is updated to reflect right RPOrigin value.  Since server runs
on localhost:8003, RPOrigin value should be http://localhost:8003

# vault UI changes to add new register and login buttons