curl \
    --header "X-Vault-Token: root" \
    http://127.0.0.1:8200/v1/sys/plugins/catalog


curl \
    --header "X-Vault-Token: root" \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/sys/plugins/reload/backend


VAULT_TOKEN="" vault write auth/webauthn/user/john password=password
VAULT_TOKEN="" vault read auth/webauthn/register


curl -s \
    --header "X-Vault-Token: root" \
    http://127.0.0.1:8200/v1/sys/config/cors | jq .


curl -s \
    --header "X-Vault-Token: root" \
    --request POST \
    --data @cors.json \
    http://127.0.0.1:8200/v1/sys/config/cors | jq .


curl -s \
    --request POST \
    --data @test.json \
    http://127.0.0.1:8200/v1/sys/auth/webauthn/register/begin | jq .
