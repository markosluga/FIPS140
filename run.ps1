# Login to SSO and export credentials
. "$PSScriptRoot\aws-login.ps1"
# Run docker
docker compose up -d
