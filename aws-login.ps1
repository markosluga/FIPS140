aws sso login --profile demos

$creds = aws configure export-credentials --profile demos --format env
foreach ($line in $creds) {
    if ($line -match '^export\s+(\w+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
