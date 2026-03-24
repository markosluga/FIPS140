#!/bin/bash
aws sso login --profile demos
eval "$(aws configure export-credentials --profile demos --format env | tr -d '\r')"
