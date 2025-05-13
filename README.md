# iac-scan-IaC-Drift-Detector
Compares live cloud infrastructure state (using `boto3`, `google-cloud-sdk`, or `azure-sdk`) against the defined IaC configuration (e.g., Terraform state file) and reports any drift or discrepancies, highlighting resources that are misconfigured or absent using `json` or `yaml` parsing. - Focused on Analyzes Infrastructure-as-Code (IaC) configurations (e.g., Terraform, CloudFormation) to identify potential security misconfigurations before deployment.  Focuses on detecting issues like overly permissive access controls, exposed secrets, and insecure resource configurations.

## Install
`git clone https://github.com/ShadowStrikeHQ/iac-scan-iac-drift-detector`

## Usage
`./iac-scan-iac-drift-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--iac-type`: No description provided
- `--iac-file`: No description provided
- `--cloud-provider`: No description provided
- `--region`: No description provided
- `--aws-access-key`: No description provided
- `--aws-secret-key`: No description provided
- `--output-format`: No description provided
- `--simulate-attack`: Simulate a potential attack based on detected misconfigurations.

## License
Copyright (c) ShadowStrikeHQ
