#!/usr/bin/env python3

import argparse
import logging
import json
import yaml
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    logging.warning("boto3 is not installed. AWS functionality will be disabled.")

try:
    from google.cloud import storage
    HAS_GOOGLE_CLOUD = True
except ImportError:
    HAS_GOOGLE_CLOUD = False
    logging.warning("google-cloud-storage is not installed. GCP functionality will be disabled.")

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False
    logging.warning("azure-identity and azure-mgmt-resourcegraph are not installed. Azure functionality will be disabled.")


def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(description="Detect IaC drift by comparing live cloud infrastructure state against IaC configuration.")

    # Core Arguments
    parser.add_argument("--iac-type", choices=["terraform", "cloudformation"], required=True,
                        help="The type of Infrastructure as Code used (e.g., terraform, cloudformation).")
    parser.add_argument("--iac-file", required=True,
                        help="Path to the IaC state file (e.g., terraform.tfstate, cloudformation.json/yaml).")
    parser.add_argument("--cloud-provider", choices=["aws", "gcp", "azure"], required=True,
                        help="The cloud provider (e.g., aws, gcp, azure).")
    parser.add_argument("--region", help="The cloud region (e.g., us-east-1). Required for AWS and GCP.") # optional for Azure?

    # Credentials (Optional - can rely on env vars/configs)
    # To avoid secrets directly in command, these would ideally read from environment variables
    # Example:
    #   parser.add_argument("--aws-access-key", default=os.environ.get("AWS_ACCESS_KEY_ID"), help="AWS Access Key (optional, uses env var AWS_ACCESS_KEY_ID if not provided)")
    #   parser.add_argument("--aws-secret-key", default=os.environ.get("AWS_SECRET_ACCESS_KEY"), help="AWS Secret Key (optional, uses env var AWS_SECRET_ACCESS_KEY if not provided)")

    # Reporting Options
    parser.add_argument("--output-format", choices=["json", "yaml", "text"], default="text",
                        help="Output format for the report (default: text).")

    # Offensive Tool options (Example)
    # parser.add_argument("--simulate-attack", action="store_true", help="Simulate a potential attack based on detected misconfigurations.")

    return parser.parse_args()



def load_iac_file(iac_file, iac_type):
    """
    Loads and parses the IaC file (Terraform state, CloudFormation template, etc.).
    Supports JSON and YAML formats.
    """
    try:
        with open(iac_file, 'r') as f:
            if iac_type == "terraform":
                # Assuming Terraform state is always JSON
                data = json.load(f)
            elif iac_type == "cloudformation":
                # Attempt to load as YAML first, then JSON
                try:
                    data = yaml.safe_load(f)
                except yaml.YAMLError:
                    f.seek(0) # Reset file pointer
                    data = json.load(f)  # Try JSON if YAML fails
            else:
                raise ValueError("Unsupported IaC type.")
        return data
    except FileNotFoundError:
        logging.error(f"IaC file not found: {iac_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON in IaC file: {iac_file}")
        raise
    except yaml.YAMLError:
        logging.error(f"Error decoding YAML in IaC file: {iac_file}")
        raise
    except Exception as e:
        logging.error(f"Error loading IaC file: {e}")
        raise


def get_aws_resource_state(region):
    """
    Retrieves the current state of AWS resources using boto3.  This is a placeholder.
    In a real implementation, you would fetch specific resource configurations based on the IaC.
    """
    if not HAS_BOTO3:
        raise Exception("boto3 is required to interact with AWS.")
    try:
        session = boto3.Session(region_name=region)
        ec2 = session.client('ec2') # Example - fetching EC2 instances.  Adapt to specific resource types.
        response = ec2.describe_instances()
        return response
    except ClientError as e:
        logging.error(f"Error fetching AWS resource state: {e}")
        raise


def get_gcp_resource_state(region):
    """
    Retrieves the current state of GCP resources using google-cloud-sdk.  This is a placeholder.
    In a real implementation, you would fetch specific resource configurations based on the IaC.
    """
    if not HAS_GOOGLE_CLOUD:
        raise Exception("google-cloud-storage is required to interact with GCP.")

    try:
        storage_client = storage.Client()
        buckets = list(storage_client.list_buckets())
        return buckets
    except Exception as e:
        logging.error(f"Error fetching GCP resource state: {e}")
        raise

def get_azure_resource_state():
    """
    Retrieves the current state of Azure resources using azure-sdk. This is a placeholder.
    In a real implementation, you would fetch specific resource configurations based on the IaC.
    """
    if not HAS_AZURE:
        raise Exception("azure-identity and azure-mgmt-resourcegraph are required to interact with Azure.")

    try:
        credential = DefaultAzureCredential()
        resource_graph_client = ResourceGraphClient(credential)
        query = """Resources
        | where type == 'microsoft.compute/virtualmachines'
        | limit 10""" # Example query, adapt to the needs.
        response = resource_graph_client.resources(query)
        return response.data

    except Exception as e:
        logging.error(f"Error fetching Azure resource state: {e}")
        raise



def detect_drift(iac_data, live_state, cloud_provider, iac_type):
    """
    Compares the IaC configuration with the live infrastructure state and reports any drift.
    This is a placeholder implementation and will need significant customization based on:
      - The specific resource types being managed in the IaC
      - The structure of the IaC files
      - The API responses from the cloud provider
    """
    drift_detected = []

    # Example comparison (very basic) - needs to be adapted to real use cases.

    if cloud_provider == 'aws' and iac_type == 'terraform':
        #  This is an example only and will need to be significantly expanded.

        # Extract Resource IDs from Terraform State
        iac_resource_ids = set()
        if 'resources' in iac_data:
            for resource in iac_data['resources']:
                if 'instances' in resource:
                    for instance in resource['instances']:
                        if 'attributes' in instance and 'id' in instance['attributes']:
                            iac_resource_ids.add(instance['attributes']['id'])

        # Extract Resource IDs from Live State (AWS)
        live_resource_ids = set()
        if 'Reservations' in live_state:
            for reservation in live_state['Reservations']:
                for instance in reservation['Instances']:
                    live_resource_ids.add(instance['InstanceId'])

        # Find missing resources in live state:
        missing_in_live = iac_resource_ids - live_resource_ids
        if missing_in_live:
            drift_detected.append(f"Drift detected: Resources in IaC missing in live state: {missing_in_live}")

        # Find unexpected resources in live state
        unexpected_in_live = live_resource_ids - iac_resource_ids
        if unexpected_in_live:
            drift_detected.append(f"Drift detected: Resources in live state not defined in IaC: {unexpected_in_live}")


    elif cloud_provider == 'gcp' and iac_type == 'terraform':
       #Placeholder logic - adapt to GCP resources
       if not isinstance(live_state, list):
           drift_detected.append("Unexpected GCP live state format. Cannot compare.")
       else:
           drift_detected.append("GCP Drift Detection (placeholder) - requires custom implementation to compare Terraform state against live GCP resources.")

    elif cloud_provider == 'azure' and iac_type == 'terraform':
        drift_detected.append("Azure Drift Detection (placeholder) - requires custom implementation to compare Terraform state against live Azure resources.")

    else:
        logging.warning(f"Drift detection not implemented for {cloud_provider} with {iac_type}.")


    return drift_detected


def print_report(drift_report, output_format):
    """
    Prints the drift report in the specified format.
    """
    if not drift_report:
        print("No drift detected.")
        return

    if output_format == "json":
        print(json.dumps(drift_report, indent=2))
    elif output_format == "yaml":
        print(yaml.dump(drift_report, indent=2))
    else:  # "text"
        for drift in drift_report:
            print(drift)



def main():
    """
    Main function to orchestrate the IaC drift detection process.
    """
    try:
        args = setup_argparse()

        # Input validation
        if args.cloud_provider in ['aws', 'gcp'] and not args.region:
            raise ValueError("Region is required for AWS and GCP.")

        iac_data = load_iac_file(args.iac_file, args.iac_type)

        if args.cloud_provider == "aws":
            live_state = get_aws_resource_state(args.region)
        elif args.cloud_provider == "gcp":
            live_state = get_gcp_resource_state(args.region)
        elif args.cloud_provider == "azure":
            live_state = get_azure_resource_state()
        else:
            raise ValueError(f"Unsupported cloud provider: {args.cloud_provider}")

        drift_report = detect_drift(iac_data, live_state, args.cloud_provider, args.iac_type)

        print_report(drift_report, args.output_format)


    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()