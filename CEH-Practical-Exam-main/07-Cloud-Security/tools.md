Cloud Security Tools

AWS Security

AWS CLI
- aws: Linha de comando AWS
- aws-shell: Shell interativo AWS

 Enumeration
- ScoutSuite: Multi-cloud auditing
- Prowler: AWS security assessment
- CloudMapper: AWS visualization

 Azure Security

 Azure CLI
- az: Linha de comando Azure
- Azure PowerShell: PowerShell para Azure

 Enumeration
- ScoutSuite: Auditoria Azure
- Stormspotter: Azure Red Team tool

 Google Cloud Security

 GCloud CLI
- gcloud: Linha de comando GCP
- gsutil: Google Cloud Storage

 Multi-Cloud Tools

# Pacu
- AWS Exploitation Framework: Framework de exploração AWS

 Cloud_enum
- Cloud Asset Discovery: Descoberta de assets cloud

 Scripts Úteis

 AWS Enumeration
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances

 Azure Enumeration
az account show
az vm list
az storage account list

 GCP Enumeration
gcloud auth list
gcloud compute instances list
gcloud storage buckets list

 ScoutSuite
python scout.py aws
python scout.py azure
python scout.py gcp

 Prowler
./prowler -g cislevel2_aws