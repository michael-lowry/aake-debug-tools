# AAKE Debug Tools
A set of tools designed to aid troubleshooting Automic Automation Kubernetes Edition (AAKE)

## Contents
1. uc4_functions_k8s_public.sh — A set of bash functions for identifying AE server processes, and labeling the corresponding pods in K8s
2. Dockerfile_public.txt — Dockerfile for a utility pod meant to be run in the same K8s cluster as your AAKE system
3. aake-debug-tools-public.yaml — Deployment manifest for the utility pod
4. pod-patching-service-account-public.yaml — RBAC manifest to grant pod patching authorization to a service account
5. views.yaml — Views configuration file for K9s, to enable display of AAKE pod labels

## Requirements
* The script must be run in a Linux pod running in the same cluster as the AAKE server.
* The pod must have access to the AAKE logs, e.g., via NFS.
* Tools like bash, gawk, kubectl, ls, grep, cut, and tail must be available. They are included in the Docker image provided.
* The default service account must be enabled, and must have PATCH access to all pods in the cluster. This is also provided via the deployment manifest and RBAC definition file.
* The no_proxy environment variable may need to be adjusted depending on how networking is configured in your cluster.

## Instructions
1. Build the docker image and push it to your container repository.
2. Edit the deployment manifest to point to the image, e.g., `repository:aake-debug-tools:latest.`
3. Edit the shell script for your environment. Set the path to the logs in the `UC4_Log_Dir` variable. Adjust the namespaces if necessary.
4. Deploy the pod and RBAC definitions to your cluster, e.g., using `kubectl apply -f <filename>`
5. SSH into the pod, e.g, using the 's' key in K9s.
6. Source the script if it's not already sourced by the `.bashrc` file.
7. Run the 'ae' function.
