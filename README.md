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
* The default service account must be enabled, and must have PATCH access to all pods in the cluster. This is also provided via the provided deployment manifest and RBAC definition file.
* The `no_proxy` environment variable may need to be adjusted depending on how networking is configured in your cluster.

## Instructions
1. Build the docker image and push it to your container repository.
2. Edit the deployment manifest to point to the image, e.g., `<repository>/aake-debug-tools:latest.`
3. Edit the shell script for your environment. Set the path to the logs in the `UC4_Log_Dir` variable. Adjust the namespaces if necessary.
4. Deploy the pod and RBAC definitions to your cluster, e.g., using `kubectl apply -f <filename>`
5. SSH into the pod, e.g, using the 's' key in K9s.
6. Source the script if it's not already sourced by the `.bashrc` file.
7. Run the 'ae' function.

## Detailed discussion
### Background
In the Automic Web Interface (AWI), the _Automation Engine Management_ /  _Processes and Utilization_ view of the _Administration_ perspective lists the details of AE server processes, including:
* AE process name, (WP001, CP005, etc.)
* Process type (WP, CP, JWP, JCP, or REST)
* Process role, (Primary, Output, Resources, Dialog, Authentication, Index, Performance, Utility, etc.)
* Pod/host name, e.g., wp-0-7b895f69dd-xmnrb
* etc.
  
When viewing an AAKE cluster using K9s or `kubectl` however, only the pod name is visible. The remaining details are not available to the cluster. This makes troubleshooting difficult, perticularly when the AWI is unavailable or not responsive.
I developed the AAKE Debug Tools to address this gap in functionality.

### Components
The package consists of:
* Docker image
* K8s deployment manifest
* RBAC manifests
  * Service account
  * Cluster role
  * Cluster role binding
* Shell script with Bash functions
* Customized K9s views file

The main component of the AAKE Debug Tools is the Bash script.

### How it works
The shell script does its magic by parsing Automation Engine log files, looking for particular messages, and extracting desired pieces of information. The script is divided into functions. Each function performs a specific task.
* `pwp()` — Identify the Primary Work Process by searching recent logs for message U00003475 & U00011818.
  The PWP log is then read to determine the system name & version.
* `search_logs()` — Starting with the 00-generation logs and then proceeding if necessary to older logs, search for messages matching a given pattern.
* `ae_logs()` & `ae_proc()` — Identify _running_ AE server processes by finding the 00-generation logs that do not have message U00003401, U00003410, or U00003432 near the end.
* `aewp()`, `aecp()`, `owp()`, `rwp()`, `jwp()` — Identify process types based on message U02000090.
* `restp()` — Identify REST processes based on message U00003400.
* `jwp_roles()` — Identify JPW role based on message U00045395.
* `wp_mode_latest()` — Identify WP/DWP status of each WP, based on messages U00003400 & U00003389.
* `k8s_labels_init()`, `k8s_labels_add()`, & `k8s_labels_emit()` — Add labels to pods.
* `ae()` — Main function. Use all of the above functions to list AE server processes and apply labels to pods.
