#!/bin/bash
#
# uc4_functions_k8s.sh
#
# Description
# Functions for UC4 (Automation Engine) administration in Kubernetes (K8S)
#
# Usage
# Source this script in .bashrc, and then use the functions from the Linux shell.
# The main function is called 'ae'. It will list all running AE server processes,
# and then attempt to patch the corresponding pods in K8s with lables for process
# name, type, and role(s).
#
# Author
# Michael A. Lowry <michael_lowry@swissre.com> <michael.lowry@gmail.com>
#
# Version		Date			Description
# 1.0.0			2025.06.30		Adapted previous uc4_functions.sh script for Kubernetes.
# 1.0.1			2025.07.21		Improved identification of OWP and RWP. Other small bug fixes.
# 1.0.2			2025.07.23		Improvements to proc2host, log2proc, and dwp functions.
# 1.0.3			2025.07.23		Added identification of JWP roles. Added + symbol to OWP & RWP.
# 1.0.4			2025.07.23		Added header with server name & version.
# 1.0.5			2025.10.06		Improved pwp() function by searching for two message numbers.
# 1.1.0			2025.10.07		Add labels to pods in cluster if kubectl is available.
# 1.1.1			2025.10.13		Fixed setting of API_SERVER.
# 1.1.2			2025.10.13		Added API_SERVER_EXP2.
# 1.1.3			2025.10.14		Fixed API_SERVER_EXP2. Exclude PWP from DWP check.
# 1.1.4			2025.10.16		Exclude stopped processes. Improved PWP & JWP role identification.
# 1.1.5			2025.10.16		Increased max age of logs to search in ae_logs() to 9600.
# 1.1.6			2025.10.17		Improved identification of DWPs.
# 1.1.7			2025.10.21		Added maxdepth to ae_logs & search_logs(); Label 'name' -> 'proc'.
# 1.2.0			2025.10.22		Enqueue pod label changes and apply them using 1 'kubectl apply'.
# 1.2.1			2025.10.22		Add environment-specific color badge (emoji) to server name.
# 1.2.2			2025.10.28		Set label_pods=true by default.
# 1.2.3			2025.10.31		Typo fix (AAKE_PRD); increased max age for ae_logs().
# 1.2.4			2025.10.31		Fixed UC4_EXP2 namespace & updated AAKE_E1 API server host name.
# 1.2.5			2025.11.03		Use $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT.
# 1.3.0			2025.11.05		Use awk in several places to improve performance.
# 1.3.1			2025.11.05		More performance improvements, i.e., in jwp_roles() function.
# 1.3.2			2025.11.06		Optimized wp_mode_latest function to speed up DWP idendification.
# 1.3.3			2025.11.06		Better exclusion of stopped processes in ae_logs() using U00003432.
# 1.3.4			2025.11.06		Better identification of O and R role WPs.
# 1.3.5			2025.11.06		Fixed double timestamp parsing in wp_mode_latest().
# 1.3.6			2025.11.11		Fixed missing UC4_Log_Dir path in jwp_roles().
# 1.3.7			2025.11.14		Added label_pod() function to add labels to an individual pod.

# Set shell options
shopt -s extglob # Extended globbing enables lists like '@(A|B|C)'

# Script version
AAKE_Debug_Tools_Version="1.3.7"

# Use JWT token & CA cert of service account.
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
# The Kubernetes REST API server.
API_SERVER="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

# Set path where UC4 logs can be found.
UC4_Log_Dir="/usr/server/tmp/log"

# Label pods in K8s?
label_pods=true

# Environment-specific color emoji
ENV_COLOR_AE_EXP="🟨"
ENV_COLOR_AE_EXP2="🟧"
ENV_COLOR_AE_DEV="🟦"
ENV_COLOR_AE_TEST"🟩"
ENV_COLOR_AE_PROD="🟥"

# Set server color tag and namespace.
set_env_values() {
	local server=$(uc4_server)
	case "$server" in
	AE_EXP) ENV_COLOR=$ENV_COLOR_AE_EXP ;;
	AE_EXP2) ENV_COLOR=$ENV_COLOR_AE_EXP2 ;;
	AE_DEV) ENV_COLOR=$ENV_COLOR_AE_DEV ;;
	AE_TEST) ENV_COLOR=$ENV_COLOR_AE_TEST ;;
	AE_PROD) ENV_COLOR=$ENV_COLOR_AE_PROD ;;
	esac
	case "$server" in
	AE_EXP2) NAMESPACE="ae-exp2" ;;
	AE*) NAMESPACE="default" ;;
	esac
}

get_running_ae_pods() {
	kubectl --server="$API_SERVER" --token=$TOKEN --certificate-authority=$CACERT get pods --no-headers | grep -E 'cp|wp' | awk '$3 == "Running" {print $1}'
}

# Identify the AE process name like WP003, given a pod host name like jcp-ws-0-cc5c66d4b-w5f6b.
# Runs in a subshell so trap/temps don't leak into your shell
pod2proc() (
  local UC4_Log_Dir="${UC4_Log_Dir:?UC4_Log_Dir not set}"
  shopt -s nullglob
  export LC_ALL=C

  # temp files; auto-clean
  pods_cp="$(mktemp -t pods_cp.XXXXXX)" || { echo "mktemp failed" >&2; exit 1; }
  pods_wp="$(mktemp -t pods_wp.XXXXXX)" || { echo "mktemp failed" >&2; exit 1; }
  awk_prog="$(mktemp -t awk_prog.XXXXXX)" || { echo "mktemp failed" >&2; exit 1; }
  trap 'rm -f "$pods_cp" "$pods_wp" "$awk_prog"' EXIT

  # classify pods by name
  while IFS= read -r pod; do
    case "$pod" in
      jcp-*|jcp-ws*|*cp-*) printf '%s\n' "$pod" >>"$pods_cp" ;;
      jwp-*|*wp-*)         printf '%s\n' "$pod" >>"$pods_wp" ;;
    esac
  done

  # write the awk program to a file (no shell quoting inside)
  cat >"$awk_prog" <<'AWK'
FNR==NR { pods[$0]=1; next }
# Parse only lines mentioning U00003492; extract pod from "Host '<pod>'"
# Keep the last seen proc per pod.
#/U00003492/ { ... } is fine even on BusyBox awk
/U00003492/ {
  # find start of "Host '"
  start = index($0, "Host '"); if (start == 0) next
  rest  = substr($0, start + 6)      # after "Host '"
  stop  = index(rest, "'"); if (stop == 0) next
  pod = substr(rest, 1, stop - 1)
  if (!(pod in pods)) next

  # extract proc number from filename: ..._024_00.txt
  n = split(FILENAME, pf, "/"); base = pf[n]
  gsub(/[.]/, "_", base)             # WPsrv_log_024_00_txt
  split(base, a, "_")                # a[3] == "024"
  proc = a[3]; if (proc == "") next

  last[pod] = proc
}
END {
  for (p in last) print p, last[p]   # "pod proc"
}
AWK

  scan_type() {
    local type="$1" pods_file="$2"
    [ -s "$pods_file" ] || return 0
    # only this type’s files
    local files=( "$UC4_Log_Dir/${type}srv_log_"[0-9][0-9][0-9]"_00.txt" )
    ((${#files[@]})) || return 0
    awk -f "$awk_prog" "$pods_file" "${files[@]}"
  }

  {
    scan_type "CP" "$pods_cp"
    scan_type "WP" "$pods_wp"
  } |
  # convert "pod proc" -> "TypeProc" using pod-derived type
  awk '
    {
      pod=$1; proc=$2
      if (substr(pod,1,4)=="jcp-" || substr(pod,1,6)=="jcp-ws" || index(pod,"cp-"))      print "CP" proc;
      else if (substr(pod,1,4)=="jwp-" || index(pod,"wp-"))                               print "WP" proc;
    }
  ' | sort
)

# Fetch list of running AE pods using kubectl and associated AE process names.
# This is an alternative to looking at recent 00-generation log files.
# TODO: Find a way to speed this up. It's currenly slower than just looking at logs.
get_ae_pods() {
	# Collect pairs as: "<proc>\t<pod>", then sort by proc and print both.
	pods=()
	pairs=()
	# get only Running pods whose names contain cp or wp
	while IFS= read -r pod; do
		pods+=("$pod")
		# Find the AE process name from logs
		proc="$(echo $pod | pod2proc)"
		# Store a sortable pair: "proc<TAB>pod"
		pairs+=("$proc"$'\t'"$pod")
	done < <(
		kubectl --server="$API_SERVER" --token="$TOKEN" --certificate-authority="$CACERT" get pods --no-headers |
			awk '$3=="Running"{print $1}' |
			grep -E '(^|.*)(cp|wp)(-|$)'
	)
}

# List running AE pods, sorted by name.
ae_pods() {
	(( ${#pairs[@]} )) || get_ae_pods
	# Sort by process (field 1) and print as "pod process"
	printf '%s\n' "${pairs[@]}" |
		LC_ALL=C sort -t $'\t' -k1,1 |
		awk -F $'\t' '{printf "%s %s\n", $1, $2}'
}

find_pod_by_proc() {
	local search_proc="$1"
	local line proc pod
	for line in "${pairs[@]}"; do
		IFS=$'\t' read -r proc pod <<<"$line"
		if [[ "$proc" == "$search_proc" ]]; then
			echo "$pod"
			return 0
		fi
	done
	# not found
	return 1
}

# Search logs one by one, from most recent to oldest.
search_logs() {
	if [[ $# -lt 2 ]]; then
		echo "Please specify an AE process type and search string."
		return 1
	fi
	local proc_type=$1
	local search_string=$2
	local grep_options=$3
	local proc_num=$4
	local max_index=$5
	local max_age=$6
	local grep_output=""
	if [[ -z "$grep_options" ]]; then grep_options="-E"; fi
	if [[ -z "$proc_num" ]]; then proc_num="???"; fi
	if [[ -z "$max_index" ]]; then max_index=10; fi
	if [[ -z "$max_age" ]]; then max_age=28800; fi
	log_prefix="${proc_type}srv_log_${proc_num}_"
	log_suffix=".txt"
	for i in $(seq -w 00 $max_index); do
		file="${log_prefix}${i}${log_suffix}"
		grep_output=""
		grep_output=$(find ${UC4_Log_Dir} -name "$file" -maxdepth 1 -type f -mmin "-$max_age" -exec grep "$grep_options" "$search_string" {} \; 2>/dev/null)
		if [[ -n "$grep_output" ]]; then
			echo "$grep_output"
			break
		fi
	done
}

uc4_server() {
	local Server_Name=$(echo $Server_Info | cut -d"'" -f2 | cut -d'#' -f1)
	echo "$Server_Name"
}

# Get a list of active processes by listing all recent 00-generation logs whose last message is not U00003401 or U00003410.
ae_logs() {
	local Proc_Type=$1
	local Log_Prefix
	case $Proc_Type in
	WP|CP) Log_Prefix="$Proc_Type";;
	*) Log_Prefix=\?P;;
	esac
	local running="yes"
	local logfile=""
	while read -rs logfile; do
	# If one of these messages appears near the end of the log, the process is probably stopped.
		tail -n 15 "$logfile" | grep -E 'U00003401|U00003410|U00003432' >/dev/null 2>&1
		if [[ $? -eq 1 ]]; then
			echo $logfile
		fi
	done < <(find ${UC4_Log_Dir} -maxdepth 1 -type f -name ${Log_Prefix}srv_log_\?\?\?_00.txt -mmin -96000 | sort)
}

# Take log file paths and extract just the AE process names, e.g., 'WP002'
log2proc() {
	local Proc_Log=""
	(
		while IFS= read -r Proc_Log; do
			local Log_Basename=$(basename "$Proc_Log")
			local Proc_Type="${Log_Basename:0:2}"
			local Proc_Num="$(echo ${Log_Basename} | cut -d'_' -f 3)"
			local Proc_Name="${Proc_Type}${Proc_Num}"
			echo "${Proc_Name}"
		done <<<"$1"
	) | sort
}

# Get a list of of AE server processes, based on log file names.
ae_proc() {
	log2proc "$(ae_logs)"
}

# Identify the Primary Work Process (PWP)
pwp() {
	local pwp1=$(grep 'PWP  \*' ${UC4_Log_Dir}/WPsrv_log_???_00.txt | cut -d'#' -f2 | cut -d' ' -f1)
	if [[ $pwp1 == "" ]]; then
		search_logs "WP" "U00003475|U00011818" "-E" '???' 10 100000 | sort -t ':' -k 2 | tail -1 | cut -d"'" -f2 | cut -d# -f2
	else
		echo $pwp1
	fi
}

# Identify the WP with role O (outputs) - there is only one WP with ths role.
owp() {
	search_logs "WP" "U0000334[3|4] .*role.*'O'" '' '???' '10' '648000' | sort | tail -1 | cut -d"'" -f2 | cut -d# -f2
}

# Identify the WP with role R (resource calculations) - there is only one WP with this role.
rwp() {
	search_logs "WP" "U0000334[3|4] .*role.*'R'" '' '???' '10' '648000' | sort | tail -1 | cut -d"'" -f2 | cut -d# -f2
}

# Identify Java work processes (JWPs)
jwp() {
	log2proc "$(search_logs 'WP' 'U02000090' '-l' '???' '00')"
}

# Identify Java communications processes (JCPs) -- NOTE: includes REST processes too.
jcp() {
	log2proc "$(search_logs 'CP' 'U02000090' '-l' '???' '00')"
}

# Identify REST processes (RESTPs)
restp() {
	log2proc "$(search_logs 'CP' 'U00003400 Server .REST API.' '-l' '???' '00')"
}

# Identify Work processes (WPs)
aewp() {
	log2proc "$(search_logs 'WP' 'U02000090' '-L' '???' '00')"
}

# Identify Communications processes (CPs)
aecp() {
	log2proc "$(search_logs 'CP' 'U02000090' '-L' '???' '00')"
}

# Identify Dialog work processes (DWPs)
dwp() {
# New approach
	if [[ -z $WP_Messages ]]; then WP_Messages="$(wp_mode_latest)"; fi
# Original approach:
#	if [[ -z $WP_Messages ]]; then WP_Messages="$(wp_messages)"; fi
	aewp | while IFS= read -r Proc_Name; do
		echo "$WP_Messages" | grep "$Proc_Name" 2>/dev/null | tail -1 | awk '$3 == "DWP" {print $2}'
	done
}

# Identify JWP roles (old way)
jwp2role() {
	if [[ $# -lt 1 ]]; then
		echo "Please provide an AE process name."
		return 1
	fi
	local Proc_Name=$1
	Proc_Name=$(normalizeProcName $Proc_Name)
	Proc_Num="${Proc_Name:2}"
	search_logs 'WP' 'U00045395' '' "$Proc_Num" '10' 200000 | tail -1 | grep -vE '\[\]|\[JWP\]' | sort | tail -1 | grep -oP '\[\K[^\]]+' | sed -E 's/(,)?JWP(,)?//g'
}

# Identify role(s) of a Java Work Processes (new way)
jwp_roles() (
  local wp="${1:-}"
  local code="U00045395"

  if [ -z "$wp" ]; then
    printf 'Usage: jwp_roles WP### (e.g., WP014)\n' >&2
    return 0
  fi
  local num
  if [[ "$wp" =~ ^WP([0-9]{3})$ ]]; then
    num="${BASH_REMATCH[1]}"
  else
    printf 'Invalid WP name: %s (expected WP###, e.g., WP014)\n' "$wp" >&2
    return 0
  fi

  # require gawk
  if ! command -v gawk >/dev/null 2>&1; then
    printf 'gawk not found in PATH.\n' >&2
    return 0
  fi

  # temporary gawk script + output; auto-clean both on return
  local awkfile tmpout
  awkfile="$(mktemp -t jwp_roles.XXXXXX.awk)" || { echo "mktemp failed" >&2; return 0; }
  tmpout="$(mktemp -t jwp_roles.out.XXXXXX)" || { echo "mktemp failed" >&2; rm -f -- "$awkfile"; return 0; }
  trap 'rm -f -- "$awkfile" "$tmpout"' RETURN

  # gawk script: keep last matching roles line; drop JWP; print (even if empty) at END
  cat >"$awkfile" <<'AWK'
# Keep the last "Assigned roles: [...]" for the given code; remove JWP; print once.
{
  sub(/\r$/, "", $0)  # strip CR if present
  if (index($0, code) == 0) next
  if (match($0, /Assigned[ \t]+roles:[ \t]*\[([^\]]*)\]/, m)) {
    s = m[1]
    gsub(/[ \t]+/, "", s)                         # remove whitespace inside payload
    s = gensub(/(^|,)JWP(,|$)/, "\\1\\2", "g", s) # delete JWP token in any comma position
    gsub(/,,+/, ",", s)                           # collapse multiple commas
    sub(/^,/, "", s); sub(/,$/, "", s)            # trim edge commas
    found = 1
    out = s
  }
}
END {
  if (found) print out           # prints newline even if out is empty (only JWP present)
}
AWK

  # newest → oldest; stop after first file that yields a match
  local g file
  for g in 00 01 02 03 04 05 06 07 08 09 10; do
    file="${UC4_Log_Dir}/WPsrv_log_${num}_${g}.txt"
    [ -f "$file" ] || continue

    # Run gawk on the file; ignore exit status; detect success by output bytes.
    LC_ALL=C gawk -v code="$code" -f "$awkfile" -- "$file" >"$tmpout" 2>/dev/null || :

    # If gawk matched, it always prints a line (possibly blank). Newline => size > 0.
    if [ -s "$tmpout" ]; then
      cat "$tmpout"
      return 0
    fi
  done

  # no match in any generation: print nothing, exit 0 (safe with set -e shells)
  return 0
)


# Take names like 'wp2' and convert them to a standard format like 'WP002'.
normalizeProcName() {
	local Proc_Name=$1
	Proc_Name=$(echo "$Proc_Name" | tr [:lower:] [:upper:])
	Proc_Type="${Proc_Name:0:2}"
	Proc_Num="${Proc_Name:2}"
	case $Proc_Type in @(CP|WP)) ;; *)
		echo "ERROR: Process type must be CP or WP." >&2
		return 1
		;;
	esac
	if [[ ${#Proc_Num} -eq 1 ]]; then
		Proc_Num="00$Proc_Num"
	elif [[ ${#Proc_Num} -eq 2 ]]; then
		Proc_Num="0$Proc_Num"
	fi
	Proc_Name="${Proc_Type}${Proc_Num}"
	echo "$Proc_Name"
}

# Take AE process names like 'WP002', and generate pathnames to the most recent (00) log.
proc2log() {
	if [[ $# -lt 1 ]]; then
		echo "Please provide an AE process name."
		return 1
	fi
	while IFS= read -r Proc_Name; do
		local Proc_Name=$(normalizeProcName $Proc_Name)
		local Proc_Type="${Proc_Name:0:2}"
		local Proc_Num="${Proc_Name:2}"
		local Proc_Log="${UC4_Log_Dir}/${Proc_Type}srv_log_${Proc_Num}_00.txt"
		echo "$Proc_Log"
	done <<<"$1"
}

# Take an AE process name, and print a list of all of the logs for this process.
proc2logs() {
	if [[ $# -lt 1 ]]; then
		echo "Please provide an AE process name."
		return 1
	fi
	while IFS= read -r Proc_Name; do
		local Proc_Name=$(normalizeProcName $Proc_Name)
		local Proc_Type="${Proc_Name:0:2}"
		local Proc_Num="${Proc_Name:2}"
		ls ${UC4_Log_Dir}/${Proc_Type}srv_log_${Proc_Num}_*.txt 2>/dev/null | sort -V
	done <<<"$1"
}

# Take AE process names like 'WP002', and look up the host/pod name.
proc2host() {
	if [[ $# -lt 1 ]]; then
		echo "Please provide an AE process name."
		return 1
	fi
	local Proc_Name=""
	local Proc_Type=""
	local Proc_Num=""
	local Host_Name=""
	while IFS= read -r Proc_Name; do
		Proc_Name=$(normalizeProcName $Proc_Name)
		Proc_Type="${Proc_Name:0:2}"
		Proc_Num="${Proc_Name:2}"
		# Example message: U00003492 Server has been started on Host 'ae-wp-5bb4d7c578-rhhfn'
		Host_Name=$(grep 'U00003492' ${UC4_Log_Dir}/${Proc_Type}srv_log_${Proc_Num}_00.txt | cut -d\' -f 2 | grep '[A-Za-z]' | sort | tail -1)
		# If the pod/host name doesn't appear in the 00 log, look in all the logs for this process.
		# Example message: U02000066 Host information: Host name='jwp-54dc97b7cc-mc45m', IP address='10.0.0.1'
		if [[ -z "$Host_Name" ]]; then
			Host_Name=$(grep 'U02000066' ${UC4_Log_Dir}/${Proc_Type}srv_log_${Proc_Num}_00.txt | cut -d\' -f 2 | grep '[A-Za-z]' | sort | tail -1)

		fi
		echo "$Host_Name"
	done <<<"$1"
}

pod2type() {
	if [[ $# -lt 1 ]]; then
		echo "Please provide an AE pod name."
		return 1
	fi
	local Proc_Host=""
	while IFS= read -r Proc_Host; do
		local Proc_Type=""
		case "$Proc_Host" in
		jcp-rest*) Proc_Type="REST" ;;
		jcp-ws*) Proc_Type="JCP" ;;
		jwp-*) Proc_Type="JWP" ;;
		*wp-*) Proc_Type="WP" ;;
		*cp-*) Proc_Type="CP" ;;
		esac
	done <<<"$1"
	echo "$Proc_Type"
}

uc4ts2epoch() {
	local uc4ts="$1"
	local epoch
	epoch=$(echo "$uc4ts" | sed -E 's|^([0-9]{4})([0-9]{2})([0-9]{2})/([0-9]{2})([0-9]{2})([0-9]{2})\..*$|\1-\2-\3 \4:\5:\6|')
	date -d "$epoch" +%s 2>/dev/null || echo 0
}

# Return log file age in days
log_age() {
	if [[ $# -lt 1 ]]; then
		echo "Please provide a log file path."
		return 1
	fi
	local log_file=$1
	local log_date=$(tail -1 "$Proc_Log" | cut -d' ' -f1 | cut -d'/' -f1)
	local diff=$((($(date +%s) - $(date -d "$log_date" +%s)) / 86400))
	echo "$Proc_Log"
}

wp_messages() {
	# This function collects both WP start messages and WP mode change messages.
	# This brute-force approach was devised to identify DWPs.
	# Collect both WP start messages and WP mode change messages.
	local -a messages=()
	local Message_Timestamp_Epoch Message_Timestamp WP_Name WP_Mode
	local WP_Start_Message WP_ModeChange_Message
	# Collect WP start messages. (When WPs start, they are normal WPs by default.)
	while IFS= read -r WP_Start_Message; do
		if [[ $(echo $WP_Start_Message | tr -cd '-' | wc -c) -eq 2 ]]; then
			Message_Timestamp=$(echo $WP_Start_Message | awk -F' - ' '{print $2}')
		else
			Message_Timestamp=$(echo $WP_Start_Message | awk -F' - ' '{print $1}' | cut -d':' -f 2)
		fi
		# Convert to epoch
		Message_Timestamp_Epoch=$(uc4ts2epoch "$Message_Timestamp")
		WP_Name="WP$(echo $WP_Start_Message | cut -d'_' -f 3)"
		WP_Mode="WP"
		# Build message
		messages+=("$Message_Timestamp_Epoch $WP_Name $WP_Mode") # Add message to list

	done < <(grep U00003400 ${UC4_Log_Dir}/WPsrv_log_???_00.txt 2>/dev/null | grep '#WP' 2>/dev/null)
	# Collect WP mode change messages
	while IFS= read -r WP_ModeChange_Message; do
		if [[ $(echo $WP_ModeChange_Message | tr -cd '-' | wc -c) -eq 2 ]]; then
			Message_Timestamp=$(echo $WP_ModeChange_Message | awk -F' - ' '{print $3}')
		else
			Message_Timestamp=$(echo $WP_ModeChange_Message | awk -F' - ' '{print $1}' | cut -d':' -f 2)
		fi
		# Convert to epoch
		Message_Timestamp_Epoch=$(uc4ts2epoch "$Message_Timestamp")
		WP_Name=$(echo $WP_ModeChange_Message | awk -F"#|'" '{print $3}')
		WP_Mode=$(echo $WP_ModeChange_Message | cut -d"'" -f 6)
		# Build message
		messages+=("$Message_Timestamp_Epoch $WP_Name $WP_Mode") # Add message to list
	done < <(egrep "U00003389 Server.*WP.*DWP|U00003389 Server.*DWP.*WP" ${UC4_Log_Dir}/WPsrv_log_???_*.txt 2>/dev/null)
	# --- Sort numerically by epoch time and remove duplicates ---
	printf '%s\n' "${messages[@]}" | sort -n -k1,1
}

# New function for collecting the latest mode of each WP.
# TODO: Exclude non-running WPs! Use ae_logs function or similar approach.
wp_mode_latest() (
  local dir="${UC4_Log_Dir:?set UC4_Log_Dir}"
  gawk -v tz="${UC4_LOG_TZ:-local}" '
    BEGIN {
      if (tz == "UTC") PROCINFO["TZ"] = "UTC"
      # Regex for UC4 timestamp like 20251107/000037.386
      tsre = "^[0-9]{8}/[0-9]{6}\\.[0-9]{3}"
    }

    # Extract the effective timestamp:
    # - If line begins "TS1 - TS2 - ", use TS2.
    # - Else if it begins "TS1 - ", use TS1.
    function extract_ts(line, m) {
      if (match(line, /^(([0-9]{8}\/[0-9]{6}\.[0-9]{3})) - (([0-9]{8}\/[0-9]{6}\.[0-9]{3})) - /, m))
        return m[4];     # TS2
      if (match(line, /^(([0-9]{8}\/[0-9]{6}\.[0-9]{3})) - /, m))
        return m[2];     # TS1
      # Fallback: first token if it looks like a TS
      split(line, a, /[[:space:]]+/)
      return (a[1] ~ tsre) ? a[1] : ""
    }

    # Convert "YYYYMMDD/HHMMSS.mmm" -> epoch_ms
    function ts2epoch_ms(ts, d, t, ms, epoch) {
      if (ts == "") return 0
      split(ts, d, "/")            # d[1]=YYYYMMDD, d[2]=HHMMSS.mmm
      split(d[2], t, ".")          # t[1]=HHMMSS, t[2]=mmm
      ms = (t[2] ~ /^[0-9]+$/) ? t[2]+0 : 0
      epoch = mktime( \
        substr(d[1],1,4) " " substr(d[1],5,2) " " substr(d[1],7,2) " " \
        substr(t[1],1,2) " " substr(t[1],3,2) " " substr(t[1],5,2) )
      return epoch*1000 + ms
    }

    # Keep only the newest timestamp (string compare OK for this format)
    function update(ts, wp, mode) {
      if (ts == "") return
      if (!(wp in ts_latest) || ts >= ts_latest[wp]) {
        ts_latest[wp]  = ts
        mode_latest[wp]= mode
      }
    }

    # ----- Start messages -----
    # Examples (1 or 2 timestamps at the front):
    # 20251021/074019.842 - U00003400 Server 'UC4_EXP2#WP' ... started.
    # 20251107/000037.386 - 20251030/095107.720 - U00003400 Server 'UC4_EXP#WP' ... started.
    /U00003400/ && /#WP/ {
      ts = extract_ts($0)
      # filename like WPsrv_log_019_00.txt → take the 3rd underscore field
      split(FILENAME, f, /_/); wp = "WP" f[3]
      update(ts, wp, "WP")
      next
    }

    # ----- Mode changes -----
    #  (works with 1 or 2 timestamps at the front)
    /U00003389 Server/ && /has changed its mode/ {
      ts = extract_ts($0)
      if (!match($0, /#(WP[0-9]+)/, m)) next
      wp = m[1]
      # Extract target mode (the RHS of "from X to Y")
      if      (match($0, /to '\''(WP|DWP)'\''/, mt)) mode = mt[1]
      else if (match($0, /from '\''(WP|DWP)'\'' to '\''(WP|DWP)'\''/, mf)) mode = mf[2]
      else next
      update(ts, wp, mode)
      next
    }

    END {
      for (wp in ts_latest) {
        epoch_ms = ts2epoch_ms(ts_latest[wp])
        key = sprintf("%013.0f-%s", epoch_ms, wp)
        rec[key] = epoch_ms " " wp " " mode_latest[wp]
      }
      n = asorti(rec, idx)
      for (i=1; i<=n; i++) print rec[idx[i]]
    }
  ' "$dir"/WPsrv_log_???_*.txt 2>/dev/null
)

#### Functions for enqueuing and applying pod label changes.
# -------- Internal state (globals) --------
declare -ag __POD_LIST=()
declare -Ag __POD_NS=()     # per-pod namespace: __POD_NS["pod"]="ns"
declare -Ag __POD_LABELS=() # per-pod labels:   __POD_LABELS["pod|key"]="value"

# kubectl connection defaults (optional)
__KUBE_NS=""
__KUBE_SERVER=""
__KUBE_TOKEN=""
__KUBE_CACERT=""

# ---------- Helpers ----------
__yaml_quote() {
	local v="$1"
	printf "'%s'" "${v//\'/''}"
}

k8s_labels_init() {
	# Optional: set defaults used by k8s_labels_emit when applying
	# Usage: k8s_labels_init [-n ns] [--server URL] [--token TOKEN] [--cacert PATH]
	__POD_LIST=()
	__POD_NS=()
	__POD_LABELS=()
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-n | --namespace)
			__KUBE_NS="$2"
			shift 2
			;;
		--server)
			__KUBE_SERVER="$2"
			shift 2
			;;
		--token)
			__KUBE_TOKEN="$2"
			shift 2
			;;
		--cacert | --certificate-authority)
			__KUBE_CACERT="$2"
			shift 2
			;;
		*)
			echo "k8s_labels_init: unknown arg: $1" >&2
			return 1
			;;
		esac
	done
}

k8s_labels_add() {
	# Enqueue one pod + its labels (call this as many times as you like)
	# Usage:
	#   k8s_labels_add --pod POD [-n NS] key1=val1 key2=val2 ...
	#   k8s_labels_add --pod POD [-n NS] --label key=val --label key=val ...
	local pod="" ns=""
	local -a kvs=()
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--pod)
			pod="$2"
			shift 2
			;;
		-n | --namespace)
			ns="$2"
			shift 2
			;;
		--label)
			kvs+=("$2")
			shift 2
			;;
		*=*)
			kvs+=("$1")
			shift
			;;
		*)
			echo "k8s_labels_add: unknown arg: $1" >&2
			return 1
			;;
		esac
	done
	[[ -z "$pod" ]] && {
		echo "k8s_labels_add: --pod is required" >&2
		return 1
	}

	# append pod once
	local seen=""
	for p in "${__POD_LIST[@]}"; do [[ "$p" == "$pod" ]] && {
		seen=1
		break
	}; done
	[[ -z "$seen" ]] && __POD_LIST+=("$pod")
	[[ -n "$ns" ]] && __POD_NS["$pod"]="$ns"

	# store labels
	local kv k v
	for kv in "${kvs[@]}"; do
		k="${kv%%=*}"
		v="${kv#*=}"
		if [[ -z "$k" ]]; then
			echo "k8s_labels_add: empty label key in '$kv'" >&2
			return 1
		fi
		__POD_LABELS["$pod|$k"]="$v"
	done
}

k8s_labels_emit() (
	# Generate YAML for all enqueued pods; either write it or apply it.
	# Usage:
	#   k8s_labels_emit --out labels.yaml
	#   k8s_labels_emit --apply [--force-conflicts]
	# Optional kube args override init defaults: -n, --server, --token, --cacert
	local out_file="" do_apply=""
	local force_conflicts="false"
	local ns="${__KUBE_NS}" server="${__KUBE_SERVER}" token="${__KUBE_TOKEN}" cacert="${__KUBE_CACERT}"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--out)
			out_file="$2"
			shift 2
			;;
		--apply)
			do_apply="yes"
			shift
			;;
		--force-conflicts)
			force_conflicts="true"
			shift
			;;
		--verbose)
			verbose="true"
			shift
			;;
		-n | --namespace)
			ns="$2"
			shift 2
			;;
		--server)
			server="$2"
			shift 2
			;;
		--token)
			token="$2"
			shift 2
			;;
		--cacert | --certificate-authority)
			cacert="$2"
			shift 2
			;;
		*)
			echo "k8s_labels_emit: unknown arg: $1" >&2
			return 1
			;;
		esac
	done

	[[ ${#__POD_LIST[@]} -eq 0 ]] && {
		echo "k8s_labels_emit: no pods enqueued" >&2
		return 1
	}

	# choose output target
	local tmp
	if [[ -n "$out_file" ]]; then
		tmp="$out_file"
	else
		tmp="$(mktemp)"
		trap 'rm -f "$tmp"' EXIT
	fi

	# build YAML (multi-doc)
	: >"$tmp"
	local pod k v pod_ns had_labels
	for pod in "${__POD_LIST[@]}"; do
		had_labels=0
		for k in "${!__POD_LABELS[@]}"; do
			[[ "$k" == "$pod|"* ]] && {
				had_labels=1
				break
			}
		done
		[[ $had_labels -eq 0 ]] && continue

		pod_ns="${__POD_NS[$pod]:-$ns}"

		{
			echo 'apiVersion: v1'
			echo 'kind: Pod'
			echo 'metadata:'
			printf '  name: %s\n' "$pod"
			[[ -n "$pod_ns" ]] && printf '  namespace: %s\n' "$pod_ns"
			echo '  labels:'
			# emit labels for this pod
			for k in "${!__POD_LABELS[@]}"; do
				[[ "$k" == "$pod|"* ]] || continue
				v="${__POD_LABELS[$k]}"
				printf '    %s: %s\n' "${k#*|}" "$(__yaml_quote "$v")"
			done
			echo '---'
		} >>"$tmp"
	done

	# If only writing a file, stop here.
	if [[ -n "$out_file" && -z "$do_apply" ]]; then
		echo "✅ Wrote YAML for ${#__POD_LIST[@]} pod(s) to: $out_file"
		return 0
	fi

	# Apply once (server-side)
	local -a K=(kubectl)
	[[ -n "$ns" ]] && K+=(-n "$ns")
	[[ -n "$server" ]] && K+=(--server="$server")
	[[ -n "$token" ]] && K+=(--token="$token")
	[[ -n "$cacert" ]] && K+=(--certificate-authority="$cacert")

	local -a APPLY=(apply --server-side -f "$tmp")
	[[ "$force_conflicts" == "true" ]] && APPLY+=(--force-conflicts)

	echo "🚀 Applying labels…"
	if [[ "$verbose" == "true" ]]; then
		"${K[@]}" "${APPLY[@]}"
	else
		"${K[@]}" "${APPLY[@]}" >/dev/null
	fi
	if [[ $? -eq 0 ]]; then echo "✅ Done"; fi
)

k8s_labels_clear() {
	__POD_LIST=()
	__POD_NS=()
	__POD_LABELS=()
}

label_pod() {
	if [[ $# -ne 5 ]]; then
		echo "Usage: label_pod <pod_name> <ae process name> <type> <role(s)> <log>"
		return 1
	fi
	pod=$1
	proc=$2
	type=$3
	role=$4
	log=$5
kubectl patch pod $pod -p "{\"metadata\":{\"labels\":{\"proc\":\"$proc\",\"type\":\"$type\",\"role\":\"$role\",\"log\":\"$log\"}}}" --token=$TOKEN --server=$API_SERVER --certificate-authority=$CACERT
}

# Display information about running AE server processes, gleaned from logs.
ae() {
	echo "AAKE Debug Tools version: $AAKE_Debug_Tools_Version"
	if [[ "$kubectl_available" == "true" ]] && [[ $label_pods == "true" ]]; then
		local run_kubectl_apply="true"
	fi
	ae_counter=0
	if [[ $# -eq 0 ]]; then
		Proc_List="$(ae_proc)"
	elif [[ $# -eq 1 ]]; then
		Proc_List=$(normalizeProcName $1)
		if [[ ! -f $(proc2log "$Proc_List") ]]; then
			echo "There is no log for AE process ${Proc_List}. Is it running?"
			return 1
		fi
	elif [[ $# -gt 1 ]]; then
		echo "Usage: ae [process name]"
		return 1
	fi
	#Server_Uptime=$(echo $Server_Info | cut -d"'" -f6 )
	printf "%-20s %-32s %s\n" "Server" "Version"                          # "Uptime"
	printf "%-22s %-32s %s\n" "$ENV_COLOR $Server_Name" "$Server_Version" # "$Server_Uptime"
	echo
	# Create extended globbing lists of processes of each type.
	if [[ -z $CP ]]; then CP="@("$(aecp | paste -sd'|' -)")"; fi
	if [[ -z $WP ]]; then WP="@("$(aewp | paste -sd'|' -)")"; fi
	if [[ -z $PWP ]]; then PWP="@("$(pwp | paste -sd'|' -)")"; fi
	if [[ -z $OWP ]]; then OWP="@("$(owp | paste -sd'|' -)")"; fi
	if [[ -z $RWP ]]; then RWP="@("$(rwp | paste -sd'|' -)")"; fi
	if [[ -z $DWP ]]; then DWP="@("$(dwp | paste -sd'|' -)")"; fi
	if [[ -z $JWP ]]; then JWP="@("$(jwp | paste -sd'|' -)")"; fi
	if [[ -z $JCP ]]; then JCP="@("$(jcp | paste -sd'|' -)")"; fi
	if [[ -z $RESTP ]]; then RESTP="@("$(restp | paste -sd'|' -)")"; fi
	if [[ "$run_kubectl_apply" == "true" ]]; then
		k8s_labels_init --namespace $NAMESPACE --server $API_SERVER --token $TOKEN --cacert $CACERT
	fi
	for Proc_Name in $Proc_List; do
		((ae_counter++))
		local Proc_Type=""
		local Host_Name=""
		local Proc_Log=""
		local Proc_Role=""
		local Proc_Type1=""
		local Proc_Log=$(proc2log "$Proc_Name")
		local Host_Name=$(proc2host $Proc_Name)
		if [[ -n "$Host_Name" ]]; then
			Proc_Type=$(pod2type $Host_Name)
		else
			Host_Name="unknown"
			Proc_Type="unknown"
		fi
		# Secondary method of determining process type based on messages logged at process start.
		if [[ "$Proc_Type" == 'unknown' ]]; then
			case $Proc_Name in
			$CP) Proc_Type="CP" ;;
			$WP) Proc_Type="WP" ;;
			$JWP) Proc_Type="JWP" ;;
			$JCP) Proc_Type="JCP" ;;
			$RESTP) Proc_Type="RESTP" ;;
			esac
		fi
		# Tertiary method
		# TODO: Somehow identify using kubectl? It's not clear how this would work.
		#if [[ "$Proc_Type" == 'unknown' ]]; then
		#	echo "Process type could not be identified."
		#fi
		# If the process type is still unknown, this can be because the process is no longer running,
		# or because it has not written to its log file in a very long time. If the ae script was called
		# with a single argument (a process name), print the age in days of the log file.
		if [[ "$Proc_Type" == 'unknown' ]] && [[ $# -eq 1 ]]; then
			local log_age="$(log_age $Proc_Log)"
			echo "The log file $Proc_Log was last modified $diff days ago."
		fi
		Proc_Type1=$Proc_Type
		# Handle special processes like PWP, OWP, RWP, and DWP.
		case $Proc_Name in
		$PWP)
			Proc_Type="PWP*"
			Proc_Role="P"
			;;
		$OWP)
			Proc_Type="OWP+"
			Proc_Role="O"
			;;
		$RWP)
			Proc_Type="RWP+"
			Proc_Role="R"
			;;
		$DWP)
			Proc_Type="DWP"
			Proc_Role="D"
			;;
		esac
		# Handle JWP roles
		if [[ "$Proc_Type" == 'JWP' ]]; then
			JWP_Role=""
			JWP_Role="$(jwp_roles $Proc_Name)"
			if [[ ! "$JWP_Role" == "" ]]; then
				Proc_Type="JWP-$JWP_Role"
				Proc_Role=$(echo $JWP_Role | sed -E 's/,/-/g')
			fi
		fi
		# Print header
		if [[ $ae_counter -eq 1 ]]; then
			printf "%-8s %-11s %-42s %s\n" "AE Proc" "Type/Role" "Host name" "Log file"
		fi
		# Print output
		printf "%-8s %-11s %-42s %s\n" "$Proc_Name" "$Proc_Type" "$Host_Name" "$Proc_Log"
		# Add label to pod in Kubernetes if kubectl is available.
		if [[ "$run_kubectl_apply" == "true" ]]; then
			Proc_Log1=$(basename $Proc_Log)
			k8s_labels_add --pod "$Host_Name" proc="$Proc_Name" type="$Proc_Type1" role="$Proc_Role" log="$Proc_Log1"
		fi
	done
	if [[ "$run_kubectl_apply" == "true" ]]; then
		k8s_labels_emit --apply --force-conflicts
		k8s_labels_clear
	fi
}

# Reset lists cached in shell environment variables.
aereset() {
	CP=""
	WP=""
	PWP=""
	OWP=""
	RWP=""
	DWP=""
	JWP=""
	JCP=""
	RESTP=""
	WP_Messages=""
	PWP_Log=""
}

echo "AAKE Debug Tools version: $AAKE_Debug_Tools_Version"

# Collect basic info about the UC4 system
if [[ -z $PWP_Log ]]; then
	PWP_Log=$(proc2log $(pwp))
	Server_Info=$(grep -E 'U00003380|U00003400' "$PWP_Log")
	Server_Name=$(echo $Server_Info | cut -d"'" -f2 | cut -d'#' -f1)
	Server_Version=$(echo $Server_Info | cut -d"'" -f4)
fi
set_env_values
# Check whether kubectl is available.
if [[ -x $(which kubectl) ]]; then
	kubectl_available="true"
fi
