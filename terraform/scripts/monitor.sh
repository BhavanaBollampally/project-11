#!/usr/bin/bash
#Author: Bhavana_System
#Task9:System monitor with logging and deletion of old files
 



Time_stamp=$(date +"%Y-%m-%d %H:%M:%S") 
file_stamp=$(date +"%Y-%m-%d_%H-%M-%S") 
RETENTION_DAYS=7 
LOG_DIR=./log_monitor/ 
mkdir -p "$LOG_DIR" 
LOG_FILE=$LOG_DIR/"$file_stamp"_log_file.log 
DEL_LOG_FILE=$LOG_DIR/"$file_stamp"_log_del_file.log 

#Threshhold values

THRESHOLD_CPU=80
THRESHOLD_MEMORY=85
THRESHOLD_DISK=80



cpu_check() {
    cpu_usage=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}')
    cpu_used=$(printf "%0.f" "$cpu_usage")
    if [ "$cpu_used" -ge "$THRESHOLD_CPU" ]
    then
    echo "CPU usage is CRITICAL...."
    return 2
    elif (( $cpu_used < $THRESHOLD_CPU )) && (( $cpu_used > 60 ))
    then
    echo "Warning!! Cpu usage is high..."
    return 1
    else
    echo "CPU usage is Normal..."
    return 0
    fi
}
cpu_check
status_cpu=$?
if [ "$status_cpu" -eq 0 ]
then
status1=OK
elif [ "$status_cpu" -eq 1 ]
then
status1=WARN
else
status1=CRITICAL
fi

memory_check() {
    memory_usage=$(free | awk '/Mem:/ {printf "%.2f", $3/$2 * 100}')
    memory_used=${memory_usage%.*}

    if [ "$memory_used" -ge "$THRESHOLD_MEMORY" ]
    then
    echo "Memory usage is CRITICAL...."
    return 2
    elif (( $memory_used < $THRESHOLD_MEMORY )) && (( $memory_used > 60 ))
    then
    echo "Warning!! Memory usage is high..."
    return 1
    else
    echo "Memory usage is Normal..."
    return 0
    fi
}

memory_check
status_memory=$?
if [ "$status_memory" -eq 0 ]
then
status2=OK
elif [ "$status_memory" -eq 1 ]
then
status2=WARN
else
status2=CRITICAL
fi

disk_check() {
    disk_used=$(df -h / | awk 'NR==2 {gsub("%",""); print $5}')

    if [ "$disk_used" -ge "$THRESHOLD_DISK" ]
    then
    echo "disk usage is CRITICAL...."
    return 2
    elif (( $disk_used < $THRESHOLD_DISK )) && (( $disk_used > 60 ))
    then
    echo "Warning!! disk usage is high..."
    return 1
    else
    echo "disk usage is Normal..."
    return 0
    fi
}

disk_check
status_disk=$?
if [ "$status_disk" -eq 0 ]
then
status3=OK
elif [ "$status_disk" -eq 1 ]
then
status3=WARN
else
status3=CRITICAL
fi

if [ "$status_cpu" -eq 2 -o "$status_memory" -eq 2 -o "$status_disk" -eq 2 ]
then
final=CRITICAL
elif [ "$status_cpu" -eq 1 -o "$status_memory" -eq 1 -o "$status_disk" -eq 1 ]
then
final=WARN
else
final=OK
fi

echo "[$Time_stamp] CPU=$cpu_used% | MEM=$memory_used% | DISK=$disk_used% | STATUS=$final " >> "$LOG_FILE"

find "$LOG_DIR" -type f -mtime +"$RETENTION_DAYS" \
-exec bash -c 'echo "[$(date +"%Y-%m-%d %H:%M:%S")] Deleted old log file: {}" >> "$1"' _ "$DEL_LOG_FILE" \; \
-exec rm {} \;

#Trigger cloud upload
# Check if AWS CLI and credentials exist
if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; then
    echo "[INFO] AWS CLI + creds found. Uploading log to S3..."
    DATE=$(date +"%Y/%m/%d")
    aws s3 cp "$LOG_FILE" "s3://bhavana-monitor-logs/$DATE/"
    echo "[SUCCESS] Log uploaded to S3 cloud storage"

else
    echo "[WARN] Cloud upload skipped (no AWS CLI or credentials)."
fi
echo "S3 test upload"
