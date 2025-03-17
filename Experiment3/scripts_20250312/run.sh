#!/bin/bash
# Define paths
GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"
PROJECT_DIR="/home/tommy/cross-architecture/Experiment3/ghidra_projects"
SCRIPT="ExtractPcodeAndFunctionCalls.java"
SCRIPT_PATH="/home/tommy/cross-architecture/Experiment3/scripts_20250312"
BASE_DIR="/home/tommy/cross-architecture/Experiment3"
DATA_DIR="$BASE_DIR/data_20250312"
RESULTS_DIR="$BASE_DIR/results"
LOGS_DIR="$BASE_DIR/logs"
TEMP_DIR="$BASE_DIR/temp_hash"
DATASET_CSV="/home/tommy/datasets/Sorted_Dataset_20250312114058.csv"

# Function to format time in HH:MM:SS
format_time() {
    local seconds=$1
    printf "%02d:%02d:%02d" $((seconds/3600)) $(((seconds%3600)/60)) $((seconds%60))
}

# Default parameters
ALL_FILES=false
CORES=$(nproc)  # 使用所有可用核心
TARGET_CPU=""
TARGET_FAMILY=""
TARGET_COUNT=0
declare -a CPU_LIST=()
declare -a FAMILY_LIST=()
MULTI_TARGET=false

# Add debug functions
debug_log() {
    local message="$1"
    echo "[DEBUG] $(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

debug_show_processes() {
    debug_log "Active Ghidra processes:"
    ps aux | grep ghidra | grep -v grep | tee -a "$LOG_FILE"
    debug_log "Process count: $(ps aux | grep ghidra | grep -v grep | wc -l)"
}

# Function to check CSV file format
debug_check_csv() {
    debug_log "Checking CSV file format:"
    head -n 5 "$DATASET_CSV" | tee -a "$LOG_FILE"
    debug_log "Total lines in CSV: $(wc -l < "$DATASET_CSV")"
}

# Function to display usage
show_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  all                 Process all files"
    echo "  cores=N             Use N cores for processing (default: all system cores)"
    echo "  cpu=ARCHITECTURE    Target specific CPU architecture (e.g., ARM, MIPS)"
    echo "  family=NAME         Target specific malware family"
    echo "  count=N             Number of unique results to collect"
    echo "  multi               Enable multi-target mode for processing multiple CPUs/families"
    echo "  cpus=ARCH1,ARCH2    Comma-separated list of CPU architectures to target"
    echo "  families=FAM1,FAM2  Comma-separated list of malware families to target"
    echo "  data=PATH           Custom data directory path (default: $DATA_DIR)"
    echo ""
    echo "Examples:"
    echo "  $0 cpu=ARM family=mirai count=10 cores=4"
    echo "  $0 multi cpus=ARM,MIPS families=mirai,hajime count=5 cores=4"
}

# Parse command line parameters
for arg in "$@"; do
    case "$arg" in
        all)
            ALL_FILES=true ;;
        multi)
            MULTI_TARGET=true ;;
        cores=*)
            CORES=${arg#cores=} ;;
        cpu=*)
            TARGET_CPU=${arg#cpu=} ;;
        cpus=*)
            IFS=',' read -r -a CPU_LIST <<< "${arg#cpus=}" ;;
        family=*)
            TARGET_FAMILY=${arg#family=} ;;
        families=*)
            IFS=',' read -r -a FAMILY_LIST <<< "${arg#families=}" ;;
        count=*)
            TARGET_COUNT=${arg#count=} ;;
        data=*)
            DATA_DIR=${arg#data=}
            RESULTS_DIR="$BASE_DIR/results" ;;
        help|--help)
            show_usage
            exit 0 ;;
    esac
done

# If we have CPU_LIST or FAMILY_LIST but multi flag is not set, enable it
if [[ ${#CPU_LIST[@]} -gt 0 || ${#FAMILY_LIST[@]} -gt 0 ]]; then
    MULTI_TARGET=true
fi

# If single targets are provided and multi is enabled, add them to lists
if [[ "$MULTI_TARGET" == "true" ]]; then
    if [[ -n "$TARGET_CPU" && ${#CPU_LIST[@]} -eq 0 ]]; then
        CPU_LIST+=("$TARGET_CPU")
        TARGET_CPU=""
    fi
    
    if [[ -n "$TARGET_FAMILY" && ${#FAMILY_LIST[@]} -eq 0 ]]; then
        FAMILY_LIST+=("$TARGET_FAMILY")
        TARGET_FAMILY=""
    fi
fi

# Display configuration
echo "Configuration:"
echo "- Data directory: $DATA_DIR"
echo "- Results directory: $RESULTS_DIR"
echo "- Using $CORES cores for parallel processing"

if [[ "$MULTI_TARGET" == "true" ]]; then
    echo "- Multi-target mode enabled"
    
    if [[ ${#CPU_LIST[@]} -gt 0 ]]; then
        echo "- Targeting CPUs: ${CPU_LIST[*]}"
    else
        echo "- Targeting all available CPUs"
    fi
    
    if [[ ${#FAMILY_LIST[@]} -gt 0 ]]; then
        echo "- Targeting families: ${FAMILY_LIST[*]}"
    else
        echo "- Targeting all available families"
    fi
    
    if [[ $TARGET_COUNT -gt 0 ]]; then
        echo "- Collecting $TARGET_COUNT unique results per CPU-family combination"
    fi
else
    [[ -n "$TARGET_CPU" ]] && echo "- Targeting CPU: $TARGET_CPU"
    [[ -n "$TARGET_FAMILY" ]] && echo "- Targeting family: $TARGET_FAMILY"
    [[ $TARGET_COUNT -gt 0 ]] && echo "- Collecting $TARGET_COUNT unique results"
fi

# Ensure necessary directory structure exists
mkdir -p "$RESULTS_DIR" "$LOGS_DIR" "$PROJECT_DIR" "$TEMP_DIR"

# Log file setup
LOG_FILE="$LOGS_DIR/batch_execution_$(date +%Y%m%d_%H%M%S).log"
echo "===== Batch analysis started $(date '+%Y-%m-%d %H:%M:%S') =====" > "$LOG_FILE"

# Function to calculate MD5 hash of a JSON file
calculate_json_hash() {
    local file="$1"
    # Extract only the pcode and function_calls sections to compare content regardless of metadata
    jq '{pcode, function_calls}' "$file" | md5sum | awk '{print $1}'
}

# Function to check if a result is unique
is_unique_result() {
    local result_file="$1"
    local temp_hash_dir="$2"
    
    # Create hash directory if it doesn't exist
    mkdir -p "$temp_hash_dir"
    
    # Calculate hash for new result
    local hash=$(calculate_json_hash "$result_file")
    local hash_file="$temp_hash_dir/$hash"
    
    # Check if this hash already exists
    if [[ -f "$hash_file" ]]; then
        # Hash exists, result is not unique
        echo "Duplicate result detected: $result_file matches $(cat "$hash_file")" | tee -a "$LOG_FILE"
        return 1
    else
        # Hash is new, record it
        echo "$result_file" > "$hash_file"
        return 0
    fi
}

# Function to process binary files
process_binary() {
    local binary_path="$1"
    local temp_hash_dir="$2"
    local target_count="$3"
    
    local binary_name=$(basename "$binary_path")
    local relative_path=${binary_path#"$DATA_DIR/"}
    local relative_dir=$(dirname "$relative_path")
    local malware_family=$(echo "$relative_dir" | awk -F'/' '{print $1}')
    
    # 创建唯一的项目名
    local project_name="Project_${binary_name}_$(date +%s)_$$"
    local process_log="$LOGS_DIR/process_${binary_name}_$(date +%s)_$$.log"
    
    # 创建结果目录结构，与原始二进制路径匹配
    local result_dir="$RESULTS_DIR/$relative_dir"
    mkdir -p "$result_dir"
    
    # 预先定义结果文件的路径
    local result_file="$result_dir/${binary_name}.json"
    
    {
        echo "===== Processing file: $binary_name =====" 
        echo "Family: $malware_family" 
        echo "Path: $relative_path"
        echo "Expected result file: $result_file"
        echo "Start time: $(date '+%Y-%m-%d %H:%M:%S')" 
        
        "$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$project_name" \
            -import "$binary_path" \
            -postScript "$SCRIPT" "$result_file" \
            -scriptPath "$SCRIPT_PATH" \
            -deleteProject
            
        echo "Completion time: $(date '+%Y-%m-%d %H:%M:%S')" 
        
        # 检查结果文件是否生成
        if [[ -f "$result_file" ]]; then
            echo "Result file successfully generated: $result_file"
        else
            echo "ERROR: Result file not generated: $result_file"
            # 尝试查找脚本可能输出的任何其他文件
            echo "Searching for any output files in the results directory..."
            find "$RESULTS_DIR" -name "*${binary_name}*" -type f
        fi
        echo ""
    } > "$process_log" 2>&1
    
    # 更新主日志
    cat "$process_log" >> "$LOG_FILE"
    echo "Completed processing: $binary_path" | tee -a "$LOG_FILE"
    
    # 检查结果文件是否存在
    if [[ -f "$result_file" ]]; then
        echo "Result file found: $result_file" | tee -a "$LOG_FILE"
        # 检查结果是否唯一（用于目标计数处理）
        if [[ $target_count -gt 0 ]]; then
            if is_unique_result "$result_file" "$temp_hash_dir"; then
                # 计算唯一结果
                unique_count=$(find "$temp_hash_dir" -type f | wc -l)
                echo "Unique results so far: $unique_count/$target_count" | tee -a "$LOG_FILE"
                
                # 检查是否达到目标计数
                if [[ $unique_count -ge $target_count ]]; then
                    echo "Reached target count of $target_count unique results!" | tee -a "$LOG_FILE"
                    # 发出停止处理的信号
                    touch "$temp_hash_dir/COMPLETE"
                fi
            fi
        fi
    else
        echo "Warning: No result file generated for $binary_path" | tee -a "$LOG_FILE"
        # 检查Java脚本是否有错误
        echo "Checking for Java script errors in the log:" | tee -a "$LOG_FILE"
        grep -i "error\|exception" "$process_log" | tee -a "$LOG_FILE"
    fi
}

# Function to get file paths from CSV based on criteria
get_files_from_csv() {
    local target_cpu="$1"
    local target_family="$2"
    local csv_file="$3"
    
    debug_log "Reading CSV file: $csv_file for CPU=$target_cpu, Family=$target_family"
    
    # Print sample CSV content for debugging
    debug_log "Sample CSV content:"
    head -n 3 "$csv_file" | tee -a "$LOG_FILE"
    
    # Skip header line, filter by CPU and family if specified
    awk -F, -v cpu="$target_cpu" -v family="$target_family" '
    NR > 1 {
        if ((cpu == "" || $2 == cpu) && (family == "" || $3 == family)) {
            print $1
        }
    }' "$csv_file"
    
    debug_log "CSV filtering completed"
}

# Parallel processing function
process_in_parallel() {
    local hash_dir="$1"
    local target_count="$2"
    shift 2
    local file_list=("$@")
    local total_files=${#file_list[@]}
    local processed=0
    local start_time=$(date +%s)
    
    echo "Total of $total_files files to process" | tee -a "$LOG_FILE"
    
    # Clear temp hash directory
    mkdir -p "$hash_dir"
    rm -rf "$hash_dir"/*
    
    # Use GNU Parallel if available
    if command -v parallel &> /dev/null; then
        debug_log "Using GNU Parallel for parallel processing with $CORES cores"
        echo "Using GNU Parallel for parallel processing with $CORES cores" | tee -a "$LOG_FILE"
        export -f process_binary calculate_json_hash is_unique_result debug_log
        export GHIDRA_HOME PROJECT_DIR SCRIPT SCRIPT_PATH BASE_DIR DATA_DIR RESULTS_DIR LOG_FILE LOGS_DIR
        
        # Create a temporary file for storing parallel progress output
        local progress_file=$(mktemp)
        debug_log "Progress file created at: $progress_file"
        
        # Add debug info - check first few files before processing
        if [ ${#file_list[@]} -gt 0 ]; then
            debug_log "First file to be processed: ${file_list[0]}"
            debug_log "File exists check: [$([ -f "${file_list[0]}" ] && echo "YES" || echo "NO")]"
        fi
        
        # Use --joblog to track job status
        debug_log "Starting GNU Parallel with $CORES cores and ${#file_list[@]} files"
        parallel --joblog "$TEMP_DIR/parallel_joblog.txt" --progress --eta -j "$CORES" --halt soon,fail=1 '
            [[ -f "'$hash_dir'/COMPLETE" ]] && { 
                echo "Target count reached, skipping further processing";
                exit 0; 
            }; 
            debug_log "Processing file: {}";
            process_binary {} "'$hash_dir'" "'$target_count'"
        ' ::: "${file_list[@]}" 2>"$progress_file" &
        
        local parallel_pid=$!
        debug_log "GNU Parallel started with PID: $parallel_pid"
        
        # Mostrar progreso mientras parallel se ejecuta
        echo ""
        while kill -0 $parallel_pid 2>/dev/null; do
            if [ -f "$progress_file" ]; then
                grep -v "^tasks\|^Computers" "$progress_file" | tail -n 1
                
                # Mostrar cómo van los resultados únicos
                if [ -d "$hash_dir" ]; then
                    unique_count=$(find "$hash_dir" -type f -not -name "COMPLETE" | wc -l)
                    if [ $unique_count -gt 0 ]; then
                        echo "Unique results collected: $unique_count/$target_count"
                    fi
                fi
            fi
            echo -ne "\033[2A"  # Move cursor up 2 lines
            sleep 5
        done
        echo -ne "\033[2B"  # Move cursor back down 2 lines
        
        # Remove the temporary file
        rm -f "$progress_file"
        
        # Wait for parallel to finish
        wait $parallel_pid
    else
        echo "GNU Parallel not installed, using native Bash parallel processing with $CORES cores" | tee -a "$LOG_FILE"
        # Use native Bash parallel processing
        local running=0
        local i=0
        declare -A pids
        
        while ([ $i -lt $total_files ] || [ $running -gt 0 ]) && [ ! -f "$hash_dir/COMPLETE" ]; do
            # Start new tasks
            while [ $running -lt $CORES ] && [ $i -lt $total_files ] && [ ! -f "$hash_dir/COMPLETE" ]; do
                process_binary "${file_list[$i]}" "$hash_dir" "$target_count" &
                pids[$i]=$!
                ((i++))
                ((running++))
            done
            
            # Check for completed tasks
            for j in "${!pids[@]}"; do
                if [ "${pids[$j]}" ] && ! kill -0 ${pids[$j]} 2>/dev/null; then
                    wait ${pids[$j]} 2>/dev/null
                    unset pids[$j]
                    ((running--))
                    ((processed++))
                    
                    # Calculate progress and ETA
                    local current_time=$(date +%s)
                    local elapsed=$((current_time - start_time))
                    local progress=$((processed * 100 / total_files))
                    
                    if [ $processed -gt 0 ]; then
                        local rate=$(echo "scale=2; $processed / $elapsed" | bc)
                        local remaining_files=$((total_files - processed))
                        local eta=$(echo "scale=0; $remaining_files / $rate" | bc 2>/dev/null)
                        
                        if [ -n "$eta" ] && [ "$eta" != "0" ]; then
                            printf "\rProgress: %3d%% (%d/%d) | Running: %d | ETA: %02d:%02d:%02d | Unique: %d/%d " \
                                "$progress" "$processed" "$total_files" "$running" \
                                $((eta / 3600)) $(((eta % 3600) / 60)) $((eta % 60)) \
                                $(find "$hash_dir" -type f -not -name "COMPLETE" | wc -l) "$target_count"
                        else
                            printf "\rProgress: %3d%% (%d/%d) | Running: %d | Unique: %d/%d " \
                                "$progress" "$processed" "$total_files" "$running" \
                                $(find "$hash_dir" -type f -not -name "COMPLETE" | wc -l) "$target_count"
                        fi
                    else
                        printf "\rProgress: %3d%% (%d/%d) | Running: %d " \
                            "$progress" "$processed" "$total_files" "$running"
                    fi
                fi
            done
            
            # Check if we've reached the target count
            if [[ -f "$hash_dir/COMPLETE" ]]; then
                echo "Target count reached, stopping further processing" | tee -a "$LOG_FILE"
                # Terminate running processes
                for pid in "${pids[@]}"; do
                    if [ "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                        kill "$pid" 2>/dev/null
                    fi
                done
                break
            fi
            
            # Brief pause to avoid excessive CPU usage
            sleep 2
        done
        echo "" # New line after progress bar
    fi
    
    # Report final status
    if [[ -f "$hash_dir/COMPLETE" ]]; then
        echo "Successfully collected $target_count unique results!" | tee -a "$LOG_FILE"
    else
        unique_count=$(find "$hash_dir" -type f | wc -l)
        echo "Processing completed. Collected $unique_count unique results." | tee -a "$LOG_FILE"
    fi
}

# Process CPU-family combinations in multi-target mode
process_multi_targeted_files() {
    echo "Starting multi-targeted processing..." | tee -a "$LOG_FILE"
    
    # Check if dataset CSV exists
    if [[ ! -f "$DATASET_CSV" ]]; then
        echo "Error: Dataset CSV file not found: $DATASET_CSV" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    # If no CPUs specified, get all unique CPUs from the CSV
    if [[ ${#CPU_LIST[@]} -eq 0 ]]; then
        while IFS= read -r cpu; do
            CPU_LIST+=("$cpu")
        done < <(awk -F, 'NR > 1 {print $2}' "$DATASET_CSV" | sort -u)
        echo "Auto-detected CPU architectures: ${CPU_LIST[*]}" | tee -a "$LOG_FILE"
    fi
    
    # If no families specified, get all unique families from the CSV
    if [[ ${#FAMILY_LIST[@]} -eq 0 ]]; then
        while IFS= read -r family; do
            FAMILY_LIST+=("$family")
        done < <(awk -F, 'NR > 1 {print $3}' "$DATASET_CSV" | sort -u)
        echo "Auto-detected malware families: ${FAMILY_LIST[*]}" | tee -a "$LOG_FILE"
    fi
    
    # Process each CPU-family combination
    local completed=0
    local combinations=$((${#CPU_LIST[@]} * ${#FAMILY_LIST[@]}))
    local overall_start_time=$(date +%s)
    
    debug_log "Starting processing of $combinations CPU-family combinations"
    debug_check_csv
    
    for cpu in "${CPU_LIST[@]}"; do
        for family in "${FAMILY_LIST[@]}"; do
            ((completed++))
            local combo_start_time=$(date +%s)
            
            echo "" | tee -a "$LOG_FILE"
            echo "===== Processing combination $completed/$combinations: CPU=$cpu, Family=$family =====" | tee -a "$LOG_FILE"
            debug_log "Starting combination $completed/$combinations: CPU=$cpu, Family=$family"
            
            # Create combination-specific hash directory for tracking unique results
            local combo_hash_dir="$TEMP_DIR/${cpu}_${family}"
            mkdir -p "$combo_hash_dir"
            rm -rf "$combo_hash_dir"/*
            
            # Initialize counters
            local processed=0
            local unique_count=0
            local actual_target_count=$TARGET_COUNT
            
            # 直接处理CSV中的每个文件，不再收集到列表中
            debug_log "Processing files for CPU=$cpu, Family=$family from CSV..."
            
            # 计算总文件数以显示进度
            local total_files=$(get_files_from_csv "$cpu" "$family" "$DATASET_CSV" | wc -l)
            
            if [[ $total_files -eq 0 ]]; then
                echo "No files match the combination: CPU=$cpu, Family=$family" | tee -a "$LOG_FILE"
                continue
            fi
            
            echo "Found $total_files files for CPU=$cpu, Family=$family" | tee -a "$LOG_FILE"
            
            # Check if we have fewer files than the target count
            if [[ $total_files -lt $TARGET_COUNT ]]; then
                echo "Warning: Only $total_files files available for CPU=$cpu, Family=$family (less than target count $TARGET_COUNT)" | tee -a "$LOG_FILE"
                echo "Will process all available files instead" | tee -a "$LOG_FILE"
                actual_target_count=$total_files
            fi
            
            # 设置信号量以限制并发任务数
            if command -v sem &> /dev/null; then
                # 使用GNU parallel的sem命令进行并发控制
                debug_log "Using GNU Parallel's semaphore for concurrency control with $CORES parallel tasks"
            else
                # 使用基本计数器来跟踪并发任务
                local running=0
                declare -A pids
            fi
            
            # 直接处理符合条件的每个文件
            while IFS= read -r filename; do
                # 检查是否已达到目标数量的唯一结果
                if [[ -f "$combo_hash_dir/COMPLETE" ]]; then
                    debug_log "Target count reached, stopping further processing"
                    break
                fi
                
                debug_log "Found in CSV: $filename"
                local file_path=$(find "$DATA_DIR" -name "$filename" -type f)
                
                if [[ -n "$file_path" ]]; then
                    debug_log "Processing file directly: $file_path"
                    
                    if command -v sem &> /dev/null; then
                        # 使用GNU Parallel的sem命令进行并发控制
                        sem --id ghidra_proc -j $CORES \
                            bash -c "process_binary \"$file_path\" \"$combo_hash_dir\" \"$actual_target_count\""
                    else
                        # 使用基本的Bash并发控制
                        while [[ $running -ge $CORES ]]; do
                            # 检查已完成的任务
                            for j in "${!pids[@]}"; do
                                if [ "${pids[$j]}" ] && ! kill -0 ${pids[$j]} 2>/dev/null; then
                                    wait ${pids[$j]} 2>/dev/null
                                    unset pids[$j]
                                    ((running--))
                                    ((processed++))
                                    
                                    # 计算和显示进度
                                    local progress=$((processed * 100 / total_files))
                                    unique_count=$(find "$combo_hash_dir" -type f -not -name "COMPLETE" | wc -l)
                                    printf "\rProgress: %3d%% (%d/%d) | Unique results: %d/%d" \
                                        "$progress" "$processed" "$total_files" "$unique_count" "$actual_target_count"
                                fi
                            done
                            sleep 1
                        done
                        
                        # 启动新任务
                        process_binary "$file_path" "$combo_hash_dir" "$actual_target_count" &
                        pids[$processed]=$!
                        ((running++))
                    fi
                else
                    debug_log "Warning: File not found in data directory: $filename"
                    echo "Warning: File not found in data directory: $filename" | tee -a "$LOG_FILE"
                fi
            done < <(get_files_from_csv "$cpu" "$family" "$DATASET_CSV")
            
            # 等待所有任务完成
            if command -v sem &> /dev/null; then
                sem --id ghidra_proc --wait
            else
                # 等待剩余的后台任务完成
                for pid in "${pids[@]}"; do
                    if [ "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                        wait "$pid" 2>/dev/null
                        ((processed++))
                    fi
                done
                echo "" # 新行结束进度条
            fi
            
            # Gather statistics for this combination
            local unique_count=$(find "$combo_hash_dir" -type f -not -name "COMPLETE" | wc -l)
            local combo_end_time=$(date +%s)
            local combo_duration=$((combo_end_time - combo_start_time))
            
            echo "Completed processing combination CPU=$cpu, Family=$family in $(format_time $combo_duration). Collected $unique_count unique results" | tee -a "$LOG_FILE"
            
            # Estimate overall progress
            local overall_elapsed=$((combo_end_time - overall_start_time))
            local avg_time_per_combo=$((overall_elapsed / completed))
            local remaining_combos=$((combinations - completed))
            local eta=$((avg_time_per_combo * remaining_combos))
            
            echo "Overall progress: $completed/$combinations combinations processed ($(printf "%.1f" $((completed * 100 / combinations)))%)"
            echo "Estimated time remaining: $(format_time $eta)"
            echo "-----------------------------------------------------------"
        done
    done
    
    local overall_end_time=$(date +%s)
    local total_duration=$((overall_end_time - overall_start_time))
    echo "All combinations processed in $(format_time $total_duration)" | tee -a "$LOG_FILE"
}

# Process single-target files
process_targeted_files() {
    echo "Starting targeted processing (single target)..." | tee -a "$LOG_FILE"
    
    # Check if dataset CSV exists
    if [[ ! -f "$DATASET_CSV" ]]; then
        echo "Error: Dataset CSV file not found: $DATASET_CSV" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    # Get file list based on criteria
    local file_list=()
    while IFS= read -r filename; do
        local file_path=$(find "$DATA_DIR" -name "$filename" -type f)
        if [[ -n "$file_path" ]]; then
            file_list+=("$file_path")
        else
            echo "Warning: File not found in data directory: $filename" | tee -a "$LOG_FILE"
        fi
    done < <(get_files_from_csv "$TARGET_CPU" "$TARGET_FAMILY" "$DATASET_CSV")
    
    # Check if we have files to process
    if [[ ${#file_list[@]} -eq 0 ]]; then
        echo "No files match the specified criteria: CPU=$TARGET_CPU, Family=$TARGET_FAMILY" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    # Process selected files in parallel
    process_in_parallel "$TEMP_DIR" "$TARGET_COUNT" "${file_list[@]}"
}

# Process all files
process_all_files() {
    echo "Starting to process all binary files..." | tee -a "$LOG_FILE"
    
    # Collect all file paths into array
    local all_files=()
    while IFS= read -r file; do
        all_files+=("$file")
    done < <(find "$DATA_DIR" -type f)
    
    # Process all files in parallel
    process_in_parallel "$TEMP_DIR" "$TARGET_COUNT" "${all_files[@]}"
}

# Check if files are being processed
debug_watch_processes() {
    local start_time=$(date +%s)
    local check_interval=30  # seconds
    local timeout=300        # 5 minutes
    local last_count=0
    local current_count=0
    local stalled=0
    
    while true; do
        sleep $check_interval
        
        # Count current Ghidra processes
        current_count=$(ps aux | grep ghidra | grep -v grep | wc -l)
        
        # Check if process count changed
        if [ "$current_count" -eq "$last_count" ]; then
            ((stalled++))
            debug_log "WARNING: Process count unchanged for $((stalled * check_interval)) seconds ($current_count processes)"
        else
            stalled=0
            debug_log "Process count changed: $last_count -> $current_count"
        fi
        
        # If stalled for too long, print detailed info
        if [ "$stalled" -gt "$((timeout / check_interval))" ]; then
            debug_log "ALERT: Processing appears stalled for $((stalled * check_interval)) seconds"
            debug_show_processes
            # Check disk I/O
            debug_log "Disk I/O status:"
            iostat | tee -a "$LOG_FILE"
            # Check memory usage
            debug_log "Memory usage:"
            free -h | tee -a "$LOG_FILE"
            # Reset stalled counter
            stalled=0
        fi
        
        # Save current count
        last_count=$current_count
        
        # Check if we should continue monitoring
        local now=$(date +%s)
        if [ "$((now - start_time))" -gt "$((timeout * 2))" ]; then
            debug_log "Stopping process monitoring after $((now - start_time)) seconds"
            break
        fi
    done
}

# Start monitoring in the background
debug_watch_processes &
MONITOR_PID=$!
debug_log "Started process monitoring with PID: $MONITOR_PID"

# Main execution flow
debug_log "Starting main execution flow"
debug_show_processes

if [[ "$ALL_FILES" == "true" ]]; then
    process_all_files
elif [[ "$MULTI_TARGET" == "true" ]]; then
    process_multi_targeted_files
elif [[ -n "$TARGET_CPU" || -n "$TARGET_FAMILY" || $TARGET_COUNT -gt 0 ]]; then
    process_targeted_files
else
    echo "No specific processing criteria provided. Please specify either 'all' or a combination of cpu/family/count." | tee -a "$LOG_FILE"
    show_usage
    exit 1
fi

# Display final summary
echo "===== Batch analysis completed $(date '+%Y-%m-%d %H:%M:%S') =====" | tee -a "$LOG_FILE"
echo "Analysis log saved in: $LOG_FILE"
echo "Analysis results saved in: $RESULTS_DIR directory"

# Display unique result summary
if [[ "$MULTI_TARGET" == "true" ]]; then
    echo "" | tee -a "$LOG_FILE"
    echo "===== Multi-target mode summary =====" | tee -a "$LOG_FILE"
    
    # For each CPU-family combination
    for combo_dir in "$TEMP_DIR"/*_*; do
        if [[ -d "$combo_dir" ]]; then
            dir_name=$(basename "$combo_dir")
            IFS='_' read -r cpu family <<< "$dir_name"
            
            unique_count=$(find "$combo_dir" -type f -not -name "COMPLETE" | wc -l)
            echo "CPU=$cpu, Family=$family: $unique_count unique results" | tee -a "$LOG_FILE"
        fi
    done
elif [[ $TARGET_COUNT -gt 0 ]]; then
    unique_count=$(find "$TEMP_DIR" -type f -not -name "COMPLETE" | wc -l)
    echo "Final unique result count: $unique_count" | tee -a "$LOG_FILE"
fi