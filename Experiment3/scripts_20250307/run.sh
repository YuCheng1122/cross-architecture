#!/bin/bash
# Define paths
GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"
PROJECT_DIR="/home/tommy/cross-architecture/Experiment3/ghidra_projects"
SCRIPT="ExtractPcodeAndFunctionCalls.java"
SCRIPT_PATH="/home/tommy/cross-architecture/Experiment3/scripts_20250307"
BASE_DIR="/home/tommy/cross-architecture/Experiment3"
DATASET_CSV="/home/tommy/datasets/Sorted_Dataset_20250312114058.csv"

# Default number of cores to use, if not specified then use half of the system cores
NUM_CORES=$(nproc)
DEFAULT_CORES=$((NUM_CORES / 2))
MAX_CORES=$NUM_CORES

# Default parameters
ALL_FILES=false
CORES=$DEFAULT_CORES
TARGET_CPU=""
TARGET_FAMILY=""
TARGET_COUNT=0

# Multiple targets support
declare -a CPU_LIST=()
declare -a FAMILY_LIST=()
MULTI_TARGET=false

# Function to display usage
show_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  all                 Process all files"
    echo "  cores=N             Use N cores for processing (default: half of system cores)"
    echo "  cpu=ARCHITECTURE    Target specific CPU architecture (e.g., ARM, MIPS)"
    echo "  family=NAME         Target specific malware family"
    echo "  count=N             Number of unique results to collect"
    echo "  multi               Enable multi-target mode for processing multiple CPUs/families"
    echo "  cpus=ARCH1,ARCH2    Comma-separated list of CPU architectures to target"
    echo "  families=FAM1,FAM2  Comma-separated list of malware families to target"
    echo ""
    echo "Examples:"
    echo "  $0 cpu=ARM family=mirai count=10 cores=4"
    echo "  $0 multi cpus=ARM,MIPS families=mirai,hajime count=5 cores=4"
}

# Parse command line parameters
for arg in "$@"; do
    if [[ "$arg" == "all" ]]; then
        ALL_FILES=true
    elif [[ "$arg" == "multi" ]]; then
        MULTI_TARGET=true
    elif [[ "$arg" =~ ^cores=([0-9]+)$ ]]; then
        requested_cores=${BASH_REMATCH[1]}
        # Ensure not exceeding system core count
        if (( requested_cores > 0 && requested_cores <= MAX_CORES )); then
            CORES=$requested_cores
        else
            echo "Warning: Requested core count $requested_cores is out of range, will use $DEFAULT_CORES cores"
        fi
    elif [[ "$arg" =~ ^cpu=(.+)$ ]]; then
        TARGET_CPU=${BASH_REMATCH[1]}
    elif [[ "$arg" =~ ^cpus=(.+)$ ]]; then
        IFS=',' read -r -a CPU_LIST <<< "${BASH_REMATCH[1]}"
    elif [[ "$arg" =~ ^family=(.+)$ ]]; then
        TARGET_FAMILY=${BASH_REMATCH[1]}
    elif [[ "$arg" =~ ^families=(.+)$ ]]; then
        IFS=',' read -r -a FAMILY_LIST <<< "${BASH_REMATCH[1]}"
    elif [[ "$arg" =~ ^count=([0-9]+)$ ]]; then
        TARGET_COUNT=${BASH_REMATCH[1]}
    elif [[ "$arg" == "help" || "$arg" == "--help" ]]; then
        show_usage
        exit 0
    fi
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

echo "Configuration:"
echo "- Will use $CORES cores for parallel processing"

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
    if [[ -n "$TARGET_CPU" ]]; then
        echo "- Targeting CPU: $TARGET_CPU"
    fi
    if [[ -n "$TARGET_FAMILY" ]]; then
        echo "- Targeting family: $TARGET_FAMILY"
    fi
    if [[ $TARGET_COUNT -gt 0 ]]; then
        echo "- Collecting $TARGET_COUNT unique results"
    fi
fi

# Ensure necessary directory structure exists
mkdir -p "$BASE_DIR/results"
mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/ghidra_projects"
mkdir -p "$BASE_DIR/temp_hash"

# Log file setup
LOG_FILE="$BASE_DIR/logs/batch_execution_$(date +%Y%m%d_%H%M%S).log"
echo "===== Batch analysis started $(date '+%Y-%m-%d %H:%M:%S') =====" > "$LOG_FILE"
echo "Using $CORES cores for parallel processing" | tee -a "$LOG_FILE"

# Ensure results directory structure matches data directory structure
echo "Synchronizing directory structure..." | tee -a "$LOG_FILE"
find "$BASE_DIR/data" -type d | while read -r dir; do
    relative_path=${dir#"$BASE_DIR/"}
    if [[ "$relative_path" != "data" ]]; then
        mkdir -p "$BASE_DIR/results/$relative_path"
        echo "Created directory: $BASE_DIR/results/$relative_path" >> "$LOG_FILE"
    fi
done

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
    local relative_path=${binary_path#"$BASE_DIR/data/"}
    local malware_family=$(dirname "$relative_path" | xargs basename)
    
    # Create unique project name
    local project_name="Project_${binary_name}_$(date +%s)_$"
    local process_log="$BASE_DIR/logs/process_${binary_name}_$(date +%s)_$.log"
    
    {
        echo "===== Processing file: $binary_name =====" 
        echo "Family: $malware_family" 
        echo "Start time: $(date '+%Y-%m-%d %H:%M:%S')" 
        
        # Run Ghidra analysis
        "$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$project_name" \
            -import "$binary_path" \
            -postScript "$SCRIPT" \
            -scriptPath "$SCRIPT_PATH" \
            -deleteProject
            
        echo "Completion time: $(date '+%Y-%m-%d %H:%M:%S')" 
        echo ""
    } > "$process_log" 2>&1
    
    # Update main log
    cat "$process_log" >> "$LOG_FILE"
    echo "Completed processing: $binary_name" | tee -a "$LOG_FILE"
    
    # Check if result file exists
    local arch=$(file "$binary_path" | grep -oE 'ARM|MIPS|x86|PowerPC|Sparc' | head -1)
    if [[ -z "$arch" ]]; then
        arch="unknown"
    fi
    
    local result_file="$BASE_DIR/results/$relative_path/${binary_name}_${arch}.json"
    
    # Check for result file existence
    if [[ -f "$result_file" ]]; then
        # Check if result is unique (for target count processing)
        if [[ $target_count -gt 0 ]]; then
            if is_unique_result "$result_file" "$temp_hash_dir"; then
                # Count unique results
                unique_count=$(find "$temp_hash_dir" -type f | wc -l)
                echo "Unique results so far: $unique_count/$target_count" | tee -a "$LOG_FILE"
                
                # Check if we've reached the target count
                if [[ $unique_count -ge $target_count ]]; then
                    echo "Reached target count of $target_count unique results!" | tee -a "$LOG_FILE"
                    # Signal to stop processing
                    touch "$temp_hash_dir/COMPLETE"
                fi
            fi
        fi
    else
        echo "Warning: No result file generated for $binary_name" | tee -a "$LOG_FILE"
    fi
}

# Function to get file paths from CSV based on criteria
get_files_from_csv() {
    local target_cpu="$1"
    local target_family="$2"
    local csv_file="$3"
    
    # Skip header line, filter by CPU and family if specified
    awk -F, -v cpu="$target_cpu" -v family="$target_family" '
    NR > 1 {
        if ((cpu == "" || $2 == cpu) && (family == "" || $3 == family)) {
            print $1
        }
    }' "$csv_file"
}

# Parallel processing function
process_in_parallel() {
    local hash_dir="$1"
    local target_count="$2"
    shift 2
    local file_list=("$@")
    local total_files=${#file_list[@]}
    local processed=0
    
    echo "Total of $total_files files to process" | tee -a "$LOG_FILE"
    
    # Clear temp hash directory
    mkdir -p "$hash_dir"
    rm -rf "$hash_dir"/*
    
    # Use GNU Parallel if available
    if command -v parallel &> /dev/null; then
        echo "Using GNU Parallel for parallel processing" | tee -a "$LOG_FILE"
        export -f process_binary calculate_json_hash is_unique_result
        export GHIDRA_HOME PROJECT_DIR SCRIPT SCRIPT_PATH BASE_DIR LOG_FILE
        
        # Process files with parallel, but check for completion flag
        parallel -j "$CORES" --halt soon,fail=1 '
            if [[ -f "'$hash_dir'/COMPLETE" ]]; then 
                echo "Target count reached, skipping further processing";
                exit 0; 
            fi; 
            process_binary {} "'$hash_dir'" "'$target_count'"
        ' ::: "${file_list[@]}"
    else
        echo "GNU Parallel not installed, using native Bash parallel processing" | tee -a "$LOG_FILE"
        # Use native Bash parallel processing
        local running=0
        local i=0
        
        while ([ $i -lt $total_files ] || [ $running -gt 0 ]) && [ ! -f "$hash_dir/COMPLETE" ]; do
            # Start new tasks
            while [ $running -lt $CORES ] && [ $i -lt $total_files ] && [ ! -f "$hash_dir/COMPLETE" ]; do
                process_binary "${file_list[$i]}" "$hash_dir" "$target_count" &
                pids[$i]=$!
                ((i++))
                ((running++))
                echo "Started processing $i/$total_files, current parallel tasks: $running" | tee -a "$LOG_FILE"
            done
            
            # Check for completed tasks
            for j in $(seq 0 $((i-1))); do
                if [ ${pids[$j]} ] && ! kill -0 ${pids[$j]} 2>/dev/null; then
                    wait ${pids[$j]}
                    unset pids[$j]
                    ((running--))
                    ((processed++))
                    echo "Completed $processed/$total_files, remaining parallel tasks: $running" | tee -a "$LOG_FILE"
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
            sleep 1
        done
    fi
    
    # Report final status
    if [[ -f "$hash_dir/COMPLETE" ]]; then
        echo "Successfully collected $target_count unique results!" | tee -a "$LOG_FILE"
    else
        unique_count=$(find "$hash_dir" -type f | wc -l)
        echo "Processing completed. Collected $unique_count unique results." | tee -a "$LOG_FILE"
    fi
}

# Process all files
process_all_files() {
    echo "Starting to process all binary files..." | tee -a "$LOG_FILE"
    
    # Collect all file paths into array
    local all_files=()
    while IFS= read -r file; do
        all_files+=("$file")
    done < <(find "$BASE_DIR/data" -type f)
    
    # Process all files in parallel
    process_in_parallel "$BASE_DIR/temp_hash" "$TARGET_COUNT" "${all_files[@]}"
}

# Process files based on CSV and criteria - Single target mode
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
        # Find the actual path of the file in the data directory
        local file_path=$(find "$BASE_DIR/data" -name "$filename" -type f)
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
    process_in_parallel "$BASE_DIR/temp_hash" "$TARGET_COUNT" "${file_list[@]}"
}

# Process files based on CSV and criteria - Multi target mode
process_multi_targeted_files() {
    echo "Starting multi-targeted processing..." | tee -a "$LOG_FILE"
    
    # Check if dataset CSV exists
    if [[ ! -f "$DATASET_CSV" ]]; then
        echo "Error: Dataset CSV file not found: $DATASET_CSV" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    # Create an array to hold all CPU-family combinations
    local combinations=()
    
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
    
    # Create all combinations of CPU and family
    for cpu in "${CPU_LIST[@]}"; do
        for family in "${FAMILY_LIST[@]}"; do
            combinations+=("$cpu:$family")
        done
    done
    
    echo "Will process ${#combinations[@]} CPU-family combinations" | tee -a "$LOG_FILE"
    
    # Process each combination
    local completed=0
    for combination in "${combinations[@]}"; do
        IFS=':' read -r cpu family <<< "$combination"
        
        echo "" | tee -a "$LOG_FILE"
        echo "===== Processing combination $((completed+1))/${#combinations[@]}: CPU=$cpu, Family=$family =====" | tee -a "$LOG_FILE"
        
        # Create combination-specific hash directory
        local combo_hash_dir="$BASE_DIR/temp_hash/${cpu}_${family}"
        mkdir -p "$combo_hash_dir"
        
        # Get file list for this combination
        local combo_file_list=()
        while IFS= read -r filename; do
            # Find the actual path of the file in the data directory
            local file_path=$(find "$BASE_DIR/data" -name "$filename" -type f)
            if [[ -n "$file_path" ]]; then
                combo_file_list+=("$file_path")
            else
                echo "Warning: File not found in data directory: $filename" | tee -a "$LOG_FILE"
            fi
        done < <(get_files_from_csv "$cpu" "$family" "$DATASET_CSV")
        
        # Check if we have files to process for this combination
        if [[ ${#combo_file_list[@]} -eq 0 ]]; then
            echo "No files match the combination: CPU=$cpu, Family=$family" | tee -a "$LOG_FILE"
            ((completed++))
            continue
        fi
        
        echo "Found ${#combo_file_list[@]} files for CPU=$cpu, Family=$family" | tee -a "$LOG_FILE"
        
        # Check if we have fewer files than the target count
        local actual_target_count=$TARGET_COUNT
        if [[ ${#combo_file_list[@]} -lt $TARGET_COUNT ]]; then
            echo "Warning: Only ${#combo_file_list[@]} files available for CPU=$cpu, Family=$family (less than target count $TARGET_COUNT)" | tee -a "$LOG_FILE"
            echo "Will collect all available unique results instead" | tee -a "$LOG_FILE"
            actual_target_count=${#combo_file_list[@]}
        fi
        
        # Process this combination
        process_in_parallel "$combo_hash_dir" "$actual_target_count" "${combo_file_list[@]}"
        
        # Gather statistics for this combination
        local unique_count=$(find "$combo_hash_dir" -type f -not -name "COMPLETE" | wc -l)
        echo "Completed processing combination CPU=$cpu, Family=$family. Collected $unique_count unique results" | tee -a "$LOG_FILE"
        
        ((completed++))
        

# Main execution flow
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

echo "===== Batch analysis completed $(date '+%Y-%m-%d %H:%M:%S') =====" | tee -a "$LOG_FILE"
echo "Analysis log saved in: $LOG_FILE"
echo "Analysis results saved in: $BASE_DIR/results directory, with directory structure matching data"

# Display unique result summary
if [[ "$MULTI_TARGET" == "true" ]]; then
    echo "" | tee -a "$LOG_FILE"
    echo "===== Multi-target mode summary =====" | tee -a "$LOG_FILE"
    
    # For each CPU-family combination
    for combo_dir in "$BASE_DIR/temp_hash"/*_*; do
        if [[ -d "$combo_dir" ]]; then
            dir_name=$(basename "$combo_dir")
            IFS='_' read -r cpu family <<< "$dir_name"
            
            unique_count=$(find "$combo_dir" -type f -not -name "COMPLETE" | wc -l)
            echo "CPU=$cpu, Family=$family: $unique_count unique results" | tee -a "$LOG_FILE"
            
            # List the unique files for this combination if requested
            if [[ "$TARGET_COUNT" -gt 0 && "$unique_count" -gt 0 ]]; then
                echo "  Unique result files:" | tee -a "$LOG_FILE"
                for hash_file in "$combo_dir"/*; do
                    if [[ -f "$hash_file" && "$hash_file" != "$combo_dir/COMPLETE" ]]; then
                        result_file=$(cat "$hash_file")
                        echo "    - $result_file" | tee -a "$LOG_FILE"
                    fi
                done
            fi
        fi
    done
elif [[ $TARGET_COUNT -gt 0 ]]; then
    unique_count=$(find "$BASE_DIR/temp_hash" -type f -not -name "COMPLETE" | wc -l)
    echo "Final unique result count: $unique_count" | tee -a "$LOG_FILE"
    
    if [[ $unique_count -gt 0 ]]; then
        echo "Unique result files:" | tee -a "$LOG_FILE"
        for hash_file in "$BASE_DIR/temp_hash"/*; do
            if [[ -f "$hash_file" && "$hash_file" != "$BASE_DIR/temp_hash/COMPLETE" ]]; then
                result_file=$(cat "$hash_file")
                echo "  - $result_file" | tee -a "$LOG_FILE"
            fi
        done
    fi
fi