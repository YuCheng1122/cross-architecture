#!/bin/bash
# Define paths
GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"
SCRIPT="ExtractPcodeAndFunctionCalls.java"
SCRIPT_PATH="/home/tommy/cross-architecture/Experiment3/scripts_20250312"
BASE_DIR="/home/tommy/cross-architecture/Experiment3"
DATA_DIR="$BASE_DIR/data_20250312"
RESULTS_DIR="$BASE_DIR/results"
LOGS_DIR="$BASE_DIR/logs"
DATASET_CSV="/home/tommy/datasets/Sorted_Dataset_20250312114058.csv"

# Create temporary project directory in RAM
GHIDRA_TEMP="$BASE_DIR/ghidra_temp"
mkdir -p "$GHIDRA_TEMP"

# Time formatting function
format_time() {
    local seconds=$1
    printf "%02d:%02d:%02d" $((seconds/3600)) $(((seconds%3600)/60)) $((seconds%60))
}

# Default parameters
CORES=$(($(nproc) * 4))
TARGET_COUNT=0
declare -a CPU_LIST=()
declare -a FAMILY_LIST=()
BATCH_SIZE=10

# Parse command line arguments
for arg in "$@"; do
    case "$arg" in
        cores=*)     CORES=${arg#cores=} ;;
        cpus=*)      IFS=',' read -r -a CPU_LIST <<< "${arg#cpus=}" ;;
        families=*)  IFS=',' read -r -a FAMILY_LIST <<< "${arg#families=}" ;;
        count=*)     TARGET_COUNT=${arg#count=} ;;
        batch=*)     BATCH_SIZE=${arg#batch=} ;;
    esac
done

# Check and create necessary directories
mkdir -p "$RESULTS_DIR" "$LOGS_DIR" "$GHIDRA_TEMP"

# Set up log file
LOG_FILE="$LOGS_DIR/batch_execution_$(date +%Y%m%d_%H%M%S).log"
echo "===== Batch Analysis Started $(date '+%Y-%m-%d %H:%M:%S') =====" > "$LOG_FILE"

# Process single file function
process_single_file() {
    local file_path="$1"
    
    # Extract file information
    local binary_name=$(basename "$file_path")
    local relative_path=${file_path#"$DATA_DIR/"}
    local relative_dir=$(dirname "$relative_path")
    
    # Set up result path
    local result_dir="$RESULTS_DIR/$relative_dir"
    mkdir -p "$result_dir"
    local result_file="$result_dir/${binary_name}.json"
    
    # Create project name and log file
    local project_name="Project_${binary_name}_$(date +%s)_$$"
    local process_log="$LOGS_DIR/${binary_name}_$(date +%s)_$$.log"
    
    echo "Processing file: $binary_name"
    
    # Run Ghidra analysis
    "$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_TEMP" "$project_name" \
        -import "$file_path" \
        -postScript "$SCRIPT" "$result_file" \
        -scriptPath "$SCRIPT_PATH" > "$process_log" 2>&1
    
    # Clean up project
    if [[ -d "$GHIDRA_TEMP/$project_name" ]]; then
        rm -rf "$GHIDRA_TEMP/$project_name"
    fi
    
    # Check if analysis was successful
    if [[ -f "$result_file" ]]; then
        echo "File processed successfully: $binary_name"
    else
        echo "Warning: Failed to process file: $binary_name"
    fi
}

# Batch process files function
process_file_batch() {
    local file_paths=("$@")
    
    echo "Starting batch processing of ${#file_paths[@]} files"
    
    # Export functions and variables
    export -f process_single_file
    export GHIDRA_HOME GHIDRA_TEMP SCRIPT_PATH SCRIPT DATA_DIR RESULTS_DIR LOGS_DIR
    
    # Use GNU Parallel for processing
    if command -v parallel &> /dev/null; then
        parallel --jobs $CORES --halt soon,fail=1 \
            "process_single_file {}" ::: "${file_paths[@]}"
    else
        # Basic parallel processing
        local running=0
        for file_path in "${file_paths[@]}"; do
            # Control number of parallel jobs
            while [[ $running -ge $CORES ]]; do
                sleep 0.5
                running=$(jobs -p | wc -l)
            done
            
            # Process file
            process_single_file "$file_path" &
            ((running++))
        done
        
        # Wait for all tasks to complete
        wait
    fi
    
    echo "Batch processing completed"
}

# Get file list from CSV
get_files_from_csv() {
    local target_cpu="$1"
    local target_family="$2"
    
    awk -F, -v cpu="$target_cpu" -v family="$target_family" '
    NR > 1 {
        if ((cpu == "" || $2 == cpu) && (family == "" || $3 == family)) {
            print $1
        }
    }' "$DATASET_CSV"
}

# Multi-target processing main function
process_multi_targeted() {
    echo "Starting multi-target processing..."
    
    # Check CSV file exists
    if [[ ! -f "$DATASET_CSV" ]]; then
        echo "Error: Dataset CSV file does not exist: $DATASET_CSV"
        exit 1
    fi
    
    # Automatically detect CPU architectures and families
    if [[ ${#CPU_LIST[@]} -eq 0 ]]; then
        mapfile -t CPU_LIST < <(awk -F, 'NR > 1 {print $2}' "$DATASET_CSV" | sort -u)
        echo "Auto-detected CPU architectures: ${CPU_LIST[*]}"
    fi
    
    if [[ ${#FAMILY_LIST[@]} -eq 0 ]]; then
        mapfile -t FAMILY_LIST < <(awk -F, 'NR > 1 {print $3}' "$DATASET_CSV" | sort -u)
        echo "Auto-detected malware families: ${FAMILY_LIST[*]}"
    fi
    
    # Display configuration information
    echo "Configuration:"
    echo "- Data directory: $DATA_DIR"
    echo "- Results directory: $RESULTS_DIR"
    echo "- Using $CORES cores for parallel processing"
    echo "- Batch size: $BATCH_SIZE files per batch"
    echo "- Target CPUs: ${CPU_LIST[*]}"
    echo "- Target families: ${FAMILY_LIST[*]}"
    if [[ $TARGET_COUNT -gt 0 ]]; then
        echo "- Processing $TARGET_COUNT files per combination (if available)"
    else
        echo "- Processing all available files per combination"
    fi
    
    # Process each CPU-family combination
    local completed=0
    local combinations=$((${#CPU_LIST[@]} * ${#FAMILY_LIST[@]}))
    local overall_start_time=$(date +%s)
    
    for cpu in "${CPU_LIST[@]}"; do
        for family in "${FAMILY_LIST[@]}"; do
            ((completed++))
            local combo_start_time=$(date +%s)
            
            echo ""
            echo "===== Processing combination $completed/$combinations: CPU=$cpu, Family=$family ====="
            
            # Calculate total number of files
            local filenames=($(get_files_from_csv "$cpu" "$family"))
            local total_files=${#filenames[@]}
            
            if [[ $total_files -eq 0 ]]; then
                echo "No files match combination: CPU=$cpu, Family=$family"
                continue
            fi
            
            echo "Found $total_files files for CPU=$cpu, Family=$family"
            
            # Limit number of files to process if TARGET_COUNT is set
            local files_to_process=$total_files
            if [[ $TARGET_COUNT -gt 0 && $TARGET_COUNT -lt $total_files ]]; then
                files_to_process=$TARGET_COUNT
                echo "Will process first $files_to_process files out of $total_files available"
                # Trim the filenames array to the target count
                filenames=("${filenames[@]:0:$files_to_process}")
            fi
            
            # Batch process files
            local batch_files=()
            local batch_count=0
            local processed_count=0
            
            for filename in "${filenames[@]}"; do
                # Find actual file path
                local file_path=$(find "$DATA_DIR" -name "$filename" -type f)
                
                if [[ -n "$file_path" ]]; then
                    batch_files+=("$file_path")
                    
                    # Process batch when enough files have been collected
                    if [[ ${#batch_files[@]} -ge $BATCH_SIZE ]]; then
                        ((batch_count++))
                        echo "Processing batch $batch_count with ${#batch_files[@]} files"
                        process_file_batch "${batch_files[@]}"
                        processed_count=$((processed_count + ${#batch_files[@]}))
                        echo "Progress: $processed_count/$files_to_process files processed"
                        batch_files=()
                    fi
                else
                    echo "Warning: File not found in data directory: $filename"
                fi
            done
            
            # Process remaining files
            if [[ ${#batch_files[@]} -gt 0 ]]; then
                ((batch_count++))
                echo "Processing final batch $batch_count with ${#batch_files[@]} files"
                process_file_batch "${batch_files[@]}"
                processed_count=$((processed_count + ${#batch_files[@]}))
                echo "Progress: $processed_count/$files_to_process files processed"
            fi
            
            # Collect statistics
            local combo_end_time=$(date +%s)
            local combo_duration=$((combo_end_time - combo_start_time))
            
            echo "Completed processing combination CPU=$cpu, Family=$family in $(format_time $combo_duration). Processed $processed_count files"
            
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
    
    # Display summary
    local overall_end_time=$(date +%s)
    local total_duration=$((overall_end_time - overall_start_time))
    echo "All combinations processed, total time $(format_time $total_duration)"
    
    echo ""
    echo "===== Multi-target Mode Summary ====="
    for cpu in "${CPU_LIST[@]}"; do
        for family in "${FAMILY_LIST[@]}"; do
            local count=$(find "$RESULTS_DIR" -path "*/${cpu}*/${family}*/*.json" -o -path "*/${family}*/${cpu}*/*.json" | wc -l)
            echo "CPU=$cpu, Family=$family: $count processed files"
        done
    done
}

# Execute main function
process_multi_targeted

echo "===== Batch Analysis Completed $(date '+%Y-%m-%d %H:%M:%S') ====="
echo "Analysis logs saved in: $LOG_FILE"
echo "Analysis results saved in: $RESULTS_DIR directory"