#!/bin/bash

# Define paths
CSV_FILE="/home/tommy/cross-architecture/Experiment3/csv/20250316_cleaned_all_combined_file_features.csv"
DATA_DIR="/home/tommy/cross-architecture/Experiment3/data_20250312"
LOG_FILE="/home/tommy/cross-architecture/Experiment3/deleted_files_$(date +%Y%m%d_%H%M%S).log"

# Check if CSV file exists
if [[ ! -f "$CSV_FILE" ]]; then
    echo "Error: CSV file not found at $CSV_FILE"
    exit 1
fi

# Check if data directory exists
if [[ ! -d "$DATA_DIR" ]]; then
    echo "Error: Data directory not found at $DATA_DIR"
    exit 1
fi

# Create log file
echo "=== File Deletion Log $(date '+%Y-%m-%d %H:%M:%S') ===" > "$LOG_FILE"
echo "CSV file: $CSV_FILE" >> "$LOG_FILE"
echo "Data directory: $DATA_DIR" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Initialize counters
total_files=0
deleted_files=0
not_found_files=0

echo "Starting to process files from CSV..."
echo "This may take some time depending on the number of files and directory structure..."

# Read file_name column from CSV (assuming it's the first column)
# Skip header row (NR > 1)
while IFS=, read -r filename rest; do
    # Skip header row if it exists
    if [[ "$filename" == "file_name" || "$filename" == "\"file_name\"" ]]; then
        continue
    fi
    
    # Remove any quotes around the filename
    filename=$(echo "$filename" | tr -d '"')
    
    # Increment total file counter
    ((total_files++))
    
    # Display progress every 100 files
    if (( total_files % 100 == 0 )); then
        echo "Processed $total_files files, deleted $deleted_files so far..."
    fi
    
    # Find file in data directory
    file_path=$(find "$DATA_DIR" -name "$filename" -type f)
    
    if [[ -n "$file_path" ]]; then
        # File found, delete it
        rm -f "$file_path"
        
        # Log the deletion
        echo "DELETED: $file_path" >> "$LOG_FILE"
        
        # Increment deleted counter
        ((deleted_files++))
    else
        # File not found
        echo "NOT FOUND: $filename" >> "$LOG_FILE"
        
        # Increment not found counter
        ((not_found_files++))
    fi
done < <(cut -d, -f1 "$CSV_FILE")

# Log summary
echo "" >> "$LOG_FILE"
echo "=== Summary ===" >> "$LOG_FILE"
echo "Total files processed: $total_files" >> "$LOG_FILE"
echo "Files deleted: $deleted_files" >> "$LOG_FILE"
echo "Files not found: $not_found_files" >> "$LOG_FILE"

# Display summary
echo ""
echo "=== Summary ==="
echo "Total files processed: $total_files"
echo "Files deleted: $deleted_files"
echo "Files not found: $not_found_files"
echo "Log file created at: $LOG_FILE"

# Check if we need to clean up empty directories
read -p "Do you want to remove empty directories? (y/n): " clean_dirs
if [[ "$clean_dirs" == "y" || "$clean_dirs" == "Y" ]]; then
    echo "Removing empty directories..."
    find "$DATA_DIR" -type d -empty -delete
    echo "Empty directories removed."
fi

echo "Process completed."