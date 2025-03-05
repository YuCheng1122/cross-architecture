#!/bin/bash
# 定義路徑
GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"
PROJECT_DIR="/home/tommy/cross-architecture/Experiment2/ghidra_projects"
SCRIPT="ExtractPcodeAndFunctionCalls.java"
SCRIPT_PATH="/home/tommy/cross-architecture/Experiment2/scripts_20250226"
BASE_DIR="/home/tommy/cross-architecture/Experiment2"

# 默認使用的核心數，如果未指定則使用系統的一半核心
NUM_CORES=$(nproc)
DEFAULT_CORES=$((NUM_CORES / 2))
MAX_CORES=$NUM_CORES

# 解析命令行參數
ALL_FILES=false
CORES=$DEFAULT_CORES

for arg in "$@"; do
    if [[ "$arg" == "all" ]]; then
        ALL_FILES=true
    elif [[ "$arg" =~ ^cores=([0-9]+)$ ]]; then
        requested_cores=${BASH_REMATCH[1]}
        # 確保不超過系統核心數
        if (( requested_cores > 0 && requested_cores <= MAX_CORES )); then
            CORES=$requested_cores
        else
            echo "警告: 請求的核心數 $requested_cores 超出範圍，將使用 $DEFAULT_CORES 核心"
        fi
    fi
done

echo "將使用 $CORES 個核心進行平行處理"

# 確保必要的目錄結構存在
mkdir -p "$BASE_DIR/results"
mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/ghidra_projects"

# 日誌檔案設置
LOG_FILE="$BASE_DIR/logs/batch_execution_$(date +%Y%m%d_%H%M%S).log"
echo "===== 批次分析開始 $(date '+%Y-%m-%d %H:%M:%S') =====" > "$LOG_FILE"
echo "使用 $CORES 個核心進行平行處理" | tee -a "$LOG_FILE"

# 確保結果目錄結構與數據目錄結構一致
echo "正在同步目錄結構..." | tee -a "$LOG_FILE"
find "$BASE_DIR/data" -type d | while read -r dir; do
    relative_path=${dir#"$BASE_DIR/"}
    if [[ "$relative_path" != "data" ]]; then
        mkdir -p "$BASE_DIR/results/$relative_path"
        echo "創建目錄: $BASE_DIR/results/$relative_path" >> "$LOG_FILE"
    fi
done

# 處理二進位檔案的函數
process_binary() {
    local binary_path="$1"
    local binary_name=$(basename "$binary_path")
    local relative_path=${binary_path#"$BASE_DIR/data/"}
    local malware_family=$(dirname "$relative_path")
    
    # 建立唯一的項目名稱
    local project_name="Project_${binary_name}_$(date +%s)_$$"
    local process_log="$BASE_DIR/logs/process_${binary_name}_$(date +%s)_$$.log"
    
    {
        echo "===== 處理文件: $binary_name =====" 
        echo "家族: $malware_family" 
        echo "開始時間: $(date '+%Y-%m-%d %H:%M:%S')" 
        
        # 運行 Ghidra 分析
        "$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$project_name" \
            -import "$binary_path" \
            -postScript "$SCRIPT" \
            -scriptPath "$SCRIPT_PATH" \
            -deleteProject
            
        echo "完成時間: $(date '+%Y-%m-%d %H:%M:%S')" 
        echo ""
    } > "$process_log" 2>&1
    
    # 更新主日誌
    cat "$process_log" >> "$LOG_FILE"
    echo "完成處理: $binary_name" | tee -a "$LOG_FILE"
}

# 並行處理函數
process_in_parallel() {
    local file_list=("$@")
    local total_files=${#file_list[@]}
    local processed=0
    
    echo "總共需要處理 $total_files 個文件" | tee -a "$LOG_FILE"
    
    # 使用 GNU Parallel 如果可用
    if command -v parallel &> /dev/null; then
        echo "使用 GNU Parallel 進行平行處理" | tee -a "$LOG_FILE"
        export -f process_binary
        export GHIDRA_HOME PROJECT_DIR SCRIPT SCRIPT_PATH BASE_DIR LOG_FILE
        parallel -j "$CORES" process_binary ::: "${file_list[@]}"
    else
        echo "GNU Parallel 未安裝，使用原生 Bash 平行處理" | tee -a "$LOG_FILE"
        # 使用原生 Bash 平行處理
        local running=0
        local i=0
        
        while [ $i -lt $total_files ] || [ $running -gt 0 ]; do
            # 啟動新任務
            while [ $running -lt $CORES ] && [ $i -lt $total_files ]; do
                process_binary "${file_list[$i]}" &
                pids[$i]=$!
                ((i++))
                ((running++))
                echo "啟動處理 $i/$total_files, 當前並行任務數: $running" | tee -a "$LOG_FILE"
            done
            
            # 檢查是否有完成的任務
            for j in $(seq 0 $((i-1))); do
                if [ ${pids[$j]} ] && ! kill -0 ${pids[$j]} 2>/dev/null; then
                    wait ${pids[$j]}
                    unset pids[$j]
                    ((running--))
                    ((processed++))
                    echo "完成 $processed/$total_files, 剩餘並行任務: $running" | tee -a "$LOG_FILE"
                fi
            done
            
            # 短暫休息，避免 CPU 過度使用
            sleep 1
        done
    fi
    
    echo "所有 $total_files 個文件處理完成！" | tee -a "$LOG_FILE"
}

# 處理所有 ARM 和 MIPS 範例
process_samples() {
    # 示例文件
    local arm_sample="$BASE_DIR/data/benign/00/00a64dbb7e20f3804a8d3912ed50c6a02caa2531bb6178dd0c63456536aa9734"
    
    # 將示例文件放入陣列
    local samples=("$arm_sample" "$mips_sample")
    
    # 並行處理示例文件
    process_in_parallel "${samples[@]}"
}

# 處理所有文件
process_all_files() {
    echo "開始處理所有二進位檔案..." | tee -a "$LOG_FILE"
    
    # 收集所有文件路徑到陣列
    local all_files=()
    while IFS= read -r file; do
        all_files+=("$file")
    done < <(find "$BASE_DIR/data" -type f)
    
    # 並行處理所有文件
    process_in_parallel "${all_files[@]}"
}

# 主執行流程
if $ALL_FILES; then
    process_all_files
else
    echo "只處理範例文件。如需處理所有文件，請使用參數 'all'" | tee -a "$LOG_FILE"
    process_samples
fi

echo "===== 批次分析完成 $(date '+%Y-%m-%d %H:%M:%S') =====" | tee -a "$LOG_FILE"
echo "分析日誌保存在: $LOG_FILE"
echo "分析結果保存在: $BASE_DIR/results 目錄下，目錄結構與 data 一致"