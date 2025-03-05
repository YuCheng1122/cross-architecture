#!/bin/bash

# 基礎目錄設置
BASE_DIR="/home/tommy/cross-architecture/Experiment1"
SCRIPT_DATE_DIR="$BASE_DIR/src/scripts_with-g＿20250204"

# 自動化相關目錄
AUTOMATION_DIR="$SCRIPT_DATE_DIR/ghidra/automation_20250208"
AUTO_SCRIPTS_DIR="$AUTOMATION_DIR/scripts"
AUTO_RESULTS_DIR="$AUTOMATION_DIR/results"
AUTO_LOGS_DIR="$AUTOMATION_DIR/logs"

# Ghidra 設置
GHIDRA_HOME="$HOME/ghidra_11.2.1_PUBLIC"

# Binary 目錄
ARM_BINARY="$SCRIPT_DATE_DIR/output_arm/mirai.arm"
MIPS_BINARY="$SCRIPT_DATE_DIR/output_mips/mirai.mips"

# 設置時間戳記
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$AUTO_RESULTS_DIR/analysis_${TIMESTAMP}"

# 創建必要的目錄
mkdir -p "$OUTPUT_DIR/arm"
mkdir -p "$OUTPUT_DIR/mips"
mkdir -p "$AUTO_LOGS_DIR"

# 日誌文件
LOG_FILE="$AUTO_LOGS_DIR/analysis_${TIMESTAMP}.log"

# 開始日誌記錄
echo "開始分析 - ${TIMESTAMP}" | tee -a "$LOG_FILE"
echo "使用目錄：$OUTPUT_DIR" | tee -a "$LOG_FILE"

# 函數：運行Ghidra分析
run_ghidra_analysis() {
    local arch=$1
    local binary_path=$2
    local processor=$3
    local log_prefix="$AUTO_LOGS_DIR/${arch}_${TIMESTAMP}"
    
    echo "開始分析 ${arch} 架構..." | tee -a "$LOG_FILE"
    
    "$GHIDRA_HOME/support/analyzeHeadless" \
        "$OUTPUT_DIR/${arch}" \
        "${arch}_MIRAI" \
        -import "$binary_path" \
        -processor "$processor" \
        -analysisTimeoutPerFile 3600 \
        -scriptPath "$AUTO_SCRIPTS_DIR" \
        -postScript ExtractPcodeForComparison.java "$OUTPUT_DIR/${arch}" \
        1>"${log_prefix}_stdout.log" \
        2>"${log_prefix}_stderr.log"
        
    local status=$?
    if [ $status -eq 0 ]; then
        echo "${arch} 分析完成" | tee -a "$LOG_FILE"
    else
        echo "${arch} 分析失敗 (錯誤碼: $status)" | tee -a "$LOG_FILE"
        cat "${log_prefix}_stderr.log" >> "$LOG_FILE"
    fi
}

# 並行運行分析
echo "開始並行分析..." | tee -a "$LOG_FILE"

run_ghidra_analysis "arm" "$ARM_BINARY" "ARM:LE:32:v8" &
ARM_PID=$!

run_ghidra_analysis "mips" "$MIPS_BINARY" "MIPS:BE:32:default" &
MIPS_PID=$!

wait $ARM_PID
wait $MIPS_PID

echo "Ghidra 分析完成，開始比對..." | tee -a "$LOG_FILE"

# 使用Python腳本進行比對（替換原本的Java比對）
python3 "$AUTO_SCRIPTS_DIR/comparePcode.py" \
    --arm-dir "$OUTPUT_DIR/arm" \
    --mips-dir "$OUTPUT_DIR/mips" \
    2>&1 | tee -a "$LOG_FILE"

echo "完整分析流程完成！" | tee -a "$LOG_FILE"
echo "結果保存在: $OUTPUT_DIR" | tee -a "$LOG_FILE"
echo "日誌文件: $LOG_FILE" | tee -a "$LOG_FILE"