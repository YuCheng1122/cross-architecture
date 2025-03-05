#!/bin/bash
# 切換到專案根目錄（假設 run.sh 位於 scripts/ 目錄下）
cd "$(dirname "$0")/.."

echo "當前目錄: $(pwd)"

# 設定環境變數（請根據實際環境調整）
GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"          # Ghidra 安裝路徑
PROJECT_DIR="$(pwd)/ghidra_projects"                    # Ghidra 專案目錄
SCRIPT="scripts/ExtractPcodeAndFeatures.java"           # Java 腳本路徑（相對於專案根目錄）
SCRIPT_PATH="scripts"                                   # 腳本所在目錄
OLD_OUT_DIR="/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/ghidra/automation_20250209/unpackedTuneDB"        # Java 程式輸出結果硬碼目錄

DATA_DIR="$(pwd)/data"                                  # 資料存放目錄（包含各 CPU 架構子目錄）
RESULTS_DIR="$(pwd)/results"                            # 分析結果最終存放目錄

echo "GHIDRA_HOME: $GHIDRA_HOME"
echo "PROJECT_DIR: $PROJECT_DIR"
echo "OLD_OUT_DIR: $OLD_OUT_DIR"
echo "DATA_DIR: $DATA_DIR"
echo "RESULTS_DIR: $RESULTS_DIR"

# 依據 data 目錄下的子目錄進行分析
for archDir in "$DATA_DIR"/*; do
    if [ -d "$archDir" ]; then
        arch=$(basename "$archDir")   # 例如 arm, mips, ...
        echo "處理 CPU 架構: $arch"
        for binary in "$archDir"/*; do
            if [ ! -f "$binary" ]; then
                continue
            fi
            base=$(basename "$binary")  # 例如 mirai.arm 或 mirai.mips
            PROJECT_NAME="Project_${arch}_${base}"
            echo "正在分析檔案: $binary (專案名稱: $PROJECT_NAME)"
            
            "$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
                -import "$binary" \
                -postScript "$SCRIPT" \
                -scriptPath "$SCRIPT_PATH" \
                -deleteProject
            
            # 依照 Java 程式內的命名規則：檔案命名為 <binaryFileName>_<ARCH>.txt，其中 ARCH 為大寫
            UARCH=$(echo "$arch" | tr '[:lower:]' '[:upper:]')
            GENERATED_FILE="${base}_${UARCH}.txt"
            
            echo "預期輸出檔案: $OLD_OUT_DIR/$GENERATED_FILE"
            
            # 移動結果到 results/架構子目錄，並以原檔名儲存
            DEST_DIR="$RESULTS_DIR/$arch"
            mkdir -p "$DEST_DIR"
            if [ -f "$OLD_OUT_DIR/$GENERATED_FILE" ]; then
                mv "$OLD_OUT_DIR/$GENERATED_FILE" "$DEST_DIR/$base"
                echo "移動 $GENERATED_FILE 至 $DEST_DIR/$base"
            else
                echo "找不到輸出檔案: $OLD_OUT_DIR/$GENERATED_FILE"
            fi
        done
    fi
done

echo "分析完成！"
