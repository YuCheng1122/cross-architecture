#!/bin/bash
# 此腳本用於執行過濾可執行區段的Python處理程序
# 並且為使用者提供一些有用的命令行選項

BASE_PATH="/home/tommy/cross-architecture/Experiment2"
PYTHON_SCRIPT="${BASE_PATH}/scripts_20250226/filter_executable_sections.py"

# 顏色設置
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 顯示腳本幫助信息
show_help() {
    echo -e "${BLUE}過濾可執行區段處理腳本${NC}"
    echo "使用方法: $0 [選項]"
    echo
    echo "選項:"
    echo "  -h, --help        顯示此幫助信息"
    echo "  -c, --check       檢查環境依賴"
    echo "  -d, --dry-run     顯示可執行區段但不執行完整處理"
    echo "  -s, --sample      只處理一個樣本文件進行測試"
    echo "  -f, --force       強制重新處理已存在的文件"
    echo "  -v, --verbose     顯示詳細的處理日誌"
    echo
}

# 檢查必要依賴
check_dependencies() {
    echo -e "${BLUE}檢查必要依賴...${NC}"
    
    # 檢查Python是否安裝
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}錯誤: 未安裝Python 3${NC}"
        echo "請執行: sudo apt-get install python3"
        return 1
    else
        PYTHON_VERSION=$(python3 --version)
        echo -e "${GREEN}找到 $PYTHON_VERSION${NC}"
    fi
    
    # 檢查radare2是否安裝
    if ! command -v r2 &> /dev/null; then
        echo -e "${RED}錯誤: 未安裝radare2${NC}"
        echo "請執行: sudo apt-get install radare2"
        return 1
    else
        R2_VERSION=$(r2 -v | head -n 1)
        echo -e "${GREEN}找到 $R2_VERSION${NC}"
    fi
    
    # 檢查必要的目錄
    echo -e "${BLUE}檢查必要目錄...${NC}"
    
    if [ ! -d "$BASE_PATH" ]; then
        echo -e "${RED}錯誤: 基礎目錄不存在: $BASE_PATH${NC}"
        return 1
    fi
    
    if [ ! -d "$BASE_PATH/results/data" ]; then
        echo -e "${RED}錯誤: 結果目錄不存在: $BASE_PATH/results/data${NC}"
        return 1
    fi
    
    if [ ! -d "$BASE_PATH/data" ]; then
        echo -e "${RED}錯誤: 原始數據目錄不存在: $BASE_PATH/data${NC}"
        return 1
    fi
    
    # 確保腳本目錄存在
    mkdir -p "${BASE_PATH}/scripts"
    
    # 如果Python腳本不存在，創建它
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo -e "${YELLOW}Python腳本不存在, 創建中...${NC}"
        cp "$(dirname "$0")/filter_executable_sections.py" "$PYTHON_SCRIPT"
        chmod +x "$PYTHON_SCRIPT"
    fi
    
    echo -e "${GREEN}所有依賴檢查通過!${NC}"
    return 0
}

    # 執行dry-run模式，只顯示可執行區段和導入函數
do_dry_run() {
    echo -e "${BLUE}執行Dry Run模式 - 顯示可執行區段和導入函數${NC}"
    
    # 找一個樣本二進制文件
    SAMPLE_BINARY=$(find "$BASE_PATH/data" -type f -not -path "*/\.*" | head -n 1)
    
    if [ -z "$SAMPLE_BINARY" ]; then
        echo -e "${RED}找不到樣本二進制文件${NC}"
        return 1
    fi
    
    echo -e "${GREEN}使用樣本文件: $SAMPLE_BINARY${NC}"
    echo
    
    echo -e "${YELLOW}執行 r2 -q -c iS $SAMPLE_BINARY${NC}"
    r2 -q -c iS "$SAMPLE_BINARY"
    echo
    
    echo -e "${YELLOW}執行 r2 -q -c iSS $SAMPLE_BINARY${NC}"
    r2 -q -c iSS "$SAMPLE_BINARY"
    echo
    
    echo -e "${YELLOW}執行 r2 -q -c iE $SAMPLE_BINARY${NC}"
    r2 -q -c iE "$SAMPLE_BINARY"
    echo
    
    echo -e "${YELLOW}執行 r2 -q -c \"aaa;afl\" $SAMPLE_BINARY | grep -E \"imp.|sym.|loc.imp\"${NC}"
    r2 -q -c "aaa;afl" "$SAMPLE_BINARY" | grep -E "imp.|sym.|loc.imp"
    echo
    
    return 0
}

# 只處理一個樣本
process_sample() {
    echo -e "${BLUE}樣本處理模式 - 只處理一個文件${NC}"
    
    # 找一個樣本JSON文件
    SAMPLE_JSON=$(find "$BASE_PATH/results/data" -name "*.json" | head -n 1)
    
    if [ -z "$SAMPLE_JSON" ]; then
        echo -e "${RED}找不到樣本JSON文件${NC}"
        return 1
    fi
    
    echo -e "${GREEN}使用樣本文件: $SAMPLE_JSON${NC}"
    
    # 創建一個臨時修改版的Python腳本只處理這一個文件
    TMP_SCRIPT="${BASE_PATH}/scripts/tmp_filter_sample.py"
    cat "$PYTHON_SCRIPT" > "$TMP_SCRIPT"
    
    # 在main函數之前插入一個樣本處理函數
    sed -i '/def main():/i \
def process_sample(sample_path):\
    """只處理一個樣本文件"""\
    logger.info(f"樣本處理模式 - 只處理: {sample_path}")\
    original_binary_dir = os.path.join(BASE_PATH, "data")\
    return process_file(sample_path, original_binary_dir)\
' "$TMP_SCRIPT"
    
    # 替換main函數內容
    sed -i '/def main():/,/if __name__ == "__main__":/c\
def main():\
    """樣本處理主函數"""\
    start_time = time.time()\
    \
    # 確保目錄存在\
    os.makedirs(DATASET_PATH, exist_ok=True)\
    os.makedirs(os.path.join(DATASET_PATH, "train", "benign"), exist_ok=True)\
    os.makedirs(os.path.join(DATASET_PATH, "train", "malware"), exist_ok=True)\
    os.makedirs(os.path.join(DATASET_PATH, "test", "benign"), exist_ok=True)\
    os.makedirs(os.path.join(DATASET_PATH, "test", "malware"), exist_ok=True)\
    \
    # 處理樣本文件\
    success = process_sample("'"$SAMPLE_JSON"'")\
    \
    duration = time.time() - start_time\
    logger.info(f"樣本處理完成! 結果: {"成功" if success else "失敗"}, 耗時: {duration:.2f}秒")\
\
if __name__ == "__main__":\
' "$TMP_SCRIPT"
    
    # 執行臨時腳本
    python3 "$TMP_SCRIPT"
    
    # 刪除臨時腳本
    rm "$TMP_SCRIPT"
    
    return 0
}

# 主處理函數
main_process() {
    echo -e "${BLUE}開始執行完整處理...${NC}"
    
    # 檢查Python腳本是否存在
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo -e "${RED}錯誤: Python腳本不存在: $PYTHON_SCRIPT${NC}"
        return 1
    fi
    
    # 如果指定了強制模式，刪除現有的數據集目錄
    if [ "$FORCE_MODE" = true ]; then
        echo -e "${YELLOW}強制模式: 刪除現有的數據集目錄...${NC}"
        rm -rf "${BASE_PATH}/dataset"
    fi
    
    # 執行Python腳本
    if [ "$VERBOSE_MODE" = true ]; then
        python3 -u "$PYTHON_SCRIPT"
    else
        python3 "$PYTHON_SCRIPT"
    fi
    
    # 檢查處理結果
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}處理完成!${NC}"
        echo -e "${BLUE}數據集已保存至: ${BASE_PATH}/dataset${NC}"
        
        # 顯示結果統計
        echo -e "${BLUE}結果統計:${NC}"
        echo "訓練集 (benign): $(find "${BASE_PATH}/dataset/train/benign" -name "*.json" | wc -l) 個文件"
        echo "訓練集 (malware): $(find "${BASE_PATH}/dataset/train/malware" -name "*.json" | wc -l) 個文件"
        echo "測試集 (benign): $(find "${BASE_PATH}/dataset/test/benign" -name "*.json" | wc -l) 個文件"
        echo "測試集 (malware): $(find "${BASE_PATH}/dataset/test/malware" -name "*.json" | wc -l) 個文件"
        
        return 0
    else
        echo -e "${RED}處理失敗!${NC}"
        return 1
    fi
}

# 默認參數
CHECK_MODE=false
DRY_RUN_MODE=false
SAMPLE_MODE=false
FORCE_MODE=false
VERBOSE_MODE=false

# 解析命令行參數
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--check)
            CHECK_MODE=true
            shift
            ;;
        -d|--dry-run)
            DRY_RUN_MODE=true
            shift
            ;;
        -s|--sample)
            SAMPLE_MODE=true
            shift
            ;;
        -f|--force)
            FORCE_MODE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE_MODE=true
            shift
            ;;
        *)
            echo -e "${RED}未知選項: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# 主執行流程
if [ "$CHECK_MODE" = true ]; then
    check_dependencies
    exit $?
fi

if [ "$DRY_RUN_MODE" = true ]; then
    do_dry_run
    exit $?
fi

if [ "$SAMPLE_MODE" = true ]; then
    process_sample
    exit $?
fi

# 檢查依賴
check_dependencies
if [ $? -ne 0 ]; then
    echo -e "${RED}依賴檢查失敗，無法繼續執行${NC}"
    exit 1
fi

# 執行主處理
main_process
exit $?