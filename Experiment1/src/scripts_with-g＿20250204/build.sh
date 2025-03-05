#!/bin/bash

# 添加工具鏈到 PATH
export PATH="$HOME/x-tools/arm-unknown-linux-gnueabi/bin:$HOME/x-tools/mips-unknown-linux-gnu/bin:$PATH"

# 編譯參數設定
COMMON_FLAGS="-O0 -g -fno-inline -fno-optimize-sibling-calls -fno-stack-protector -fno-exceptions -fcommon"
BOT_DIR="/home/tommy/cross-architecture/Experiment1/MIRAI/Mirai-Source-Code/mirai/bot"
# 編譯函數
compile_arch() {
    local arch=$1
    local compiler=$2
    local objdump_cmd="${arch}-unknown-linux-gnu-objdump"  # 修正的 objdump 命令
    local output_dir="output_${arch}"
    
    mkdir -p ${output_dir}
    
    # 編譯所有源文件
    for src in ${BOT_DIR}/*.c; do
        ${compiler} ${COMMON_FLAGS} -c ${src} -o ${output_dir}/$(basename ${src} .c).o
    done
    
    # 鏈接
    ${compiler} ${COMMON_FLAGS} -static ${output_dir}/*.o -o ${output_dir}/mirai.${arch} -lpthread
    
    # 導出符號表
    if command -v ${objdump_cmd} &> /dev/null; then
        ${objdump_cmd} -t ${output_dir}/mirai.${arch} > ${output_dir}/symbols.txt
    else
        echo "Warning: ${objdump_cmd} not found, skipping symbol dump"
    fi
}

# 編譯兩個版本
compile_arch "arm" "arm-unknown-linux-gnueabi-gcc"
compile_arch "mips" "mips-unknown-linux-gnu-gcc"

# 驗證調試信息
check_debug_info() {
    local arch=$1
    local output_dir="output_${arch}"
    
    echo "Checking debug info for ${arch}..."
    if [ -f "${output_dir}/mirai.${arch}" ]; then
        readelf -S ${output_dir}/mirai.${arch} | grep debug
    else
        echo "Binary file not found: ${output_dir}/mirai.${arch}"
    fi
}

check_debug_info "arm"
check_debug_info "mips"