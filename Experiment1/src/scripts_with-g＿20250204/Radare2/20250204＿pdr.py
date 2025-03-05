import r2pipe
import os
from datetime import datetime

def analyze_function(binary_path, function_name):
    try:
        r2 = r2pipe.open(binary_path)
        r2.cmd('aaa')  
        
        # 獲取所有函數
        functions = r2.cmdj('aflj')  
        if not functions:
            return f"No functions found in {binary_path}"
        
        # 尋找目標函數
        target_func = None
        for func in functions:
            if func['name'].endswith(function_name):
                target_func = func
                break
        
        if target_func:
            r2.cmd(f's {target_func["offset"]}')
            ir = r2.cmd('pdr')
            return ir
        else:
            return f"Function {function_name} not found in {binary_path}"
            
    except Exception as e:
        return f"Error analyzing {binary_path}: {str(e)}"
    finally:
        if r2:
            r2.quit()

def compare_binary_functions(arm_path, mips_path, output_dir="analysis_results"):
    # 創建輸出目錄
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成輸出文件名（包含時間戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"ir_analysis_{timestamp}.txt")
    
    # 要分析的函數列表
    functions_to_analyze = [
        "attack_tcp_syn",
        "attack_udp_generic",
        "attack_init",
        "attack_app_http",
        "attack_gre_ip",
        "killer_kill",
        "scanner_kill"
    ]
    
    with open(output_file, 'w') as f:
        # 寫入分析頭部信息
        f.write(f"IR Analysis Report - {timestamp}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"ARM Binary: {arm_path}\n")
        f.write(f"MIPS Binary: {mips_path}\n\n")
        
        # 分析每個函數
        for func_name in functions_to_analyze:
            f.write(f"\nAnalyzing function: {func_name}\n")
            f.write("=" * 50 + "\n\n")
            
            # 分析 ARM 版本
            f.write(f"ARM IR:\n{'-' * 20}\n")
            arm_ir = analyze_function(arm_path, func_name)
            f.write(arm_ir + "\n\n")
            
            # 分析 MIPS 版本
            f.write(f"MIPS IR:\n{'-' * 20}\n")
            mips_ir = analyze_function(mips_path, func_name)
            f.write(mips_ir + "\n\n")
            
            f.write("\n" + "=" * 50 + "\n")

def main():
    arm_binary = "../output_arm/mirai.arm"
    mips_binary = "../output_mips/mirai.mips"
    
    # 檢查文件是否存在
    if not os.path.exists(arm_binary):
        print(f"Error: ARM binary not found at {arm_binary}")
        return
    
    if not os.path.exists(mips_binary):
        print(f"Error: MIPS binary not found at {mips_binary}")
        return
    
    print("Starting analysis...")
    compare_binary_functions(arm_binary, mips_binary)
    print("Analysis complete. Results saved in analysis_results directory.")

if __name__ == "__main__":
    main()