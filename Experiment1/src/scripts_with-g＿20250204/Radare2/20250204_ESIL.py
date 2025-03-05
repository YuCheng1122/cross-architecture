import r2pipe
import os
from datetime import datetime

def analyze_function_esil(binary_path, function_name):
    r2 = r2pipe.open(binary_path)
    r2.cmd('aaa')  
    
    functions = r2.cmdj('aflj')
    target_func = None
    for func in functions:
        if function_name in func['name']:
            target_func = func
            break
            
    if target_func:
        r2.cmd(f's {target_func["offset"]}')
        esil = r2.cmd('pde')  
        disasm = r2.cmd('pdr')
        
        return {
            'offset': hex(target_func['offset']),
            'esil': esil,
            'disasm': disasm
        }
    return None

def compare_architectures(arm_binary, mips_binary, output_dir):
    # 創建輸出目錄（如果不存在）
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成輸出文件名（包含時間戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"esil_analysis_{timestamp}.txt")
    
    with open(output_file, 'w') as f:
        f.write("ESIL Analysis Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"ARM Binary: {arm_binary}\n")
        f.write(f"MIPS Binary: {mips_binary}\n\n")
        
        f.write("=== ARM Analysis ===\n")
        arm_result = analyze_function_esil(arm_binary, "attack_tcp_syn")
        if arm_result:
            f.write(f"Function address: {arm_result['offset']}\n\n")
            f.write("ESIL:\n")
            f.write(arm_result['esil'] + "\n")
            f.write("\nDisassembly:\n")
            f.write(arm_result['disasm'] + "\n")
        
        f.write("\n=== MIPS Analysis ===\n")
        mips_result = analyze_function_esil(mips_binary, "attack_tcp_syn")
        if mips_result:
            f.write(f"Function address: {mips_result['offset']}\n\n")
            f.write("ESIL:\n")
            f.write(mips_result['esil'] + "\n")
            f.write("\nDisassembly:\n")
            f.write(mips_result['disasm'] + "\n")

def main():
    arm_binary = "../output_arm/mirai.arm"
    mips_binary = "../output_mips/mirai.mips"
    output_dir = "/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/Radare2/analysis_results"
    
    print("Starting analysis...")
    compare_architectures(arm_binary, mips_binary, output_dir)
    print(f"Analysis complete. Results saved in {output_dir}")

if __name__ == "__main__":
    main()