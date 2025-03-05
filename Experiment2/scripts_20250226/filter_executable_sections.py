#!/usr/bin/env python3
"""
過濾Ghidra分析結果中的函數及P-Code，只保留可執行區段中的部分。
使用radare2來獲取可執行區段的信息。
"""
import os
import sys
import json
import subprocess
import shutil
import logging
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime

# 設定基礎路徑
BASE_PATH = "/home/tommy/cross-architecture/Experiment2"
RESULTS_PATH = os.path.join(BASE_PATH, "results/data")
DATASET_PATH = os.path.join(BASE_PATH, "dataset")

# 設定日誌
LOG_DIR = os.path.join(BASE_PATH, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f'filter_exec_sections_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def configure_timing_logger():
    """配置計時日誌"""
    timing_logger = logging.getLogger('timing_logger')
    timing_logger.setLevel(logging.INFO)
    timing_handler = logging.FileHandler(os.path.join(LOG_DIR, f'timing_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'))
    timing_handler.setFormatter(logging.Formatter('%(asctime)s,%(message)s'))
    timing_logger.addHandler(timing_handler)
    return timing_logger

timing_logger = configure_timing_logger()

def get_executable_sections(binary_path):
    """
    使用radare2獲取二進制文件的可執行區段
    返回可執行區段的地址範圍列表
    """
    try:
        # 添加選項以提高穩定性
        env = os.environ.copy()
        # 設置環境變量來避免某些崩潰
        env["R2_CRASH_REPORTS"] = "0"
        
        # 運行radare2獲取節區信息，添加超時機制
        sections_cmd = ["r2", "-q", "-c", "iS", binary_path]
        try:
            sections_output = subprocess.check_output(
                sections_cmd, 
                stderr=subprocess.STDOUT, 
                text=True, 
                env=env,
                timeout=10  # 10秒超時
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"獲取節區信息超時: {binary_path}")
            return []
        
        # 獲取詳細的段信息，添加超時機制
        try:
            section_details_cmd = ["r2", "-q", "-c", "iSS", binary_path]
            section_details = subprocess.check_output(
                section_details_cmd, 
                stderr=subprocess.STDOUT, 
                text=True, 
                env=env,
                timeout=10  # 10秒超時
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"獲取詳細段信息超時: {binary_path}")
            section_details = ""
        
        # 嘗試另一種方法獲取可執行區段
        try:
            alternative_cmd = ["r2", "-q", "-c", "e bin.relocs.apply=true;iS", binary_path]
            alternative_output = subprocess.check_output(
                alternative_cmd, 
                stderr=subprocess.STDOUT, 
                text=True, 
                env=env,
                timeout=10  # 10秒超時
            )
            if not sections_output or "SIGABRT" in sections_output:
                sections_output = alternative_output
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            # 忽略這個替代方法的錯誤
            pass
        
        # 解析輸出找出可執行段
        executable_sections = []
        
        # 如果常規方法失敗，使用更簡單的方法
        if not executable_sections and ("SIGABRT" in sections_output or "invalid" in sections_output):
            try:
                # 嘗試使用更基本的命令
                simple_cmd = ["r2", "-q", "-c", "S", binary_path]
                simple_output = subprocess.check_output(
                    simple_cmd, 
                    stderr=subprocess.STDOUT, 
                    text=True, 
                    env=env,
                    timeout=5
                )
                
                # 從輸出中尋找可執行區段
                for line in simple_output.splitlines():
                    if "rwx" in line or "r-x" in line:
                        parts = line.split()
                        try:
                            # 嘗試解析地址和大小
                            for i, part in enumerate(parts):
                                if "0x" in part:
                                    vaddr = int(part, 16)
                                    # 假設下一個是大小
                                    if i+1 < len(parts) and "0x" in parts[i+1]:
                                        vsize = int(parts[i+1], 16)
                                        executable_sections.append((vaddr, vaddr + vsize))
                                        break
                        except (ValueError, IndexError):
                            continue
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        # 從標準輸出中解析可執行段
        for line in sections_output.splitlines():
            if ("exec" in line.lower() or "r-x" in line or "rwx" in line) and not line.startswith("["):
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        vaddr = int(parts[2], 16)
                        size = int(parts[3], 16)
                        executable_sections.append((vaddr, vaddr + size))
                    except (ValueError, IndexError):
                        continue
        
        # 從詳細信息中也提取可執行段
        for line in section_details.splitlines():
            if "perm=..x" in line or "flags=EXEC" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.startswith("vaddr="):
                        try:
                            vaddr = int(part.split("=")[1], 16)
                            vsize = int(parts[i+1].split("=")[1], 16)
                            executable_sections.append((vaddr, vaddr + vsize))
                        except (ValueError, IndexError):
                            continue
        
        # 如果沒有找到可執行段，但文件存在，添加一個默認段
        if not executable_sections and os.path.exists(binary_path) and os.path.getsize(binary_path) > 0:
            try:
                # 嘗試獲取文件的基本信息
                info_cmd = ["r2", "-q", "-c", "i", binary_path]
                info_output = subprocess.check_output(
                    info_cmd, 
                    stderr=subprocess.STDOUT, 
                    text=True, 
                    env=env,
                    timeout=5
                )
                
                # 尋找基地址和入口點
                base_addr = 0
                entry_point = 0
                file_size = os.path.getsize(binary_path)
                
                for line in info_output.splitlines():
                    if "baddr" in line:
                        try:
                            base_addr = int(line.split("0x")[1].split()[0], 16)
                        except (IndexError, ValueError):
                            pass
                    if "entry" in line:
                        try:
                            entry_point = int(line.split("0x")[1].split()[0], 16)
                        except (IndexError, ValueError):
                            pass
                
                # 如果找到入口點，添加一個合理的可執行段
                if entry_point > 0:
                    # 估計代碼段大小為文件大小的一半
                    code_size = file_size // 2
                    # 從入口點減去一些偏移作為開始
                    start = max(base_addr, entry_point - (code_size // 4))
                    end = start + code_size
                    executable_sections.append((start, end))
                    logger.info(f"沒有找到顯式可執行段，使用估計段: {hex(start)}-{hex(end)}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        return executable_sections
    except subprocess.CalledProcessError as e:
        logger.error(f"獲取可執行區段失敗: {e}")
        logger.error(f"輸出: {e.output}")
        return []
    except Exception as e:
        logger.error(f"處理可執行區段時發生錯誤: {e}")
        return []

def get_imported_functions(binary_path):
    """
    使用radare2獲取二進制文件的導入函數
    返回導入函數的地址列表
    """
    try:
        # 設置環境變量來避免某些崩潰
        env = os.environ.copy()
        env["R2_CRASH_REPORTS"] = "0"
        
        imported_functions = []
        
        try:
            # 運行radare2獲取導入函數信息
            imports_cmd = ["r2", "-q", "-c", "iE", binary_path]
            imports_output = subprocess.check_output(
                imports_cmd, 
                stderr=subprocess.STDOUT, 
                text=True, 
                env=env,
                timeout=10
            )
            
            # 從iE輸出中提取
            for line in imports_output.splitlines():
                if " FUNC " in line or " IMPORT " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            addr = parts[1]
                            if addr.startswith("0x"):
                                addr_int = int(addr, 16)
                                imported_functions.append(addr_int)
                        except (ValueError, IndexError):
                            continue
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.warning(f"獲取導入函數信息 (iE) 失敗: {binary_path}")
        
        try:
            # 使用AFL命令獲取更多導入函數信息，但限制分析時間避免懸掛
            afl_cmd = ["r2", "-q", "-c", "aa;afl", binary_path]
            afl_output = subprocess.check_output(
                afl_cmd, 
                stderr=subprocess.STDOUT, 
                text=True, 
                env=env,
                timeout=15  # 稍微長一點的超時
            )
            
            # 從afl輸出中提取外部函數
            for line in afl_output.splitlines():
                if any(x in line for x in ["imp.", "sym.", "loc.imp"]):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            addr = parts[0]
                            if addr.startswith("0x"):
                                addr_int = int(addr, 16)
                                imported_functions.append(addr_int)
                        except (ValueError, IndexError):
                            continue
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.warning(f"獲取函數列表 (afl) 失敗: {binary_path}")
            
            # 如果afl失敗，嘗試使用更簡單的命令
            try:
                simple_cmd = ["r2", "-q", "-c", "f", binary_path]
                simple_output = subprocess.check_output(
                    simple_cmd, 
                    stderr=subprocess.STDOUT, 
                    text=True, 
                    env=env,
                    timeout=5
                )
                
                for line in simple_output.splitlines():
                    if any(x in line for x in ["imp.", "sym.", "loc.imp"]):
                        parts = line.split()
                        if len(parts) >= 1:
                            try:
                                addr = parts[0]
                                if addr.startswith("0x"):
                                    addr_int = int(addr, 16)
                                    imported_functions.append(addr_int)
                            except (ValueError, IndexError):
                                continue
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        return list(set(imported_functions))  # 移除重複項
    except Exception as e:
        logger.error(f"處理導入函數時發生錯誤: {e}")
        return []

def address_in_executable_section(addr_str, executable_sections):
    """
    檢查地址是否在可執行區段中
    """
    try:
        # 將地址字符串轉換為整數
        addr = int(addr_str.strip().replace("0x", ""), 16)
        
        # 檢查地址是否在任何可執行區段中
        for start, end in executable_sections:
            if start <= addr < end:
                return True
        return False
    except ValueError:
        logger.warning(f"無法解析地址: {addr_str}")
        return False

def is_imported_function(addr_str, imported_functions):
    """
    檢查地址是否為導入函數
    """
    try:
        # 將地址字符串轉換為整數
        addr = int(addr_str.strip().replace("0x", ""), 16)
        
        # 檢查地址是否在導入函數列表中
        return addr in imported_functions
    except ValueError:
        logger.warning(f"無法解析地址: {addr_str}")
        return False

def filter_executable_functions(json_path, original_binary_path):
    """
    過濾JSON文件中的函數和P-Code，只保留在可執行區段中的部分，並排除導入的外部函數
    """
    start_time = time.time()
    logger.info(f"處理文件: {json_path}")
    
    try:
        # 檢查原始二進制文件是否存在
        if not os.path.exists(original_binary_path):
            logger.error(f"找不到原始二進制文件: {original_binary_path}")
            return None
        
        # 獲取可執行區段
        executable_sections = get_executable_sections(original_binary_path)
        if not executable_sections:
            logger.warning(f"未找到可執行區段: {original_binary_path}")
            # 即使沒有找到可執行區段，也繼續處理
            # 創建一個虛擬的可執行區段，包含整個地址空間
            # 這樣可以處理那些 radare2 無法正確分析的文件
            executable_sections = [(0, 0xFFFFFFFFFFFFFFFF)]
            logger.info(f"使用完整地址空間作為備用: {original_binary_path}")
        
        # 獲取導入函數
        imported_functions = get_imported_functions(original_binary_path)
        if not imported_functions:
            logger.info(f"未找到導入函數，可能是靜態鏈接或 radare2 分析失敗: {original_binary_path}")
        else:
            logger.info(f"找到 {len(imported_functions)} 個導入函數")
        
        # 讀取JSON文件
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        # 過濾函數調用
        filtered_function_calls = {}
        for addr, calls in data.get("function_calls", {}).items():
            # 檢查函數是否在可執行區段中且不是導入函數
            if address_in_executable_section(addr, executable_sections):
                # 如果沒有導入函數信息，則不進行導入函數過濾
                if not imported_functions or not is_imported_function(addr, imported_functions):
                    # 只保留在可執行區段中且不是導入函數的調用目標
                    filtered_calls = []
                    for call in calls:
                        if address_in_executable_section(call, executable_sections):
                            if not imported_functions or not is_imported_function(call, imported_functions):
                                filtered_calls.append(call)
                    filtered_function_calls[addr] = filtered_calls
        
        # 過濾P-Code
        filtered_pcode = {}
        for addr, pcode_list in data.get("pcode", {}).items():
            # 檢查函數是否在可執行區段中且不是導入函數
            if address_in_executable_section(addr, executable_sections):
                # 如果沒有導入函數信息，則不進行導入函數過濾
                if not imported_functions or not is_imported_function(addr, imported_functions):
                    filtered_pcode[addr] = pcode_list
        
        # 構建過濾後的數據
        filtered_data = {
            "function_calls": filtered_function_calls,
            "pcode": filtered_pcode
        }
        
        # 保留原始日誌信息
        if "log_info" in data:
            filtered_data["log_info"] = data["log_info"]
            # 添加過濾信息到日誌
            filtered_data["log_info"]["filter_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            filtered_data["log_info"]["executable_sections_count"] = len(executable_sections)
            filtered_data["log_info"]["imported_functions_count"] = len(imported_functions)
            filtered_data["log_info"]["original_functions_count"] = len(data.get("function_calls", {}))
            filtered_data["log_info"]["filtered_functions_count"] = len(filtered_function_calls)
        
        duration = time.time() - start_time
        timing_logger.info(f"過濾文件耗時,{json_path},{duration:.2f}秒")
        
        return filtered_data
    except Exception as e:
        logger.error(f"處理文件 {json_path} 時發生錯誤: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def save_filtered_data(filtered_data, output_path):
    """保存過濾後的數據到新的JSON文件"""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(filtered_data, f, indent=2)
        logger.info(f"過濾後的數據已保存到: {output_path}")
        return True
    except Exception as e:
        logger.error(f"保存過濾後的數據時發生錯誤: {e}")
        return False

def process_file(file_path, original_binary_dir):
    """處理單個JSON文件"""
    try:
        # 確定原始二進制文件路徑
        relative_path = os.path.relpath(file_path, RESULTS_PATH)
        dir_parts = relative_path.split(os.sep)
        
        if len(dir_parts) < 2:
            logger.warning(f"無法確定文件 {file_path} 的原始二進制文件位置")
            return False
        
        # 確定分類 (良性/惡意)
        category = "malware" if any(x in dir_parts for x in ["malware", "gafgyt", "ddos"]) else "benign"
        
        # 獲取架構信息
        arch = "unknown"
        with open(file_path, 'r') as f:
            data = json.load(f)
            if "log_info" in data and "architecture" in data["log_info"]:
                arch = data["log_info"]["architecture"].lower()
        
        # 確定文件名（去除架構後綴）
        file_name = os.path.basename(file_path)
        binary_name = file_name.split("_")[0]  # 假設文件名格式為 binary_arch.json
        
        # 構建原始二進制文件路徑
        original_binary_path = os.path.join(original_binary_dir, category, binary_name)
        
        # 如果直接路徑不存在，嘗試在子目錄中查找
        if not os.path.exists(original_binary_path):
            for root, _, files in os.walk(os.path.join(original_binary_dir, category)):
                if binary_name in files:
                    original_binary_path = os.path.join(root, binary_name)
                    break
            
            # 如果還是找不到，嘗試通過文件名的前兩個字符尋找
            if not os.path.exists(original_binary_path) and len(binary_name) >= 2:
                prefix = binary_name[:2]
                candidate_path = os.path.join(original_binary_dir, category, prefix, binary_name)
                if os.path.exists(candidate_path):
                    original_binary_path = candidate_path
            
            # 最後嘗試遞歸搜索整個目錄
            if not os.path.exists(original_binary_path):
                found = False
                for root, _, files in os.walk(original_binary_dir):
                    if binary_name in files:
                        original_binary_path = os.path.join(root, binary_name)
                        found = True
                        break
                
                if not found:
                    logger.warning(f"找不到原始二進制文件: {binary_name}")
                    # 即使找不到原始文件，也繼續處理JSON
        
        # 過濾數據
        filtered_data = filter_executable_functions(file_path, original_binary_path)
        if filtered_data is None:
            # 即使過濾失敗，也創建一個最小化的數據集
            logger.warning(f"使用原始數據作為備用: {file_path}")
            with open(file_path, 'r') as f:
                original_data = json.load(f)
                filtered_data = {
                    "function_calls": original_data.get("function_calls", {}),
                    "pcode": original_data.get("pcode", {})
                }
                if "log_info" in original_data:
                    filtered_data["log_info"] = original_data["log_info"]
                    filtered_data["log_info"]["filter_error"] = "Failed to filter executable sections"
        
        # 確定輸出路徑
        # PowerPC架構歸為測試集，其他架構歸為訓練集
        dataset_type = "test" if arch.lower() in ["powerpc", "ppc"] else "train"
        output_dir = os.path.join(DATASET_PATH, dataset_type, category)
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, os.path.basename(file_path))
        return save_filtered_data(filtered_data, output_path)
    except Exception as e:
        logger.error(f"處理文件 {file_path} 時發生錯誤: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def process_file_worker(args):
    """
    工作函數，用於多進程處理
    接收一個元組參數，包含文件路徑和原始二進制目錄
    """
    file_path, original_binary_dir = args
    return process_file(file_path, original_binary_dir)

def main():
    """主函數"""
    start_time = time.time()
    
    # 確保目錄存在
    os.makedirs(DATASET_PATH, exist_ok=True)
    os.makedirs(os.path.join(DATASET_PATH, "train", "benign"), exist_ok=True)
    os.makedirs(os.path.join(DATASET_PATH, "train", "malware"), exist_ok=True)
    os.makedirs(os.path.join(DATASET_PATH, "test", "benign"), exist_ok=True)
    os.makedirs(os.path.join(DATASET_PATH, "test", "malware"), exist_ok=True)
    
    # 獲取所有JSON文件
    json_files = []
    for root, _, files in os.walk(RESULTS_PATH):
        for file in files:
            if file.endswith(".json"):
                json_files.append(os.path.join(root, file))
    
    logger.info(f"找到 {len(json_files)} 個JSON文件需要處理")
    
    # 確定原始二進制文件目錄
    original_binary_dir = os.path.join(BASE_PATH, "data")
    if not os.path.exists(original_binary_dir):
        logger.error(f"找不到原始二進制文件目錄: {original_binary_dir}")
        sys.exit(1)
    
    # 使用進程池並行處理文件
    success_count = 0
    error_count = 0
    
    # 創建工作參數列表
    work_items = [(f, original_binary_dir) for f in json_files]
    
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        # 使用具名函數而不是lambda
        results = list(executor.map(process_file_worker, work_items))
        success_count = results.count(True)
        error_count = results.count(False)
    
    duration = time.time() - start_time
    logger.info(f"處理完成! 成功: {success_count}, 失敗: {error_count}, 總耗時: {duration:.2f}秒")
    timing_logger.info(f"總處理耗時,{duration:.2f}秒,共處理文件數,{len(json_files)},成功數,{success_count},失敗數,{error_count}")

if __name__ == "__main__":
    main()