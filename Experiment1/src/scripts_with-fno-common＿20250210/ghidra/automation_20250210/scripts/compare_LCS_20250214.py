import os
import glob
import json
import pandas as pd
from datetime import datetime

def jaccard_score(A, B):
    intersection = len(A.intersection(B))
    union = len(A.union(B))
    if union == 0:
        return 0, 0, 0
    return intersection / union, intersection, union

def calculate_cls_similarity(seq1, seq2):
    """
    計算兩個序列的 CLS (Common Longest Subsequence) 相似度
    """
    m, n = len(seq1), len(seq2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq1[i-1] == seq2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    
    cls_length = dp[m][n]
    # 計算相似度分數 (0-1之間)
    score = (2.0 * cls_length) / (len(seq1) + len(seq2)) if (len(seq1) + len(seq2)) > 0 else 0
    
    return score, cls_length

def build_func_info(pcode_dict, func_names):
    """
    建立 mapping: function name -> (address, opcode set, opcode sequence)
    """
    info = {}
    for addr, lines in pcode_dict.items():
        name = func_names.get(addr, addr)
        opcode_set = set()
        opcode_seq = []  # 新增：保存 opcode 序列
        for line in lines:
            tokens = line.split()
            if tokens:
                if tokens[0].startswith('(') and len(tokens) > 3:
                    opcode = tokens[3]
                    opcode_set.add(opcode)
                    opcode_seq.append(opcode)
                elif len(tokens) > 1:
                    opcode = tokens[1]
                    opcode_set.add(opcode)
                    opcode_seq.append(opcode)
        info[name] = (addr, opcode_set, opcode_seq)  # 修改：加入 opcode_seq
    return info

def load_user_defined_funcs(filepath):
    user_defined_funcs = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                func = line.strip()
                if func:
                    user_defined_funcs.add(func)
    except FileNotFoundError:
        print(f"Warning: User defined functions file {filepath} not found")
    return user_defined_funcs

# 結果存放目錄
RESULTS_DIR = "../results"
COMPARE_DIR = os.path.join(RESULTS_DIR, "compare")
os.makedirs(COMPARE_DIR, exist_ok=True)

def load_data_from_dir(relative_dir):
    """
    從 RESULTS/relative_dir 下讀取第一個檔案（假設僅有一個 JSON 檔）
    """
    full_path = os.path.join(RESULTS_DIR, relative_dir)
    files = glob.glob(os.path.join(full_path, "*"))
    if not files:
        print(f"找不到 {relative_dir} 結果檔案")
        return None
    with open(files[0], "r") as f:
        data = json.load(f)
    return data

# 載入使用者定義的函式
user_defined_funcs = load_user_defined_funcs('/home/tommy/user_defined_funcs.txt')

# 找出 RESULTS 目錄下的 timestamp 子目錄（排除 compare 資料夾）
timestamp_dirs = [d for d in os.listdir(RESULTS_DIR)
                  if os.path.isdir(os.path.join(RESULTS_DIR, d)) and d.lower() != "compare"]

if not timestamp_dirs:
    print("找不到 timestamp 目錄")
    exit(1)

timestamp_dirs.sort()
for ts in timestamp_dirs:
    ts_path = os.path.join(RESULTS_DIR, ts)
    arch_dirs = [d for d in os.listdir(ts_path) if os.path.isdir(os.path.join(ts_path, d))]
    
    arm_dir = None
    mips_dir = None
    for ad in arch_dirs:
        if ad.lower() == "arm":
            arm_dir = ad
        elif ad.lower() == "mips":
            mips_dir = ad
    if arm_dir is None or mips_dir is None:
        print(f"{ts} 下找不到 arm 或 mips 結果")
        continue

    data_arm = load_data_from_dir(os.path.join(ts, arm_dir))
    data_mips = load_data_from_dir(os.path.join(ts, mips_dir))
    if data_arm is None or data_mips is None:
        continue

    pcode_arm = data_arm.get("pcode", {})
    func_names_arm = data_arm.get("func_names", {})
    pcode_mips = data_mips.get("pcode", {})
    func_names_mips = data_mips.get("func_names", {})
    if not pcode_arm or not pcode_mips:
        print(f"在 {ts} 下, arm 或 mips 結果中找不到 pcode 資料")
        continue

    arm_info = build_func_info(pcode_arm, func_names_arm)
    mips_info = build_func_info(pcode_mips, func_names_mips)
    common_funcs = set(arm_info.keys()) & set(mips_info.keys())
    if not common_funcs:
        print(f"{ts} 下 arm 與 mips 沒有共同函數")
        continue

    rows = []
    for func in sorted(common_funcs):
        arm_addr, arm_op_set, arm_op_seq = arm_info[func]  # 修改：解包三個值
        mips_addr, mips_op_set, mips_op_seq = mips_info[func]  # 修改：解包三個值
        
        # 計算 Jaccard 相似度
        sim, intersection, union = jaccard_score(arm_op_set, mips_op_set)
        
        # 計算 CLS 相似度
        cls_sim, cls_length = calculate_cls_similarity(arm_op_seq, mips_op_seq)
        
        # 判斷是否為使用者定義的函式
        is_user_defined = 1 if (func in user_defined_funcs) else 0
        
        # 計算 ARM 和 MIPS 的函式集合大小
        arm_set_size = len(arm_op_set)
        mips_set_size = len(mips_op_set)
        
        rows.append({
            "ARM Address": arm_addr,
            "ARM Function Name": func,
            "ARM Set Size": arm_set_size,
            "ARM Sequence Length": len(arm_op_seq),
            "MIPS Address": mips_addr,
            "MIPS Function Name": func,
            "MIPS Set Size": mips_set_size,
            "MIPS Sequence Length": len(mips_op_seq),
            "Similarity Score": sim,
            "Intersection Size": intersection,
            "Union Size": union,
            "CLS Length": cls_length,  # 新增
            "CLS Similarity Score": cls_sim,  # 新增
            "UserDefined": is_user_defined
        })

    df = pd.DataFrame(rows, columns=[
        "ARM Address", "ARM Function Name", "ARM Set Size", "ARM Sequence Length",
        "MIPS Address", "MIPS Function Name", "MIPS Set Size", "MIPS Sequence Length",
        "Similarity Score", "Intersection Size", "Union Size",
        "CLS Length", "CLS Similarity Score",  # 新增
        "UserDefined"
    ])
    
    # 取得當前時間戳記
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 修改輸出檔名
    output_csv = os.path.join(COMPARE_DIR, f"LCS_Jascard_pcode_similarity_{ts}_arm_vs_mips_{current_time}.csv")
    df.to_csv(output_csv, index=False)
    print(f"儲存比較結果到 {output_csv}")