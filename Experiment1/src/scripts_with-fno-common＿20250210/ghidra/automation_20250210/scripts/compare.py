import os
import glob
import json
import pandas as pd

def jaccard_score(A, B):
    if len(A.union(B)) == 0:
        return 0
    return len(A.intersection(B)) / len(A.union(B))

def build_func_info(pcode_dict, func_names):
    """
    建立 mapping: function name -> (address, opcode set)
    """
    info = {}
    for addr, lines in pcode_dict.items():
        name = func_names.get(addr, addr)
        opcode_set = set()
        for line in lines:
            tokens = line.split()
            if tokens:
                if tokens[0].startswith('(') and len(tokens) > 3:
                    opcode_set.add(tokens[3])
                elif len(tokens) > 1:
                    opcode_set.add(tokens[1])
        info[name] = (addr, opcode_set)
    return info

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
    # 本例只比較 arm 與 mips
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
        arm_addr, arm_op_set = arm_info[func]
        mips_addr, mips_op_set = mips_info[func]
        sim = jaccard_score(arm_op_set, mips_op_set)
        rows.append({
            "ARM Address": arm_addr,
            "ARM Function Name": func,
            "MIPS Address": mips_addr,
            "MIPS Function Name": func,
            "Similarity Score": sim
        })

    df = pd.DataFrame(rows, columns=["ARM Address", "ARM Function Name", "MIPS Address", "MIPS Function Name", "Similarity Score"])
    output_csv = os.path.join(COMPARE_DIR, f"pcode_similarity_{ts}_arm_vs_mips.csv")
    df.to_csv(output_csv, index=False)
    print(f"儲存比較結果到 {output_csv}")
