import os
import glob
import json
import pandas as pd

def jaccard_score(A, B):
    if len(A.union(B)) == 0:
        return 0
    return len(A.intersection(B)) / len(A.union(B))

def pcode_set(pcode_dict):
    pcode_func_set = {}
    for func_addr, lines in pcode_dict.items():
        opcode_set = set()
        for line in lines:
            tokens = line.split()
            if tokens:
                if tokens[0].startswith('(') and len(tokens) > 3:
                    opcode_set.add(tokens[3])
                elif len(tokens) > 1:
                    opcode_set.add(tokens[1])
        pcode_func_set[func_addr] = opcode_set
    return pcode_func_set

# 結果存放路徑（results 下的子目錄，例如 arm、mips、...）
RESULTS_DIR = "../results"
# 輸出比較結果的目錄
COMPARE_DIR = os.path.join(RESULTS_DIR, "compare")
os.makedirs(COMPARE_DIR, exist_ok=True)

# 動態取得 RESULTS 內所有子目錄（排除 compare 資料夾）
subdirs = [d for d in os.listdir(RESULTS_DIR)
           if os.path.isdir(os.path.join(RESULTS_DIR, d)) and d.lower() != "compare"]

if len(subdirs) < 2:
    print("至少需要兩個結果資料夾才能進行比較")
    exit(1)

subdirs.sort()

# 定義一個函數，讀取指定子目錄中第一個 .txt 檔案並回傳 pcode 資料
def load_pcode_from_dir(dir_name):
    txt_files = glob.glob(os.path.join(RESULTS_DIR, dir_name, "*.txt"))
    if not txt_files:
        print(f"找不到 {dir_name} 結果檔案")
        return None
    with open(txt_files[0], 'r') as f:
        data = json.load(f)
    pcode = data.get("pcode", {})
    if not pcode:
        print(f"{dir_name} 結果檔案中找不到 pcode 資料")
    return pcode

# 兩兩比較所有結果目錄
for i in range(len(subdirs)):
    for j in range(i+1, len(subdirs)):
        arch1 = subdirs[i]
        arch2 = subdirs[j]
        pcode_dict1 = load_pcode_from_dir(arch1)
        pcode_dict2 = load_pcode_from_dir(arch2)
        if pcode_dict1 is None or pcode_dict2 is None:
            continue
        pcode_set1 = pcode_set(pcode_dict1)
        pcode_set2 = pcode_set(pcode_dict2)
        functions1 = list(pcode_set1.keys())
        functions2 = list(pcode_set2.keys())
        # 建立 DataFrame 比對每個函數之間的 Jaccard 相似度
        df = pd.DataFrame(index=functions1, columns=functions2)
        for func1 in functions1:
            for func2 in functions2:
                sim = jaccard_score(pcode_set1[func1], pcode_set2[func2])
                df.loc[func1, func2] = sim
        output_csv = os.path.join(COMPARE_DIR, f"pcode_similarity_{arch1}_vs_{arch2}.csv")
        df.to_csv(output_csv, index=True)
        print(f"儲存比較結果到 {output_csv}")
