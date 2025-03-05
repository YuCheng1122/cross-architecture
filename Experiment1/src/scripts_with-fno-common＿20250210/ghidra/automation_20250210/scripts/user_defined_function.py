#!/usr/bin/env python3
import csv

# 讀取自定義函式清單，這個檔案是你剛才從 tags 中抽取出來的
user_defined_funcs = set()
with open('/home/tommy/user_defined_funcs.txt', 'r') as f:
    for line in f:
        func = line.strip()
        if func:
            user_defined_funcs.add(func)

# 輸入與輸出 CSV 檔案的路徑
input_csv = '/home/tommy/cross-architecture/Experiment1/src/scripts_with-fno-common＿20250210/ghidra/automation_20250210/results/compare/pcode_similarity_20250210_113636_arm_vs_mips_20250213154413.csv'
output_csv = '/home/tommy/cross-architecture/Experiment1/src/scripts_with-fno-common＿20250210/ghidra/automation_20250210/results/compare/pcode_similarity_20250210_113636_arm_vs_mips_20250213154413_marked.csv'

with open(input_csv, 'r', newline='') as fin, open(output_csv, 'w', newline='') as fout:
    reader = csv.DictReader(fin)
    # 新增一個欄位 UserDefined
    fieldnames = reader.fieldnames + ['UserDefined']
    writer = csv.DictWriter(fout, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        arm_func = row['ARM Function Name'].strip()
        mips_func = row['MIPS Function Name'].strip()
        # 如果 ARM 或 MIPS 的函式名稱在自定義函式清單中，則標記為 Yes
        if arm_func in user_defined_funcs or mips_func in user_defined_funcs:
            row['UserDefined'] = 'Yes'
        else:
            row['UserDefined'] = 'No'
        writer.writerow(row)
