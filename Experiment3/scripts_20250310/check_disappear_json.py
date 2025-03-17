import os
import csv

# 定義路徑
csv_path = '/home/tommy/cross-architecture/Experiment3/csv/Cross-arch_Dataset_20250310103953.csv'
benign_dir = '/home/tommy/cross-architecture/Experiment3/results/data/benign'
malware_dir = '/home/tommy/cross-architecture/Experiment3/results/data/malware'

# 讀取 CSV 檔案中的 file_name
file_names_in_csv = set()
with open(csv_path, 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        file_names_in_csv.add(row['file_name'])

# 收集目錄中的所有檔案
files_in_dir = set()

# 處理 benign 目錄
for subdir in os.listdir(benign_dir):
    subdir_path = os.path.join(benign_dir, subdir)
    if os.path.isdir(subdir_path):
        for file in os.listdir(subdir_path):
            base_name = file.split('_')[0] if '_' in file else file
            base_name = os.path.splitext(base_name)[0]
            files_in_dir.add(base_name)

# 處理 malware 目錄
for subdir in os.listdir(malware_dir):
    subdir_path = os.path.join(malware_dir, subdir)
    if os.path.isdir(subdir_path):
        for file in os.listdir(subdir_path):
            base_name = file.split('_')[0] if '_' in file else file
            base_name = os.path.splitext(base_name)[0]
            files_in_dir.add(base_name)

# 檢查 CSV 中的每個 file_name 是否存在於目錄結構中
missing_files = file_names_in_csv - files_in_dir
found_files = file_names_in_csv.intersection(files_in_dir)

# 輸出結果
print(f"CSV 中總共有 {len(file_names_in_csv)} 個檔案")
print(f"所有目錄中總共有 {len(files_in_dir)} 個檔案")
print(f"找到的檔案數量: {len(found_files)}")
print(f"缺少的檔案數量: {len(missing_files)}")

# 輸出缺少的檔案到文字檔
if missing_files:
    with open('missing_files.txt', 'w') as f:
        for file in sorted(missing_files):
            f.write(f"{file}\n")
    print("已將缺少的檔案寫入 missing_files.txt")