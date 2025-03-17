#!/usr/bin/env python3
import pandas as pd
import os

def main():
    # 設定文件路徑
    file1_path = '/home/tommy/cross-architecture/Experiment3/csv/Sorted_Dataset_20250312114058.csv'
    file2_path = '/home/tommy/cross-architecture/Experiment3/csv/20250316_cleaned_all_combined_file_features.csv'
    
    # 設定輸出文件路徑
    output_dir = os.path.dirname(file1_path)
    output_filename = 'difference_result.csv'
    output_path = os.path.join(output_dir, output_filename)
    
    print(f"正在讀取第一個文件: {file1_path}")
    df1 = pd.read_csv(file1_path)
    
    print(f"正在讀取第二個文件: {file2_path}")
    df2 = pd.read_csv(file2_path)
    
    # 顯示兩個文件的資訊
    print(f"第一個文件 ({os.path.basename(file1_path)}) 包含 {len(df1)} 行")
    print(f"第二個文件 ({os.path.basename(file2_path)}) 包含 {len(df2)} 行")
    
    # 檢查兩個文件是否都包含 file_name 欄位
    if 'file_name' not in df1.columns or 'file_name' not in df2.columns:
        print("錯誤: 其中一個或兩個文件都缺少 file_name 欄位")
        print(f"第一個文件的列: {df1.columns.tolist()}")
        print(f"第二個文件的列: {df2.columns.tolist()}")
        return
    
    # 確保 CPU 和 label 欄位存在於第一個文件中
    required_columns = ['file_name', 'CPU', 'label']
    missing_columns = [col for col in required_columns if col not in df1.columns]
    if missing_columns:
        print(f"警告: 第一個文件缺少以下列: {missing_columns}")
        print(f"無法按照要求的順序輸出")
        return
    
    # 只用 file_name 欄位進行比較
    print(f"僅使用 file_name 欄位進行比較")
    
    # 找出在 df1 中但不在 df2 中的 file_name
    file_names_in_df1 = set(df1['file_name'])
    file_names_in_df2 = set(df2['file_name'])
    unique_file_names = file_names_in_df1 - file_names_in_df2
    
    # 篩選出只在第一個文件中的行
    difference = df1[df1['file_name'].isin(unique_file_names)]
    
    print(f"找到 {len(difference)} 個 file_name 在第一個文件中但不在第二個文件中")
    
    # 按照指定順序排列列（file_name, CPU, label）
    output_columns = ['file_name', 'CPU', 'label']
    
    # 檢查所有需要的列是否都存在
    for col in output_columns:
        if col not in difference.columns:
            print(f"錯誤: 結果缺少必要的列 {col}")
            return
    
    # 僅選擇所需的列並按照指定順序排列
    difference = difference[output_columns]
    
    # 保存結果
    difference.to_csv(output_path, index=False)
    print(f"結果已保存到: {output_path}")

if __name__ == "__main__":
    main()