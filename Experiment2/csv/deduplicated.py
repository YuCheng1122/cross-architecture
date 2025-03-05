import pandas as pd
import os

def remove_duplicates(input_file, output_file):
    """
    移除特徵完全相同但檔名不同的記錄
    
    Parameters:
    input_file (str): 輸入CSV檔案路徑
    output_file (str): 輸出CSV檔案路徑
    
    Returns:
    tuple: (原始記錄數, 去重後記錄數, 重複記錄數)
    """
    print(f"處理檔案: {input_file}")
    
    # 讀取CSV檔案
    df = pd.read_csv(input_file)
    original_count = len(df)
    print(f"原始記錄數: {original_count}")
    
    # 取得除了file_name之外的所有特徵欄位
    feature_columns = [col for col in df.columns if col != 'file_name']
    
    # 根據所有特徵欄位進行去重
    # 保留每組重複記錄中的第一條記錄
    df_unique = df.drop_duplicates(subset=feature_columns, keep='first')
    
    # 計算重複記錄數
    unique_count = len(df_unique)
    duplicate_count = original_count - unique_count
    
    print(f"去重後記錄數: {unique_count}")
    print(f"移除重複記錄數: {duplicate_count}")
    
    # 如果存在重複記錄，則保存去重後的檔案
    if duplicate_count > 0:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        df_unique.to_csv(output_file, index=False)
        print(f"已保存去重後的檔案: {output_file}")
    else:
        print("沒有發現重複記錄，不保存新檔案")
    
    return original_count, unique_count, duplicate_count

def main():
    # 檔案路徑
    train_benign_file = '/home/tommy/cross-architecture/Experiment2/csv/20250228_cleanedtrain_benign_file_features.csv'
    train_malware_file = '/home/tommy/cross-architecture/Experiment2/csv/20250228_cleanedtrain_malware_file_features.csv'
    test_benign_file = '/home/tommy/cross-architecture/Experiment2/csv/20250228_cleanedtest_benign_file_features.csv'
    test_malware_file = '/home/tommy/cross-architecture/Experiment2/csv/20250228_cleanedtest_malware_file_features.csv'
    
    # 設定去重後的輸出檔案路徑
    output_dir = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated'
    train_benign_output = f"{output_dir}/dedup_train_benign_file_features.csv"
    train_malware_output = f"{output_dir}/dedup_train_malware_file_features.csv"
    test_benign_output = f"{output_dir}/dedup_test_benign_file_features.csv"
    test_malware_output = f"{output_dir}/dedup_test_malware_file_features.csv"
    
    # 處理所有檔案
    print("開始進行檔案去重處理...")
    total_original = 0
    total_unique = 0
    total_duplicates = 0
    
    # 處理訓練集良性檔案
    orig, uniq, dupes = remove_duplicates(train_benign_file, train_benign_output)
    total_original += orig
    total_unique += uniq
    total_duplicates += dupes
    print("-" * 50)
    
    # 處理訓練集惡意檔案
    orig, uniq, dupes = remove_duplicates(train_malware_file, train_malware_output)
    total_original += orig
    total_unique += uniq
    total_duplicates += dupes
    print("-" * 50)
    
    # 處理測試集良性檔案
    orig, uniq, dupes = remove_duplicates(test_benign_file, test_benign_output)
    total_original += orig
    total_unique += uniq
    total_duplicates += dupes
    print("-" * 50)
    
    # 處理測試集惡意檔案
    orig, uniq, dupes = remove_duplicates(test_malware_file, test_malware_output)
    total_original += orig
    total_unique += uniq
    total_duplicates += dupes
    print("-" * 50)
    
    # 輸出總結資訊
    print("去重處理完成！")
    print(f"總記錄數: {total_original}")
    print(f"去重後總記錄數: {total_unique}")
    print(f"總移除重複記錄數: {total_duplicates}")
    print(f"重複率: {(total_duplicates / total_original * 100):.2f}%")

if __name__ == "__main__":
    main()