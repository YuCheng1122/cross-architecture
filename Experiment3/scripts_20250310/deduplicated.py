import pandas as pd
import os
import matplotlib.pyplot as plt
import seaborn as sns

def remove_duplicates(input_file, output_file):
    """
    Remove records with identical features but different filenames
    
    Parameters:
    input_file (str): Input CSV file path
    output_file (str): Output CSV file path
    
    Returns:
    tuple: (original record count, deduplicated record count, duplicate record count)
    """
    print(f"Processing file: {input_file}")
    
    # Read CSV file
    df = pd.read_csv(input_file)
    original_count = len(df)
    print(f"Original record count: {original_count}")
    
    # Get all feature columns except file_name, CPU, and label
    feature_columns = [col for col in df.columns if col not in ['file_name', 'CPU', 'label']]
    
    # Deduplicate based on all feature columns
    # Keep the first record in each group of duplicates
    df_unique = df.drop_duplicates(subset=feature_columns, keep='first')
    
    # Calculate duplicate record count
    unique_count = len(df_unique)
    duplicate_count = original_count - unique_count
    
    print(f"Deduplicated record count: {unique_count}")
    print(f"Removed duplicate records: {duplicate_count}")
    
    # Save deduplicated file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df_unique.to_csv(output_file, index=False)
    print(f"Deduplicated file saved to: {output_file}")
    
    return original_count, unique_count, duplicate_count, df_unique

def count_by_cpu_and_label(df):
    """
    統計每個CPU架構下的各標籤數量
    
    Parameters:
    df (DataFrame): 包含CPU和label欄位的資料框
    
    Returns:
    DataFrame: 統計結果
    """
    # 計算每個CPU和label組合的數量
    count_df = df.groupby(['CPU', 'label']).size().reset_index(name='count')
    
    # 將結果轉換為更易讀的形式
    result = count_df.pivot_table(index='CPU', columns='label', values='count', fill_value=0)
    
    # 增加總計列
    result['總計'] = result.sum(axis=1)
    
    # 增加總計行 - 使用 pd.concat 代替已棄用的 append 方法
    total_row = pd.Series(result.sum(), name='總計')
    result = pd.concat([result, total_row.to_frame().T])
    
    return result

def visualize_cpu_label_distribution(df, output_file):
    """
    Create a heatmap of CPU architecture and label distribution
    
    Parameters:
    df (DataFrame): DataFrame containing CPU and label columns
    output_file (str): Output image file path
    """
    # Count the number of samples for each CPU and label combination
    count_df = df.groupby(['CPU', 'label']).size().unstack(fill_value=0)
    
    plt.figure(figsize=(16, 10))
    
    # Create a custom colormap with black, yellow, and red
    colors = ['black', 'yellow', 'red']
    thresholds = [0, 45, 100, count_df.values.max()]
    cmap = plt.cm.colors.ListedColormap(['black', 'yellow', 'red'])
    bounds = [0, 45, 100, count_df.values.max() + 1]
    norm = plt.cm.colors.BoundaryNorm(bounds, cmap.N)
    
    # Create the heatmap
    ax = sns.heatmap(count_df, annot=True, fmt='d', cmap=cmap, norm=norm, linewidths=0.5, linecolor='gray')
    
    # Set title and labels
    plt.title('Sample Distribution by CPU Architecture and Family', fontsize=16)
    plt.xlabel('Family', fontsize=14)
    plt.ylabel('CPU Architecture', fontsize=14)
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha='right')
    
    # Create custom legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='black', label='< 45 samples'),
        Patch(facecolor='yellow', label='45-100 samples'),
        Patch(facecolor='red', label='> 100 samples')
    ]
    plt.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(1.15, 1))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Heatmap saved to: {output_file}")

def main():
    # 檔案路徑
    combined_file = '/home/tommy/cross-architecture/Experiment3/csv/20250316_cleaned_all_combined_file_features.csv'
    
    # 設定去重後的輸出檔案路徑
    output_dir = '/home/tommy/cross-architecture/Experiment3/csv/deduplicated'
    combined_output = f"{output_dir}/dedup_combined_file_features.csv"
    stats_output = f"{output_dir}/cpu_label_statistics.csv"
    chart_output = f"{output_dir}/cpu_label_distribution.png"
    
    # 處理檔案
    print("開始進行檔案去重處理...")
    
    # 處理合併檔案
    orig, uniq, dupes, df_unique = remove_duplicates(combined_file, combined_output)
    
    print("-" * 50)
    
    # 輸出總結資訊
    print("去重處理完成！")
    print(f"總記錄數: {orig}")
    print(f"去重後總記錄數: {uniq}")
    print(f"總移除重複記錄數: {dupes}")
    print(f"重複率: {(dupes / orig * 100):.2f}%")
    
    print("-" * 50)
    
    # 統計每個CPU架構下的各標籤數量
    print("統計每個CPU架構下的標籤數量...")
    stats_df = count_by_cpu_and_label(df_unique)
    stats_df.to_csv(stats_output)
    print(f"已保存統計結果: {stats_output}")
    
    print("-" * 50)
    print("CPU架構與標籤的統計結果:")
    print(stats_df)
    
    # 視覺化結果
    try:
        print("繪製分佈圖...")
        visualize_cpu_label_distribution(df_unique, chart_output)
    except Exception as e:
        print(f"繪製分佈圖時出錯: {str(e)}")

if __name__ == "__main__":
    main()