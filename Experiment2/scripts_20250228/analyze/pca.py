import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score
from sklearn.feature_selection import SelectFromModel
import os
from datetime import datetime

def load_data(train_benign_file, train_malware_file, test_benign_file, test_malware_file):
    """載入訓練和測試資料"""
    print("載入資料...")
    
    # 載入訓練資料
    train_benign_df = pd.read_csv(train_benign_file)
    train_malware_df = pd.read_csv(train_malware_file)
    
    # 載入測試資料
    test_benign_df = pd.read_csv(test_benign_file)
    test_malware_df = pd.read_csv(test_malware_file)
    
    # 添加標籤
    train_benign_df['is_malware'] = 0
    train_malware_df['is_malware'] = 1
    test_benign_df['is_malware'] = 0
    test_malware_df['is_malware'] = 1
    
    # 添加資料來源標籤
    train_benign_df['data_source'] = 'train'
    train_malware_df['data_source'] = 'train'
    test_benign_df['data_source'] = 'test'
    test_malware_df['data_source'] = 'test'
    
    return train_benign_df, train_malware_df, test_benign_df, test_malware_df

def get_features(df):
    """獲取特徵欄位，排除非特徵欄位"""
    exclude_cols = ['file_name', 'CPU', 'label', 'family', 'is_malware', 'data_source']
    feature_cols = [col for col in df.columns if col not in exclude_cols]
    
    # 過濾掉全為零的欄位
    non_zero_features = []
    for col in feature_cols:
        if df[col].sum() > 0:
            non_zero_features.append(col)
    
    return non_zero_features

def analyze_feature_differences(all_data, feature_cols, output_dir='./results'):
    """分析PowerPC和其他架構之間的特徵差異"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n分析PowerPC與其他架構的特徵差異...")
    
    # 確保family欄位存在，如果沒有則添加一個默認值
    if 'family' not in all_data.columns:
        all_data['family'] = 'Unknown'
    
    # 將Mirai和Gafgyt標記出來，其他malware標記為Other
    malware_data = all_data[all_data['is_malware'] == 1].copy()
    malware_data.loc[~malware_data['family'].isin(['Mirai', 'Gafgyt']), 'family'] = 'Other_Malware'
    
    # 將所有benign標記為Benign
    benign_data = all_data[all_data['is_malware'] == 0].copy()
    benign_data['family'] = 'Benign'
    
    # 合併資料
    labeled_data = pd.concat([benign_data, malware_data])
    
    # 分離PowerPC和非PowerPC資料
    powerpc_data = labeled_data[labeled_data['CPU'] == 'PowerPC']
    other_data = labeled_data[labeled_data['CPU'] != 'PowerPC']
    
    # 計算每個架構中惡意軟體家族的分佈
    print("\nPowerPC樣本分佈:")
    powerpc_dist = powerpc_data['family'].value_counts()
    print(powerpc_dist)
    
    print("\n其他架構樣本分佈:")
    other_dist = other_data['family'].value_counts()
    print(other_dist)
    
    # 1. 特徵統計分析：計算所有特徵的平均值，按family分組
    feature_stats = {}
    
    # 2. 比較PowerPC vs 其他架構 (Benign & Malware)
    print("\n計算PowerPC vs 其他架構的特徵差異...")
    
    # 計算PowerPC良性/惡意軟體的特徵平均值
    powerpc_benign = powerpc_data[powerpc_data['family'] == 'Benign']
    powerpc_malware = powerpc_data[powerpc_data['family'] != 'Benign']
    
    if len(powerpc_benign) > 0 and len(powerpc_malware) > 0:
        powerpc_benign_mean = powerpc_benign[feature_cols].mean()
        powerpc_malware_mean = powerpc_malware[feature_cols].mean()
        
        # 計算其他架構良性/惡意軟體的特徵平均值
        other_benign = other_data[other_data['family'] == 'Benign']
        other_malware = other_data[other_data['family'] != 'Benign']
        
        other_benign_mean = other_benign[feature_cols].mean()
        other_malware_mean = other_malware[feature_cols].mean()
        
        # 計算差異比例
        benign_diff_ratio = (powerpc_benign_mean - other_benign_mean) / other_benign_mean.replace(0, 1)
        malware_diff_ratio = (powerpc_malware_mean - other_malware_mean) / other_malware_mean.replace(0, 1)
        
        # 創建差異DataFrame
        benign_diff_df = pd.DataFrame({
            'PowerPC_Benign_Mean': powerpc_benign_mean,
            'Other_Benign_Mean': other_benign_mean,
            'Difference': powerpc_benign_mean - other_benign_mean,
            'Difference_Ratio': benign_diff_ratio
        })
        
        malware_diff_df = pd.DataFrame({
            'PowerPC_Malware_Mean': powerpc_malware_mean,
            'Other_Malware_Mean': other_malware_mean,
            'Difference': powerpc_malware_mean - other_malware_mean,
            'Difference_Ratio': malware_diff_ratio
        })
        
        # 按差異絕對值排序
        benign_diff_df = benign_diff_df.sort_values('Difference_Ratio', key=abs, ascending=False)
        malware_diff_df = malware_diff_df.sort_values('Difference_Ratio', key=abs, ascending=False)
        
        # 保存結果
        benign_diff_df.to_csv(f'{output_dir}/{timestamp}_powerpc_vs_other_benign_diff.csv')
        malware_diff_df.to_csv(f'{output_dir}/{timestamp}_powerpc_vs_other_malware_diff.csv')
        
        print(f"良性檔案最大差異特徵 (PowerPC vs 其他架構):")
        print(benign_diff_df.head(10))
        
        print(f"\n惡意軟體最大差異特徵 (PowerPC vs 其他架構):")
        print(malware_diff_df.head(10))
        
        # 繪製最大差異特徵圖表
        plot_top_diff_features(benign_diff_df, 'Benign', output_dir, timestamp)
        plot_top_diff_features(malware_diff_df, 'Malware', output_dir, timestamp)
    
    # 3. 比較PowerPC上的不同惡意軟體家族
    print("\n分析PowerPC上不同惡意軟體家族的特徵差異...")
    
    # 檢查是否有足夠的Mirai和Gafgyt樣本
    powerpc_mirai = powerpc_data[powerpc_data['family'] == 'Mirai']
    powerpc_gafgyt = powerpc_data[powerpc_data['family'] == 'Gafgyt']
    powerpc_other_malware = powerpc_data[powerpc_data['family'] == 'Other_Malware']
    
    family_stats = {}
    # 計算平均值 (只計算有樣本的家族)
    if len(powerpc_benign) > 0:
        family_stats['Benign'] = powerpc_benign[feature_cols].mean()
    if len(powerpc_mirai) > 0:
        family_stats['Mirai'] = powerpc_mirai[feature_cols].mean()
    if len(powerpc_gafgyt) > 0:
        family_stats['Gafgyt'] = powerpc_gafgyt[feature_cols].mean()
    if len(powerpc_other_malware) > 0:
        family_stats['Other_Malware'] = powerpc_other_malware[feature_cols].mean()
    
    # 如果至少有兩個家族，計算它們之間的差異
    if len(family_stats) >= 2:
        # 創建一個合併的DataFrame
        family_df = pd.DataFrame(family_stats)
        family_df.to_csv(f'{output_dir}/{timestamp}_powerpc_family_feature_means.csv')
        
        # 計算分離度 (Gafgyt vs Mirai)
        if 'Gafgyt' in family_stats and 'Mirai' in family_stats:
            gafgyt_mirai_diff = (family_stats['Gafgyt'] - family_stats['Mirai']).abs()
            gafgyt_mirai_diff = gafgyt_mirai_diff.sort_values(ascending=False)
            gafgyt_mirai_diff.to_csv(f'{output_dir}/{timestamp}_powerpc_gafgyt_vs_mirai_diff.csv')
            
            print("\nGafgyt和Mirai間最大差異特徵:")
            print(gafgyt_mirai_diff.head(10))
        
        # 計算惡意軟體家族與良性檔案的差異
        for family_name in ['Mirai', 'Gafgyt', 'Other_Malware']:
            if family_name in family_stats and 'Benign' in family_stats:
                family_benign_diff = (family_stats[family_name] - family_stats['Benign']).abs()
                family_benign_diff = family_benign_diff.sort_values(ascending=False)
                family_benign_diff.to_csv(f'{output_dir}/{timestamp}_powerpc_{family_name}_vs_benign_diff.csv')
                
                print(f"\n{family_name}和良性檔案間最大差異特徵:")
                print(family_benign_diff.head(10))
        
        # 繪製家族特徵熱圖
        plot_family_heatmap(family_df, output_dir, timestamp)
    
    # 4. 使用機器學習找出重要特徵
    print("\n使用機器學習識別重要特徵...")
    
    # PowerPC上的Benign vs Malware分類
    if len(powerpc_benign) > 0 and len(powerpc_malware) > 0:
        X = powerpc_data[feature_cols].fillna(0)
        y = powerpc_data['is_malware']
        
        # 使用Random Forest識別重要特徵
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X, y)
        
        # 獲取特徵重要性
        feature_importance = pd.DataFrame({
            'Feature': feature_cols,
            'Importance': rf.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        # 保存結果
        feature_importance.to_csv(f'{output_dir}/{timestamp}_powerpc_benign_malware_feature_importance.csv', index=False)
        
        print("\nPowerPC上Benign vs Malware分類的重要特徵:")
        print(feature_importance.head(10))
        
        # 繪製特徵重要性
        plot_feature_importance(feature_importance, "Benign vs Malware", output_dir, timestamp)
    
    # 5. Mirai vs Gafgyt分類 (如果有足夠樣本)
    if len(powerpc_mirai) >= 5 and len(powerpc_gafgyt) >= 5:
        mirai_gafgyt_data = pd.concat([powerpc_mirai, powerpc_gafgyt])
        X = mirai_gafgyt_data[feature_cols].fillna(0)
        y = (mirai_gafgyt_data['family'] == 'Mirai').astype(int)  # Mirai=1, Gafgyt=0
        
        # 使用Random Forest識別重要特徵
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X, y)
        
        # 獲取特徵重要性
        feature_importance = pd.DataFrame({
            'Feature': feature_cols,
            'Importance': rf.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        # 保存結果
        feature_importance.to_csv(f'{output_dir}/{timestamp}_powerpc_mirai_vs_gafgyt_feature_importance.csv', index=False)
        
        print("\nPowerPC上Mirai vs Gafgyt分類的重要特徵:")
        print(feature_importance.head(10))
        
        # 繪製特徵重要性
        plot_feature_importance(feature_importance, "Mirai vs Gafgyt", output_dir, timestamp)
    
    print(f"\n分析完成，結果保存在 {output_dir} 目錄下")

def plot_top_diff_features(diff_df, label_type, output_dir, timestamp):
    """繪製最顯著差異特徵的圖表"""
    plt.figure(figsize=(12, 8))
    
    # 取出前10個差異最大的特徵
    top_diff = diff_df.head(10)
    
    # 計算顏色（正值為藍色，負值為紅色）
    colors = ['blue' if val >= 0 else 'red' for val in top_diff['Difference_Ratio']]
    
    # 繪製柱狀圖
    sns.barplot(x=top_diff.index, y='Difference_Ratio', data=top_diff, palette=colors)
    
    plt.title(f'PowerPC vs 其他架構 {label_type} 檔案的Top 10特徵差異比例', fontsize=16)
    plt.xlabel('特徵', fontsize=14)
    plt.ylabel('差異比例 (PowerPC / 其他架構 - 1)', fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # 保存圖表
    plt.savefig(f'{output_dir}/{timestamp}_powerpc_vs_other_{label_type.lower()}_top_diff.png', dpi=300)
    plt.close()

def plot_family_heatmap(family_df, output_dir, timestamp):
    """繪製家族特徵比較熱圖"""
    # 選取最具差異性的前20個特徵
    # 計算所有家族列間的標準差
    std_df = family_df.std(axis=1)
    top_features = std_df.sort_values(ascending=False).head(20).index
    
    # 篩選出這些特徵
    plot_df = family_df.loc[top_features]
    
    # 繪製熱圖
    plt.figure(figsize=(14, 10))
    
    # 使用clustermap自動按相似度聚類行和列
    cmap = sns.diverging_palette(220, 10, as_cmap=True)
    g = sns.clustermap(
        plot_df, 
        cmap=cmap,
        center=0,
        col_cluster=True,
        row_cluster=True,
        linewidths=.75,
        figsize=(14, 10),
        fmt='.2f',
        cbar_kws={"shrink": .5}
    )
    
    plt.title('PowerPC上不同家族的特徵分佈熱圖', fontsize=16)
    plt.tight_layout()
    
    # 保存圖表
    plt.savefig(f'{output_dir}/{timestamp}_powerpc_family_heatmap.png', dpi=300)
    plt.close()

def plot_feature_importance(importance_df, label, output_dir, timestamp):
    """繪製特徵重要性圖表"""
    plt.figure(figsize=(10, 8))
    
    # 取前15個重要特徵
    top_features = importance_df.head(15)
    
    # 繪製柱狀圖
    sns.barplot(x='Importance', y='Feature', data=top_features)
    
    plt.title(f'PowerPC上{label}分類的Top 15重要特徵', fontsize=16)
    plt.xlabel('特徵重要性', fontsize=14)
    plt.ylabel('特徵', fontsize=14)
    plt.tight_layout()
    
    # 保存圖表
    label_str = label.lower().replace(" ", "_").replace("vs", "_vs_")
    plt.savefig(f'{output_dir}/{timestamp}_powerpc_{label_str}_feature_importance.png', dpi=300)
    plt.close()

def main():
    train_benign_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_train_benign_file_features.csv'
    train_malware_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_train_malware_file_features.csv'
    test_benign_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_test_benign_file_features.csv'
    test_malware_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_test_malware_file_features.csv'
    
    # 載入資料
    train_benign_df, train_malware_df, test_benign_df, test_malware_df = load_data(
        train_benign_file, train_malware_file, test_benign_file, test_malware_file
    )
    
    # 合併所有資料以供分析
    all_data = pd.concat([train_benign_df, train_malware_df, test_benign_df, test_malware_df])
    
    # 獲取特徵
    feature_cols = get_features(all_data)
    print(f"使用 {len(feature_cols)} 個非零特徵進行分析")
    
    # 分析PowerPC與其他架構的差異
    analyze_feature_differences(all_data, feature_cols)

if __name__ == "__main__":
    main()