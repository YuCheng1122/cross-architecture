import pandas as pd
import numpy as np
import glob
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score

# 讀取其他架構的訓練資料 (檔名為 'other_arch_train.csv')
other_arch_train = pd.read_csv('other_arch_train.csv')

# 利用 glob 找出所有 x86 的 train fold 與 test fold 檔案
train_fold_files = sorted(glob.glob('train_fold_*.csv'))
test_fold_files = sorted(glob.glob('test_fold_*.csv'))

# 儲存每個 fold 的評估指標
fold_metrics = []

# 假設 train 與 test fold 檔案數量相同且對應 (例如 fold 1, 2, ... 10)
for train_file, test_file in zip(train_fold_files, test_fold_files):
    # 從檔名取得 fold 編號
    fold_number = os.path.splitext(os.path.basename(train_file))[0].split('_')[-1]
    
    # 讀取 x86 的 train fold 資料
    x86_train = pd.read_csv(train_file)
    
    # 合併 x86 的訓練資料與其他架構的資料
    combined_train = pd.concat([x86_train, other_arch_train], ignore_index=True)
    X_train = combined_train.drop(['file_name', 'CPU', 'label'], axis=1)
    y_train = combined_train['label']
    
    # 讀取對應的 x86 測試 fold
    test_df = pd.read_csv(test_file)
    X_test = test_df.drop(['true_label', 'pred_label'], axis=1, errors='ignore')
    y_test = test_df['true_label']
    
    # 建立並訓練 Random Forest 模型
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train, y_train)
    
    # 預測並計算評估指標
    y_pred = clf.predict(X_test)
    f1 = f1_score(y_test, y_pred, average='macro')
    precision = precision_score(y_test, y_pred, average='macro')
    recall = recall_score(y_test, y_pred, average='macro')
    
    print(f"Fold {fold_number}: F1 = {f1:.4f}, Precision = {precision:.4f}, Recall = {recall:.4f}")
    
    # 儲存預測結果
    result_df = X_test.copy()
    result_df['true_label'] = y_test
    result_df['pred_label'] = y_pred
    result_filename = f'enhancement_experiment_fold_{fold_number}_predictions.csv'
    result_df.to_csv(result_filename, index=False)
    
    # 紀錄該 fold 的指標
    fold_metrics.append({'fold': fold_number, 'f1': f1, 'precision': precision, 'recall': recall})

# 計算所有 fold 的平均指標
avg_f1 = np.mean([m['f1'] for m in fold_metrics])
avg_precision = np.mean([m['precision'] for m in fold_metrics])
avg_recall = np.mean([m['recall'] for m in fold_metrics])

print(f"Average across all folds: F1 = {avg_f1:.4f}, Precision = {avg_precision:.4f}, Recall = {avg_recall:.4f}")
