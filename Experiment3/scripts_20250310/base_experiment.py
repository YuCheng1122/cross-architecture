import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, precision_score, recall_score

# 讀取已經整理好的 x86 資料集
df = pd.read_csv('x86_dataset.csv')

# 假設資料欄位包含：file_name, CPU, label 與其他數值特徵
# 這裡刪除 file_name 與 CPU，剩下的特徵用於訓練
X = df.drop(['file_name', 'CPU', 'label'], axis=1)
y = df['label']

# 建立 Stratified 10-fold 交叉驗證
skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)

fold = 1
f1_list = []
precision_list = []
recall_list = []

for train_index, test_index in skf.split(X, y):
    # 切分訓練與測試資料
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]
    
    # 建立並訓練 Random Forest 模型
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train, y_train)
    
    # 預測
    y_pred = clf.predict(X_test)
    
    # 計算 F1, Precision, Recall（使用 macro 平均）
    f1 = f1_score(y_test, y_pred, average='macro')
    precision = precision_score(y_test, y_pred, average='macro')
    recall = recall_score(y_test, y_pred, average='macro')
    
    f1_list.append(f1)
    precision_list.append(precision)
    recall_list.append(recall)
    
    print(f"Fold {fold} -- F1: {f1:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}")
    
    # 儲存該折的測試資料（包含原始特徵、真實標籤及預測結果）
    test_fold = X_test.copy()
    test_fold['true_label'] = y_test
    test_fold['pred_label'] = y_pred
    test_fold.to_csv(f'test_fold_{fold}.csv', index=False)
    
    # 儲存該折的訓練資料（包含原始特徵及真實標籤）
    train_fold = X_train.copy()
    train_fold['true_label'] = y_train
    train_fold.to_csv(f'train_fold_{fold}.csv', index=False)
    
    fold += 1

print(f"\nAverage F1: {np.mean(f1_list):.4f}")
print(f"Average Precision: {np.mean(precision_list):.4f}")
print(f"Average Recall: {np.mean(recall_list):.4f}")
