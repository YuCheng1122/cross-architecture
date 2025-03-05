import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score, confusion_matrix
from datetime import datetime
import os

def load_data(train_benign_file, train_malware_file, test_benign_file, test_malware_file):
    """Load training and testing data"""
    print("Loading data...")
    
    # Load training data
    train_benign_df = pd.read_csv(train_benign_file)
    train_malware_df = pd.read_csv(train_malware_file)
    
    # Load testing data
    test_benign_df = pd.read_csv(test_benign_file)
    test_malware_df = pd.read_csv(test_malware_file)
    
    # Add labels
    train_benign_df['is_malware'] = 0
    train_malware_df['is_malware'] = 1
    test_benign_df['is_malware'] = 0
    test_malware_df['is_malware'] = 1
    
    return train_benign_df, train_malware_df, test_benign_df, test_malware_df

def get_features(df):
    """Get feature columns, excluding non-feature columns and zero columns"""
    exclude_cols = ['file_name', 'CPU', 'label', 'family', 'is_malware']
    feature_cols = [col for col in df.columns if col not in exclude_cols]
    
    # Filter out zero columns
    non_zero_features = []
    for col in feature_cols:
        if df[col].sum() > 0:
            non_zero_features.append(col)
    
    return non_zero_features

def calculate_metrics(y_true, y_pred):
    """Calculate basic performance metrics"""
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred),
        'recall': recall_score(y_true, y_pred),
        'f1': f1_score(y_true, y_pred)
    }
    
    return metrics

def evaluate_on_powerpc(train_cpu, train_benign_df, train_malware_df, 
                        test_benign_df, test_malware_df, feature_cols, 
                        random_seeds=[42, 123, 456, 789, 101]):
    """Train on specified architecture and test on PowerPC"""
    print(f"Training on {train_cpu}, testing on PowerPC...")
    
    # Get training data
    if train_cpu == 'all':
        # Use all training data
        train_benign = train_benign_df
        train_malware = train_malware_df
    else:
        # Filter by CPU
        train_benign = train_benign_df[train_benign_df['CPU'] == train_cpu]
        train_malware = train_malware_df[train_malware_df['CPU'] == train_cpu]
    
    # Skip if not enough training samples
    if len(train_benign) < 10 or len(train_malware) < 10:
        print(f"  Skipping {train_cpu} (insufficient training samples)")
        return None
    
    # Get testing data for PowerPC
    test_benign = test_benign_df[test_benign_df['CPU'] == 'PowerPC']
    test_malware = test_malware_df[test_malware_df['CPU'] == 'PowerPC']
    
    # Skip if not enough testing samples
    if len(test_benign) < 5 or len(test_malware) < 5:
        print(f"  Skipping PowerPC (insufficient testing samples)")
        return None
    
    # Print data sizes
    print(f"  Training data: {len(train_benign)} benign, {len(train_malware)} malware")
    print(f"  Testing data: {len(test_benign)} benign, {len(test_malware)} malware")
    
    # Combine training data
    train_data = pd.concat([train_benign, train_malware])
    
    # Combine testing data
    test_data = pd.concat([test_benign, test_malware])
    
    # Prepare training data
    X_train = train_data[feature_cols].fillna(0)
    y_train = train_data['is_malware']
    
    # Prepare testing data
    X_test = test_data[feature_cols].fillna(0)
    y_test = test_data['is_malware']
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Results for multiple runs
    run_results = []
    
    # Run with multiple random seeds
    for seed in random_seeds:
        print(f"  Running with seed {seed}")
        
        # Train Random Forest
        rf = RandomForestClassifier(n_estimators=100, random_state=seed)
        rf.fit(X_train_scaled, y_train)
        
        # Make predictions
        y_pred = rf.predict(X_test_scaled)
        
        # Calculate metrics
        metrics = calculate_metrics(y_test, y_pred)
        metrics['seed'] = seed
        
        # Add to results
        run_results.append(metrics)
    
    # Calculate statistics across runs
    f1_scores = [result['f1'] for result in run_results]
    mean_f1 = np.mean(f1_scores)
    std_f1 = np.std(f1_scores)
    
    print(f"  Mean F1 Score: {mean_f1:.4f} ± {std_f1:.4f}")
    
    # Compile results
    results = {
        'train_cpu': train_cpu,
        'train_samples': len(train_data),
        'test_samples': len(test_data),
        'mean_f1': mean_f1,
        'std_f1': std_f1,
        'run_results': run_results
    }
    
    return results

def plot_simple_f1_chart(all_results, output_dir='./results'):
    """Plot and save a simple F1 score chart"""
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Extract data for plotting
    train_cpus = [r['train_cpu'] for r in all_results]
    mean_f1s = [r['mean_f1'] for r in all_results]
    
    # Create DataFrame
    df = pd.DataFrame({
        'Architecture': train_cpus,
        'Mean F1 Score': mean_f1s
    })
    
    # Sort by mean F1 score
    df = df.sort_values('Mean F1 Score', ascending=False)
    
    # Define colors - deep purple, navy blue, teal, medium green, chartreuse
    custom_colors = ['#2D004A', '#304887', '#3D7D7C', '#4CAA66', '#B9CF45']
    
    # Make sure we have enough colors
    while len(custom_colors) < len(df):
        custom_colors.extend(custom_colors)
    
    # Set the style
    sns.set_style('whitegrid')
    plt.figure(figsize=(12, 7))
    
    # Create the bar chart with custom colors
    simple_bars = plt.bar(
        df['Architecture'], 
        df['Mean F1 Score'], 
        color=custom_colors[:len(df)]
    )
    
    # Add the values on top of each bar
    for bar in simple_bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width()/2., 
            height + 0.01,
            f'{height:.4f}', 
            ha='center', 
            va='bottom', 
            fontsize=12,
            fontweight='bold'
        )
    
    # Set the labels and title
    plt.title('F1 Scores on PowerPC by Training Architecture', fontsize=16)
    plt.xlabel('Training Architecture', fontsize=14)
    plt.ylabel('F1 Score', fontsize=14)
    
    # Set y-axis limits
    plt.ylim(0, 1.1)
    
    # Add a light grid for better readability
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(f'{output_dir}/{timestamp}_simple_f1_chart.png', dpi=300)
    plt.close()
    
    # Plot malware family performance for Self-PowerPC if available
    for result in all_results:
        if result['train_cpu'] == 'Self-PowerPC' and 'family_results' in result and result['family_results']:
            plot_family_performance(result, output_dir, timestamp)

def plot_family_performance(self_result, output_dir, timestamp):
    """Plot the performance metrics for different malware families"""
    family_results = self_result['family_results']
    
    # Prepare data for plotting
    families = []
    f1_scores = []
    recall_scores = []
    sample_counts = []
    
    for family, results_list in family_results.items():
        if not results_list:
            continue
            
        family_f1s = [r['f1'] for r in results_list]
        family_recalls = [r['recall'] for r in results_list]
        
        families.append(family)
        f1_scores.append(np.mean(family_f1s))
        recall_scores.append(np.mean(family_recalls))
        sample_counts.append(results_list[0]['count'])
    
    # If no valid family data, return
    if not families:
        return
    
    # Sort by F1 score
    sorted_indices = np.argsort(f1_scores)[::-1]  # Descending
    families = [families[i] for i in sorted_indices]
    f1_scores = [f1_scores[i] for i in sorted_indices]
    recall_scores = [recall_scores[i] for i in sorted_indices]
    sample_counts = [sample_counts[i] for i in sorted_indices]
    
    # Create a combined bar and scatter plot
    plt.figure(figsize=(14, 8))
    
    # Bar colors - use a blue gradient
    colors = plt.cm.Blues(np.linspace(0.6, 0.9, len(families)))
    
    # Plot F1 scores as bars
    bars = plt.bar(families, f1_scores, color=colors, alpha=0.8)
    
    # Add recall as points
    plt.scatter(families, recall_scores, color='red', s=100, zorder=3, label='Recall')
    
    # Add sample count as text
    for i, (family, count) in enumerate(zip(families, sample_counts)):
        plt.text(i, 0.05, f'n={count}', ha='center', va='bottom', 
                fontsize=9, rotation=0, color='black')
    
    # Add F1 values on top of bars
    for i, bar in enumerate(bars):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                f'{f1_scores[i]:.3f}', ha='center', va='bottom',
                fontsize=10, fontweight='bold')
    
    # Set labels and title
    plt.title('PowerPC Malware Family Detection Performance', fontsize=16)
    plt.xlabel('Malware Family', fontsize=14)
    plt.ylabel('Score', fontsize=14)
    plt.ylim(0, 1.1)
    plt.legend()
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha='right')
    
    # Add grid
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/{timestamp}_powerpc_family_performance.png', dpi=300)
    plt.close()

def evaluate_self_architecture(architecture, test_benign_df, test_malware_df, feature_cols, 
                        random_seeds=[42, 123, 456, 789, 101], train_ratio=0.8):
    """Train and test on the same architecture using a split of the test data"""
    print(f"\nEvaluating self-training for {architecture}...")
    
    # Filter test data for the specified architecture
    arch_benign = test_benign_df[test_benign_df['CPU'] == architecture]
    arch_malware = test_malware_df[test_malware_df['CPU'] == architecture]
    
    # Skip if not enough samples
    if len(arch_benign) < 10 or len(arch_malware) < 10:
        print(f"  Skipping {architecture} (insufficient samples)")
        return None
    
    # Print data sizes
    print(f"  Available data: {len(arch_benign)} benign, {len(arch_malware)} malware")
    
    # Analyze malware family distribution for PowerPC
    if 'family' in arch_malware.columns:
        family_counts = arch_malware['family'].value_counts()
        print(f"  Malware family distribution for {architecture}:")
        for family, count in family_counts.items():
            print(f"    {family}: {count}")
    
    # Results for multiple runs
    run_results = []
    
    # Results by malware family
    family_results = {}
    
    for seed in random_seeds:
        # Set random seed for reproducibility
        np.random.seed(seed)
        
        # Split benign data
        benign_indices = np.random.permutation(len(arch_benign))
        benign_train_idx = benign_indices[:int(train_ratio * len(benign_indices))]
        benign_test_idx = benign_indices[int(train_ratio * len(benign_indices)):]
        
        # Split malware data
        malware_indices = np.random.permutation(len(arch_malware))
        malware_train_idx = malware_indices[:int(train_ratio * len(malware_indices))]
        malware_test_idx = malware_indices[int(train_ratio * len(malware_indices)):]
        
        # Create training and testing sets
        train_benign = arch_benign.iloc[benign_train_idx]
        test_benign = arch_benign.iloc[benign_test_idx]
        train_malware = arch_malware.iloc[malware_train_idx]
        test_malware = arch_malware.iloc[malware_test_idx]
        
        # Combine training and testing data
        train_data = pd.concat([train_benign, train_malware])
        test_data = pd.concat([test_benign, test_malware])
        
        # Prepare training data
        X_train = train_data[feature_cols].fillna(0)
        y_train = train_data['is_malware']
        
        # Prepare testing data
        X_test = test_data[feature_cols].fillna(0)
        y_test = test_data['is_malware']
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Random Forest
        rf = RandomForestClassifier(n_estimators=100, random_state=seed)
        rf.fit(X_train_scaled, y_train)
        
        # Make predictions
        y_pred = rf.predict(X_test_scaled)
        
        # Calculate metrics
        metrics = calculate_metrics(y_test, y_pred)
        metrics['seed'] = seed
        
        # Add to results
        run_results.append(metrics)
        
        # Evaluate per malware family if available
        if 'family' in test_malware.columns:
            # Get all test indices to maintain original positions
            all_test_indices = pd.concat([test_benign['file_name'], test_malware['file_name']])
            predictions = pd.DataFrame({
                'file_name': all_test_indices.values,
                'true_label': y_test.values,
                'predicted': y_pred
            })
            
            # Analyze each family's performance
            for family in test_malware['family'].unique():
                if pd.isna(family) or family == '':
                    continue
                    
                # Get samples for this family
                family_samples = test_malware[test_malware['family'] == family]['file_name'].values
                
                # Get predictions for this family
                family_preds = predictions[predictions['file_name'].isin(family_samples)]
                
                if len(family_preds) > 0:
                    # Calculate metrics
                    family_y_true = np.ones(len(family_preds))  # All are malware
                    family_y_pred = family_preds['predicted'].values
                    
                    if family not in family_results:
                        family_results[family] = []
                    
                    # Calculate F1 score specifically for this family (treated as positive class)
                    family_tp = np.sum((family_y_true == 1) & (family_y_pred == 1))
                    family_fp = np.sum((family_y_true == 0) & (family_y_pred == 1))
                    family_fn = np.sum((family_y_true == 1) & (family_y_pred == 0))
                    
                    family_precision = family_tp / (family_tp + family_fp) if (family_tp + family_fp) > 0 else 0
                    family_recall = family_tp / (family_tp + family_fn) if (family_tp + family_fn) > 0 else 0
                    family_f1 = 2 * (family_precision * family_recall) / (family_precision + family_recall) if (family_precision + family_recall) > 0 else 0
                    
                    family_results[family].append({
                        'accuracy': np.mean(family_y_true == family_y_pred),
                        'precision': family_precision,
                        'recall': family_recall,
                        'f1': family_f1,
                        'count': len(family_preds),
                        'detected': np.sum(family_y_pred == 1),
                        'seed': seed
                    })
    
    # Calculate statistics across runs
    f1_scores = [result['f1'] for result in run_results]
    mean_f1 = np.mean(f1_scores)
    std_f1 = np.std(f1_scores)
    
    print(f"  Self-training F1 Score: {mean_f1:.4f} ± {std_f1:.4f}")
    
    # Calculate and print malware family performance
    if family_results:
        print(f"\n  Malware family detection performance:")
        family_avg_results = {}
        
        for family, results_list in family_results.items():
            if not results_list:
                continue
                
            family_f1s = [r['f1'] for r in results_list]
            family_recalls = [r['recall'] for r in results_list]
            avg_f1 = np.mean(family_f1s)
            avg_recall = np.mean(family_recalls)
            
            family_avg_results[family] = {
                'avg_f1': avg_f1,
                'avg_recall': avg_recall,
                'count': results_list[0]['count']
            }
            
            print(f"    {family}: F1={avg_f1:.4f}, Recall={avg_recall:.4f}, Count={results_list[0]['count']}")
    
    # Compile results
    results = {
        'train_cpu': f"Self-{architecture}",
        'train_samples': len(train_data),
        'test_samples': len(test_data),
        'mean_f1': mean_f1,
        'std_f1': std_f1,
        'run_results': run_results,
        'family_results': family_results if family_results else None
    }
    
    return results

def main():
    train_benign_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_train_benign_file_features.csv'
    train_malware_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_train_malware_file_features.csv'
    test_benign_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_test_benign_file_features.csv'
    test_malware_file = '/home/tommy/cross-architecture/Experiment2/csv/deduplicated/dedup_test_malware_file_features.csv'
    
    # Load data
    train_benign_df, train_malware_df, test_benign_df, test_malware_df = load_data(
        train_benign_file, train_malware_file, test_benign_file, test_malware_file
    )
    
    # Print CPU distributions
    print("\nTraining data CPU distribution:")
    train_cpu_dist = pd.DataFrame({
        'Benign': train_benign_df['CPU'].value_counts(),
        'Malware': train_malware_df['CPU'].value_counts()
    }).fillna(0)
    print(train_cpu_dist)
    
    print("\nTesting data CPU distribution:")
    test_cpu_dist = pd.DataFrame({
        'Benign': test_benign_df['CPU'].value_counts(),
        'Malware': test_malware_df['CPU'].value_counts()
    }).fillna(0)
    print(test_cpu_dist)
    
    # Print PowerPC malware family distribution if available
    powerpc_malware = test_malware_df[test_malware_df['CPU'] == 'PowerPC']
    if 'family' in powerpc_malware.columns:
        print("\nPowerPC malware family distribution:")
        family_dist = powerpc_malware['family'].value_counts()
        for family, count in family_dist.items():
            print(f"  {family}: {count}")
    
    # Get features from all data
    all_data = pd.concat([train_benign_df, train_malware_df, test_benign_df, test_malware_df])
    feature_cols = get_features(all_data)
    print(f"\nUsing {len(feature_cols)} non-zero features")
    
    # Define CPU architectures for training
    # Get all available architectures and add 'all'
    available_cpus = sorted(list(set(train_benign_df['CPU'].unique()) | set(train_malware_df['CPU'].unique())))
    available_cpus = [cpu for cpu in available_cpus if not pd.isna(cpu)]
    train_cpus = available_cpus + ['all']
    
    # Experiment configuration
    random_seeds = [42, 123, 456, 789, 101]  # Multiple seeds for reproducibility
    
    # Evaluate each architecture on PowerPC
    all_results = []
    for train_cpu in train_cpus:
        results = evaluate_on_powerpc(
            train_cpu,
            train_benign_df, train_malware_df,
            test_benign_df, test_malware_df,
            feature_cols,
            random_seeds=random_seeds
        )
        if results is not None:
            all_results.append(results)
    
    # Evaluate self-training for PowerPC (using 80% of test data for training, 20% for testing)
    self_train_results = evaluate_self_architecture(
        'PowerPC',
        test_benign_df, test_malware_df,
        feature_cols,
        random_seeds=random_seeds,
        train_ratio=0.8
    )
    
    if self_train_results is not None:
        all_results.append(self_train_results)
    
    # Save detailed PowerPC family performance to CSV if family data is available
    output_dir = './results'
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if self_train_results is not None and 'family_results' in self_train_results and self_train_results['family_results']:
        family_data = []
        
        for family, results_list in self_train_results['family_results'].items():
            if not results_list:
                continue
                
            f1_scores = [r['f1'] for r in results_list]
            precision_scores = [r['precision'] for r in results_list]
            recall_scores = [r['recall'] for r in results_list]
            
            family_data.append({
                'Family': family,
                'Count': results_list[0]['count'],
                'F1_Score': np.mean(f1_scores),
                'F1_StdDev': np.std(f1_scores),
                'Precision': np.mean(precision_scores),
                'Recall': np.mean(recall_scores),
                'Detection_Rate': np.mean([r['detected'] / r['count'] for r in results_list])
            })
        
        if family_data:
            family_df = pd.DataFrame(family_data)
            family_df = family_df.sort_values('F1_Score', ascending=False)
            family_df.to_csv(f'{output_dir}/{timestamp}_powerpc_family_performance.csv', index=False)
            print(f"\nPowerPC family performance statistics saved to {output_dir}/{timestamp}_powerpc_family_performance.csv")
    
    # Plot and save results
    if all_results:
        plot_simple_f1_chart(all_results)
    else:
        print("No results to plot.")
    
    print("\nExperiment completed. Results saved to the 'results' directory.")

if __name__ == "__main__":
    main()