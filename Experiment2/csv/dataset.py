import pandas as pd
import numpy as np
import os

# Define file paths
benign_path = '/home/tommy/cross-architecture/Experiment2/csv/benignware_info.csv'
malware_path = '/home/tommy/cross-architecture/Experiment2/csv/Malware202403_info.csv'

# Read CSV files
print("Loading CSV files...")
benign_df = pd.read_csv(benign_path)
malware_df = pd.read_csv(malware_path)

# Print the first few rows to verify data structure
print("\nSample of benign data:")
print(benign_df.head())
print("\nSample of malware data:")
print(malware_df.head())

# Count records before processing
print(f"\nInitial record counts:")
print(f"Benign files: {benign_df.shape[0]}")
print(f"Malware files: {malware_df.shape[0]}")

# Filter out packed samples
print("\nFiltering out packed samples...")
benign_df = benign_df[benign_df['is_packed'] == 0]
malware_df = malware_df[malware_df['is_packed'] == 0]

print(f"After filtering out packed samples:")
print(f"Benign files: {benign_df.shape[0]}")
print(f"Malware files: {malware_df.shape[0]}")

# Filter out SINGLETON samples using regex
print("\nFiltering out SINGLETON samples...")
import re
singleton_pattern = re.compile(r'SINGLETON:', re.IGNORECASE)
malware_df = malware_df[~malware_df['family'].astype(str).str.contains(singleton_pattern)]

print(f"After filtering out SINGLETON samples:")
print(f"Malware files: {malware_df.shape[0]}")

# Process benign data
benign_df['label'] = 'benign'
benign_df['family'] = 'Benign'  # Add family column for benign files

# Select only required columns
benign_selected = benign_df[['file_name', 'CPU', 'label', 'family']]
malware_selected = malware_df[['file_name', 'CPU', 'label', 'family']]

# Replace "Advanced Micro Devices X86-64" with "X86-64"
benign_selected.loc[benign_selected['CPU'] == 'Advanced Micro Devices X86-64', 'CPU'] = 'X86-64'
malware_selected.loc[malware_selected['CPU'] == 'Advanced Micro Devices X86-64', 'CPU'] = 'X86-64'

# Combine datasets
combined_df = pd.concat([benign_selected, malware_selected], ignore_index=True)

# Define the required counts for each CPU-family combination
count_requirements = [
    # ARM
    {'CPU': 'ARM', 'family': 'mirai', 'count': 3285},
    {'CPU': 'ARM', 'family': 'gafgyt', 'count': 3285},
    {'CPU': 'ARM', 'family': 'Benign', 'count': 3285},
    {'CPU': 'ARM', 'family': 'penguin', 'count': 3285},
    {'CPU': 'ARM', 'family': 'hajime', 'count': 3285},
    {'CPU': 'ARM', 'family': 'tsunami', 'count': 2001},
    {'CPU': 'ARM', 'family': 'hiddad', 'count': 1786},
    {'CPU': 'ARM', 'family': 'dvmap', 'count': 1644},
    {'CPU': 'ARM', 'family': 'dofloo', 'count': 1596},
    {'CPU': 'ARM', 'family': 'mobidash', 'count': 1461},
    
    # Intel 80386
    {'CPU': 'Intel 80386', 'family': 'xorddos', 'count': 3285},
    {'CPU': 'Intel 80386', 'family': 'mirai', 'count': 3285},
    {'CPU': 'Intel 80386', 'family': 'gafgyt', 'count': 3285},
    {'CPU': 'Intel 80386', 'family': 'ingopack', 'count': 3285},
    {'CPU': 'Intel 80386', 'family': 'setag', 'count': 3285},
    {'CPU': 'Intel 80386', 'family': 'Benign', 'count': 3285},
    {'CPU': 'Intel 80386', 'family': 'mobidash', 'count': 3013},
    {'CPU': 'Intel 80386', 'family': 'tsunami', 'count': 2682},
    {'CPU': 'Intel 80386', 'family': 'dofloo', 'count': 1750},
    {'CPU': 'Intel 80386', 'family': 'ddostf', 'count': 828},
    
    # X86-64 (Advanced Micro Devices X86-64)
    {'CPU': 'X86-64', 'family': 'ngioweb', 'count': 3285},
    {'CPU': 'X86-64', 'family': 'gafgyt', 'count': 3285},
    {'CPU': 'X86-64', 'family': 'mirai', 'count': 3285},
    {'CPU': 'X86-64', 'family': 'prometei', 'count': 3285},
    {'CPU': 'X86-64', 'family': 'Benign', 'count': 3285},
    {'CPU': 'X86-64', 'family': 'tsunami', 'count': 3285},
    {'CPU': 'X86-64', 'family': 'xmrig', 'count': 2776},
    {'CPU': 'X86-64', 'family': 'mobidash', 'count': 1668},
    {'CPU': 'X86-64', 'family': 'fakeapp', 'count': 1609},
    {'CPU': 'X86-64', 'family': 'ladvix', 'count': 1530},
    
    # MIPS R3000
    {'CPU': 'MIPS R3000', 'family': 'mirai', 'count': 3285},
    {'CPU': 'MIPS R3000', 'family': 'Benign', 'count': 3285},
    {'CPU': 'MIPS R3000', 'family': 'gafgyt', 'count': 3285},
    {'CPU': 'MIPS R3000', 'family': 'hajime', 'count': 3285},
    {'CPU': 'MIPS R3000', 'family': 'tsunami', 'count': 1813},
    {'CPU': 'MIPS R3000', 'family': 'mozi', 'count': 1266},
    {'CPU': 'MIPS R3000', 'family': 'dakkatoni', 'count': 609},
    {'CPU': 'MIPS R3000', 'family': 'berbew', 'count': 490},
    {'CPU': 'MIPS R3000', 'family': 'mobidash', 'count': 447},
    {'CPU': 'MIPS R3000', 'family': 'kaiji', 'count': 365},
    {'CPU': 'MIPS R3000', 'family': 'dofloo', 'count': 295},
]

# Set random seed for reproducibility
np.random.seed(42)

# Function to sample or take all available data according to requirements
def sample_data(df, cpu, family, count):
    subset = df[(df['CPU'] == cpu) & (df['family'] == family)]
    available_count = len(subset)
    
    if available_count == 0:
        print(f"Warning: No data found for CPU={cpu}, family={family}")
        return pd.DataFrame()
    
    if available_count <= count:
        print(f"Taking all {available_count} records for CPU={cpu}, family={family} (requested {count})")
        return subset
    else:
        print(f"Sampling {count} out of {available_count} records for CPU={cpu}, family={family}")
        return subset.sample(count, random_state=42)

# Initialize an empty DataFrame for the final dataset
final_df = pd.DataFrame(columns=['file_name', 'CPU', 'label', 'family'])

# Process regular count requirements
for req in count_requirements:
    samples = sample_data(combined_df, req['CPU'], req['family'], req['count'])
    final_df = pd.concat([final_df, samples], ignore_index=True)
    
# Special cases processing
print("\nProcessing special cases:")

# MC68000, Sparc, AArch64: Take all malware but no benign
for cpu in ['MC68000', 'Sparc', 'AArch64']:
    malware_subset = combined_df[(combined_df['CPU'] == cpu) & (combined_df['family'] != 'Benign')]
    print(f"Taking all {len(malware_subset)} malware records for CPU={cpu}, no benign")
    final_df = pd.concat([final_df, malware_subset], ignore_index=True)

# PowerPC: Take all malware and benign
powerpc_subset = combined_df[combined_df['CPU'] == 'PowerPC']
print(f"Taking all {len(powerpc_subset)} records for CPU=PowerPC (both malware and benign)")
final_df = pd.concat([final_df, powerpc_subset], ignore_index=True)

# Remove any duplicate rows that might have been introduced
final_df = final_df.drop_duplicates()

# Print information about the final dataset
print("\nFinal dataset statistics:")
print(f"Total records: {len(final_df)}")
print("\nDistribution by CPU and family:")
print(final_df.groupby(['CPU', 'family']).size().reset_index(name='count'))

# Save the final dataset
output_path = os.path.join(os.path.dirname(benign_path), 'processed_malware_dataset.csv')
final_df.to_csv(output_path, index=False)
print(f"\nProcessed dataset saved to: {output_path}")

# Create distribution summary
distribution_summary = final_df.groupby(['CPU', 'label']).size().reset_index(name='count')
summary_path = os.path.join(os.path.dirname(benign_path), 'dataset_distribution.csv')
distribution_summary.to_csv(summary_path, index=False)
print(f"Distribution summary saved to: {summary_path}")