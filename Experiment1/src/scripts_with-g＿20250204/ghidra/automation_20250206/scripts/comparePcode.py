import os
import re
import csv
from difflib import SequenceMatcher

def normalize_line(line):
    # 將所有 0x… 數字替換成 0xX，避免因數值不同而影響比較
    line = re.sub(r'0x[0-9a-fA-F]+', '0xX', line)
    # 可以加上其他規則，例如移除多餘空白
    return line.strip()

def get_pcode_content(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    marker = "High-level P-code:"
    idx = content.find(marker)
    if idx != -1:
        # 取 marker 之後的內容
        pcode = content[idx + len(marker):].strip()
        # 將每一行正規化
        lines = [normalize_line(line) for line in pcode.splitlines() if line.strip()]
        return "\n".join(lines)
    return ""

def similarity(s1, s2):
    return SequenceMatcher(None, s1, s2).ratio()

def read_map(dir_path):
    functions = {}
    map_path = os.path.join(dir_path, "function_map.csv")
    with open(map_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            label = row["Label"]
            function = row["Function"]
            source_file = row["SourceFile"]
            arch = row["Architecture"]
            # 檔案命名規則: label_<Label>_<Function>_pcode.txt
            pcode_filename = f"label_{label}_{function}_pcode.txt"
            pcode_path = os.path.join(dir_path, pcode_filename)
            if os.path.exists(pcode_path):
                pcode_content = get_pcode_content(pcode_path)
            else:
                pcode_content = ""
            functions[label] = {
                "Function": function,
                "SourceFile": source_file,
                "Architecture": arch,
                "Pcode": pcode_content
            }
    return functions

def count_pcode_lines(pcodeContent):
    if pcodeContent:
        return len(pcodeContent.splitlines())
    return 0

def calculate_match_ratio(arm_content, mips_content):
    return similarity(arm_content, mips_content) * 100

def generate_comparison_notes(armLines, mipsLines, matchRatio):
    notes = []
    if armLines > 0 and abs(armLines - mipsLines) > armLines * 0.2:
        notes.append("P-code行數差異顯著")
    if matchRatio < 50:
        notes.append("低相似度")
    elif matchRatio > 90:
        notes.append("高相似度")
    return "; ".join(notes)

def main():
    # 修改這裡的路徑以符合您的目錄
    arm_dir = "/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/ghidra/automation_20250206/results/analysis_20250206_165530/arm"
    mips_dir = "/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/ghidra/automation_20250206/results/analysis_20250206_165530/mips"
    
    arm_functions = read_map(arm_dir)
    mips_functions = read_map(mips_dir)
    
    output_csv = "comparison_results.csv"
    with open(output_csv, "w", newline='', encoding='utf-8') as csvfile:
        fieldnames = ["Label", "Function", "SourceFile", "ARM_PcodeLines", "MIPS_PcodeLines", "Match_Ratio", "Notes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        all_labels = set(arm_functions.keys()).union(mips_functions.keys())
        for label in all_labels:
            arm_info = arm_functions.get(label)
            mips_info = mips_functions.get(label)
            if arm_info and mips_info:
                arm_lines = count_pcode_lines(arm_info["Pcode"])
                mips_lines = count_pcode_lines(mips_info["Pcode"])
                match_ratio = calculate_match_ratio(arm_info["Pcode"], mips_info["Pcode"])
                notes = generate_comparison_notes(arm_lines, mips_lines, match_ratio)
                
                writer.writerow({
                    "Label": label,
                    "Function": arm_info["Function"],
                    "SourceFile": arm_info["SourceFile"],
                    "ARM_PcodeLines": arm_lines,
                    "MIPS_PcodeLines": mips_lines,
                    "Match_Ratio": f"{match_ratio:.2f}",
                    "Notes": notes
                })
    print("比對完成，結果保存至:", output_csv)

if __name__ == "__main__":
    main()
