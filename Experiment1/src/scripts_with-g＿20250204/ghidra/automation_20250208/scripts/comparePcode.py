#!/usr/bin/env python3
import os
import csv
import argparse
from datetime import datetime
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class PcodeComparator:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir if base_dir else "/home/tommy/cross-architecture/Experiment1"
        self.script_date_dir = os.path.join(self.base_dir, "src/scripts_with-g＿20250204")
        self.automation_dir = os.path.join(self.script_date_dir, "ghidra/automation_20250208")
        self.results_dir = os.path.join(self.automation_dir, "results")
        self.logs_dir = os.path.join(self.automation_dir, "logs")
        os.makedirs(self.logs_dir, exist_ok=True)
        self.setup_logging()

    def setup_logging(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.logs_dir, f"analysis_{timestamp}.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
        )

    def setup_analysis_directories(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analysis_dir = os.path.join(self.results_dir, f"analysis_{timestamp}")
        arm_dir = os.path.join(analysis_dir, "arm")
        mips_dir = os.path.join(analysis_dir, "mips")
        os.makedirs(arm_dir, exist_ok=True)
        os.makedirs(mips_dir, exist_ok=True)
        return arm_dir, mips_dir

    def read_function_map(self, csv_path):
        mapping = {}
        try:
            with open(csv_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    mapping[row['Function'].strip()] = row['Label'].strip()
        except Exception as e:
            logging.error(f"Error reading {csv_path}: {str(e)}")
            return {}
        return mapping

    def get_pcode_file_path(self, directory, label, function_name):
        filename = f"label_{label}_{function_name}_pcode.txt"
        return os.path.join(directory, filename)

    def read_pcode_file(self, file_path):
        if not os.path.exists(file_path):
            return None
        tokens = set()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                pcode_section = False
                for line in f:
                    line = line.strip()
                    if not pcode_section:
                        if line.upper().startswith("HIGH-LEVEL P-CODE"):
                            pcode_section = True
                        continue
                    if line:
                        tokens.add(line)
        except Exception as e:
            logging.error(f"Error reading {file_path}: {str(e)}")
            return None
        return tokens

    def jaccard_similarity(self, setA, setB):
        if not setA and not setB:
            return 1.0
        union = setA.union(setB)
        return len(setA.intersection(setB)) / len(union) if union else 0.0

    def run_ghidra_analysis(self, binary_path, arch, processor, output_dir):
        ghidra_home = os.path.expanduser("~/ghidra_11.2.1_PUBLIC")
        analyzeHeadless = os.path.join(ghidra_home, "support", "analyzeHeadless")
        cmd = [
            analyzeHeadless,
            output_dir,
            f"{arch}_MIRAI",
            "-import", binary_path,
            "-processor", processor,
            "-analysisTimeoutPerFile", "3600",
            "-scriptPath", os.path.dirname(os.path.abspath(__file__)),
            "-postScript", "ExtractPcodeForComparison.java", output_dir
        ]
        log_prefix = os.path.join(self.logs_dir, f"{arch}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        try:
            with open(f"{log_prefix}_stdout.log", 'w') as stdout, \
                 open(f"{log_prefix}_stderr.log", 'w') as stderr:
                subprocess.run(cmd, stdout=stdout, stderr=stderr, check=True)
                logging.info(f"{arch} analysis completed successfully")
                return True
        except subprocess.CalledProcessError as e:
            logging.error(f"{arch} analysis failed with error code {e.returncode}")
            return False

    # 如果外部傳入 arm_dir 與 mips_dir，就直接使用它們；否則自動建立
    def analyze_and_compare(self, arm_dir=None, mips_dir=None):
        if not arm_dir or not mips_dir:
            arm_dir, mips_dir = self.setup_analysis_directories()
            logging.info(f"New analysis directories created:\nARM: {arm_dir}\nMIPS: {mips_dir}")
        else:
            logging.info(f"Using provided directories:\nARM: {arm_dir}\nMIPS: {mips_dir}")

        arm_binary = os.path.join(self.script_date_dir, "output_arm/mirai.arm")
        mips_binary = os.path.join(self.script_date_dir, "output_mips/mirai.mips")

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self.run_ghidra_analysis, arm_binary, "arm", "ARM:LE:32:v8", arm_dir): "ARM",
                executor.submit(self.run_ghidra_analysis, mips_binary, "mips", "MIPS:BE:32:default", mips_dir): "MIPS"
            }
            for future in as_completed(futures):
                arch = futures[future]
                try:
                    if not future.result():
                        logging.error(f"{arch} analysis failed")
                        return
                except Exception as e:
                    logging.error(f"{arch} analysis failed with exception: {str(e)}")
                    return

        arm_map = self.read_function_map(os.path.join(arm_dir, "function_map.csv"))
        mips_map = self.read_function_map(os.path.join(mips_dir, "function_map.csv"))
        if not arm_map or not mips_map:
            logging.error("Failed to read function maps")
            return

        common_funcs = set(arm_map.keys()).intersection(mips_map.keys())
        logging.info(f"Found {len(common_funcs)} common functions")

        results = []
        for func in common_funcs:
            arm_label = arm_map[func]
            mips_label = mips_map[func]
            arm_file = self.get_pcode_file_path(arm_dir, arm_label, func)
            mips_file = self.get_pcode_file_path(mips_dir, mips_label, func)
            arm_tokens = self.read_pcode_file(arm_file)
            mips_tokens = self.read_pcode_file(mips_file)
            if arm_tokens is None or mips_tokens is None:
                continue
            sim = self.jaccard_similarity(arm_tokens, mips_tokens)
            results.append({
                "Function": func,
                "Arm_Label": arm_label,
                "Mips_Label": mips_label,
                "Jaccard_Similarity": sim
            })

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_csv = os.path.join(script_dir, f"comparison_results_{timestamp}.csv")
        try:
            with open(output_csv, "w", newline="", encoding='utf-8') as csvfile:
                fieldnames = ["Function", "Arm_Label", "Mips_Label", "Jaccard_Similarity"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in results:
                    writer.writerow(row)
            logging.info(f"Results saved to: {output_csv}")
        except Exception as e:
            logging.error(f"Error writing results: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='P-code Comparison Tool')
    parser.add_argument('--arm-dir', help='Directory for ARM analysis', required=True)
    parser.add_argument('--mips-dir', help='Directory for MIPS analysis', required=True)
    parser.add_argument('--base-dir', help='Base directory for analysis (optional)')
    args = parser.parse_args()
    comparator = PcodeComparator(args.base_dir)
    comparator.analyze_and_compare(args.arm_dir, args.mips_dir)

if __name__ == "__main__":
    main()
