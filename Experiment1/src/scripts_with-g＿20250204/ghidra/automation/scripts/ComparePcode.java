import java.io.*;
import java.util.*;

public class ComparePcode {
    static class FunctionInfo {
        String name;
        String sourceFile;
        String architecture;
        String pcodeContent;
        
        FunctionInfo(String name, String sourceFile, String architecture, String pcodeContent) {
            this.name = name;
            this.sourceFile = sourceFile;
            this.architecture = architecture;
            this.pcodeContent = pcodeContent;
        }
    }
    
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java ComparePcode <arm_dir> <mips_dir> <output_csv>");
            return;
        }
        
        String armDir = args[0];
        String mipsDir = args[1];
        String outputCsv = args[2];
        
        try {
            // 讀取函數映射
            Map<Integer, FunctionInfo> armFunctions = readFunctionMap(armDir);
            Map<Integer, FunctionInfo> mipsFunctions = readFunctionMap(mipsDir);
            
            // 創建比對結果文件
            PrintWriter writer = new PrintWriter(new FileWriter(outputCsv));
            writer.println("Label,Function,SourceFile,ARM_PcodeLines,MIPS_PcodeLines,Match_Ratio,Notes");
            
            // 比對每個標籤的函數
            Set<Integer> allLabels = new HashSet<>();
            allLabels.addAll(armFunctions.keySet());
            allLabels.addAll(mipsFunctions.keySet());
            
            for (Integer label : allLabels) {
                FunctionInfo armInfo = armFunctions.get(label);
                FunctionInfo mipsInfo = mipsFunctions.get(label);
                
                if (armInfo != null && mipsInfo != null) {
                    // 計算P-code相似度
                    int armLines = countPcodeLines(armInfo.pcodeContent);
                    int mipsLines = countPcodeLines(mipsInfo.pcodeContent);
                    double matchRatio = calculateMatchRatio(armInfo.pcodeContent, mipsInfo.pcodeContent);
                    
                    String notes = generateComparisonNotes(armLines, mipsLines, matchRatio);
                    
                    writer.printf("%d,%s,%s,%d,%d,%.2f,%s%n",
                                label, armInfo.name, armInfo.sourceFile,
                                armLines, mipsLines, matchRatio, notes);
                }
            }
            
            writer.close();
            System.out.println("比對完成，結果保存至: " + outputCsv);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private static Map<Integer, FunctionInfo> readFunctionMap(String dir) throws IOException {
        Map<Integer, FunctionInfo> functions = new HashMap<>();
        
        File mapFile = new File(dir, "function_map.csv");
        BufferedReader reader = new BufferedReader(new FileReader(mapFile));
        
        // 跳過標題行
        reader.readLine();
        
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(",");
            int label = Integer.parseInt(parts[0]);
            String functionName = parts[1];
            String sourceFile = parts[2];
            String architecture = parts[3];
            
            // 讀取對應的P-code文件
            String pcodeFile = String.format("%s/label_%d_%s_pcode.txt", 
                                           dir, label, functionName);
            String pcodeContent = readPcodeFile(pcodeFile);
            
            functions.put(label, new FunctionInfo(functionName, sourceFile, 
                                                architecture, pcodeContent));
        }
        
        reader.close();
        return functions;
    }
    
    private static String readPcodeFile(String filename) throws IOException {
        StringBuilder content = new StringBuilder();
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        
        String line;
        boolean isPcode = false;
        while ((line = reader.readLine()) != null) {
            if (line.equals("P-code:")) {
                isPcode = true;
                continue;
            }
            if (isPcode && !line.trim().isEmpty()) {
                content.append(line).append("\n");
            }
        }
        
        reader.close();
        return content.toString();
    }
    
    private static int countPcodeLines(String pcodeContent) {
        return pcodeContent.split("\n").length;
    }
    
    private static double calculateMatchRatio(String arm, String mips) {
        // 這裡使用一個簡單的相似度計算方法
        // 可以根據需求改進比對算法
        String[] armLines = arm.split("\n");
        String[] mipsLines = mips.split("\n");
        
        int matches = 0;
        int total = Math.max(armLines.length, mipsLines.length);
        
        for (int i = 0; i < Math.min(armLines.length, mipsLines.length); i++) {
            if (comparePcodeLine(armLines[i], mipsLines[i])) {
                matches++;
            }
        }
        
        return (double) matches / total * 100;
    }
    
    private static boolean comparePcodeLine(String arm, String mips) {
        // 這裡可以實現更複雜的P-code比對邏輯
        // 目前使用簡單的字符串比較
        return arm.trim().equals(mips.trim());
    }
    
    private static String generateComparisonNotes(int armLines, int mipsLines, double matchRatio) {
        StringBuilder notes = new StringBuilder();
        
        if (Math.abs(armLines - mipsLines) > armLines * 0.2) {
            notes.append("P-code行數差異顯著; ");
        }
        
        if (matchRatio < 50) {
            notes.append("低相似度; ");
        } else if (matchRatio > 90) {
            notes.append("高相似度; ");
        }
        
        return notes.toString().trim();
    }
}