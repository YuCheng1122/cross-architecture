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
            
            // 取得所有標籤
            Set<Integer> allLabels = new HashSet<>();
            allLabels.addAll(armFunctions.keySet());
            allLabels.addAll(mipsFunctions.keySet());
            
            for (Integer label : allLabels) {
                FunctionInfo armInfo = armFunctions.get(label);
                FunctionInfo mipsInfo = mipsFunctions.get(label);
                
                if (armInfo != null && mipsInfo != null) {
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
            
            // 讀取對應的 P-code 文件
            String pcodeFile = String.format("%s/label_%d_%s_pcode.txt", dir, label, functionName);
            String pcodeContent = readPcodeFile(pcodeFile);
            
            functions.put(label, new FunctionInfo(functionName, sourceFile, architecture, pcodeContent));
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
    
    // 調整後的匹配率計算：對每一行計算一個 0~1 的相似度，並取平均
    private static double calculateMatchRatio(String arm, String mips) {
        String[] armLines = arm.split("\n");
        String[] mipsLines = mips.split("\n");
        
        int total = Math.max(armLines.length, mipsLines.length);
        int min = Math.min(armLines.length, mipsLines.length);
        double sumSimilarity = 0.0;
        
        for (int i = 0; i < min; i++) {
            double sim = computeSimilarity(armLines[i].trim(), mipsLines[i].trim());
            sumSimilarity += sim;
        }
        // 假設超出的行視為 0 相似度
        return (sumSimilarity / total) * 100;
    }
    
    // 計算兩個字串的相似度，基於 Levenshtein 距離的歸一化結果
    private static double computeSimilarity(String s1, String s2) {
        int distance = levenshteinDistance(s1, s2);
        int maxLen = Math.max(s1.length(), s2.length());
        if (maxLen == 0) return 1.0;
        return 1.0 - ((double) distance / maxLen);
    }
    
    // 標準的 Levenshtein 距離實作
    private static int levenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();
        int[][] dp = new int[len1 + 1][len2 + 1];
        
        for (int i = 0; i <= len1; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= len2; j++) {
            dp[0][j] = j;
        }
        
        for (int i = 1; i <= len1; i++) {
            for (int j = 1; j <= len2; j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost);
            }
        }
        return dp[len1][len2];
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
