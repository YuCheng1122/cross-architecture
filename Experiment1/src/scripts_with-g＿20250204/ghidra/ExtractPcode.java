import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ExtractPcode extends GhidraScript {
    @Override
    public void run() throws Exception {
        // 時間戳記格式化
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
        String timestamp = now.format(formatter);
        
        // 直接指定輸出目錄
        String arch = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        String outputDir = "/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/ghidra/analysis_results/" + arch;
        String baseFileName = "pcode_analysis_" + timestamp;
        
        // 創建輸出目錄
        new File(outputDir).mkdirs();

        // 創建摘要文件
        File summaryFile = new File(outputDir, baseFileName + "_summary.txt");
        PrintWriter summaryWriter = new PrintWriter(summaryFile);
        
        // 寫入摘要信息
        summaryWriter.println("Analysis Time: " + timestamp);
        summaryWriter.println("Binary: " + currentProgram.getName());
        summaryWriter.println("Processor: " + currentProgram.getLanguage().getProcessor().toString());
        summaryWriter.println("\nAnalyzed Functions:");
        
        // 遍歷所有函數
        FunctionIterator functions = currentProgram.getListing().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            File outputFile = new File(outputDir, function.getName() + "_" + timestamp + "_pcode.txt");
            PrintWriter writer = new PrintWriter(outputFile);
            
            // 記錄到摘要文件
            summaryWriter.println("\nFunction: " + function.getName());
            summaryWriter.println("Address: " + function.getEntryPoint());
            
            // 獲取函數的所有指令
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            writer.println("Function: " + function.getName());
            writer.println("Address: " + function.getEntryPoint());
            writer.println("P-code:\n");
            
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                PcodeOp[] pcodeOps = instruction.getPcode();
                
                writer.println(instruction.getAddress() + ": " + instruction);
                for (PcodeOp pcodeOp : pcodeOps) {
                    writer.println("\t" + pcodeOp);
                }
                writer.println();
            }
            writer.close();
        }
        summaryWriter.close();
        println("P-code extraction completed to: " + outputDir);
    }
}