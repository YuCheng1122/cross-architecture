import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class ExtractPcodeForComparison extends GhidraScript {
    private Map<String, Integer> functionLabels = new HashMap<>();
    private int currentLabel = 1;
    
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        
        if (args.length < 1) {
            println("Usage: Please specify output directory as script argument");
            return;
        }
        
        String outputDir = args[0];
        new File(outputDir).mkdirs();
        
        String arch = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        println("Processing architecture: " + arch);
        println("Output directory: " + outputDir);
        
        // 創建函數映射文件
        File functionMapFile = new File(outputDir, "function_map.csv");
        PrintWriter mapWriter = new PrintWriter(new FileWriter(functionMapFile));
        mapWriter.println("Label,Function,SourceFile,Architecture");
        
        // 遍歷所有函數
        FunctionIterator functions = currentProgram.getListing().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            String functionName = function.getName();
            
            // 獲取或創建標籤
            int label = getOrCreateLabel(functionName);
            
            // 獲取源碼信息
            String sourceFile = getSourceFileInfo(function);
            
            // 寫入映射信息
            mapWriter.printf("%d,%s,%s,%s%n", 
                           label, functionName, sourceFile, arch);
            
            // 輸出P-code到單獨的文件
            String pcodeFileName = String.format("%s/label_%d_%s_pcode.txt", 
                                               outputDir, label, functionName);
            PrintWriter pcodeWriter = new PrintWriter(new FileWriter(pcodeFileName));
            
            // 寫入函數信息
            pcodeWriter.println("Label: " + label);
            pcodeWriter.println("Function: " + functionName);
            pcodeWriter.println("Architecture: " + arch);
            pcodeWriter.println("Source File: " + sourceFile);
            pcodeWriter.println("Entry Point: " + function.getEntryPoint());
            pcodeWriter.println("\nP-code:\n");
            
            // 獲取並寫入P-code
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                PcodeOp[] pcodeOps = instruction.getPcode();
                
                pcodeWriter.println(instruction.getAddress() + ": " + instruction);
                for (PcodeOp pcodeOp : pcodeOps) {
                    pcodeWriter.println("\t" + pcodeOp);
                    
                    // 輸出調試信息
                    println("Processing instruction at " + instruction.getAddress() + 
                           " for function " + functionName);
                }
                pcodeWriter.println();
            }
            
            pcodeWriter.close();
            println("Completed processing function: " + functionName);
        }
        
        mapWriter.close();
        println("P-code extraction completed. Results saved to: " + outputDir);
    }
    
    private int getOrCreateLabel(String functionName) {
        return functionLabels.computeIfAbsent(functionName, k -> currentLabel++);
    }
    
    private String getSourceFileInfo(Function function) {
        String sourceFile = "Unknown";
        try {
            SourceType sourceType = function.getSymbol().getSource();
            
            if (sourceType == SourceType.USER_DEFINED || sourceType == SourceType.IMPORTED) {
                Reference[] refs = getReferencesTo(function.getEntryPoint());
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        Data data = getDataAt(ref.getFromAddress());
                        if (data != null && data.hasStringValue()) {
                            String value = data.getDefaultValueRepresentation();
                            if (value.contains(".c:")) {
                                sourceFile = value;
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            println("Warning: Error getting source info for " + function.getName() + ": " + e.getMessage());
        }
        return sourceFile;
    }
}