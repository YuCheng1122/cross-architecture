import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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
        
        // 初始化 decompiler 介面以提取高階 P-Code
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
        
        // 遍歷所有函數
        FunctionIterator functions = currentProgram.getListing().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            String functionName = function.getName();
            
            int label = getOrCreateLabel(functionName);
            String sourceFile = getSourceFileInfo(function);
            mapWriter.printf("%d,%s,%s,%s%n", label, functionName, sourceFile, arch);
            
            String pcodeFileName = String.format("%s/label_%d_%s_pcode.txt", outputDir, label, functionName);
            PrintWriter pcodeWriter = new PrintWriter(new FileWriter(pcodeFileName));
            
            // 輸出函數基本信息
            pcodeWriter.println("Label: " + label);
            pcodeWriter.println("Function: " + functionName);
            pcodeWriter.println("Architecture: " + arch);
            pcodeWriter.println("Source File: " + sourceFile);
            pcodeWriter.println("Entry Point: " + function.getEntryPoint());
            pcodeWriter.println("\nHigh-level P-code:\n");
            
            // 使用 decompiler 提取高階 P-Code
            DecompileResults decompResults = decompInterface.decompileFunction(function, 60, monitor);
            if (!decompResults.decompileCompleted()) {
                pcodeWriter.println("Decompilation failed for function: " + functionName);
                pcodeWriter.close();
                println("Decompilation failed for function: " + functionName);
                continue;
            }
            
            HighFunction highFunction = decompResults.getHighFunction();
            if (highFunction == null) {
                pcodeWriter.println("HighFunction is null for function: " + functionName);
                pcodeWriter.close();
                println("HighFunction is null for function: " + functionName);
                continue;
            }
            
            Iterator<PcodeOpAST> opIter = highFunction.getPcodeOps();
            while (opIter.hasNext()) {
                PcodeOpAST op = opIter.next();
                pcodeWriter.println(op);
                println("Processing high-level P-code op: " + op);
            }
            
            pcodeWriter.close();
            println("Completed processing function: " + functionName);
        }
        
        mapWriter.close();
        decompInterface.dispose();
        println("High-level P-code extraction completed. Results saved to: " + outputDir);
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
