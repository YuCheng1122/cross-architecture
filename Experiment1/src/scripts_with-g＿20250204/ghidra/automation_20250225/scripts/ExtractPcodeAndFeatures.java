//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;

public class ExtractPcodeAndFeatures extends GhidraScript {

    // 定義日誌級別
    enum LogLevel {
        INFO, WARNING, ERROR
    }

    private String currentLogFileName;

    private void writeLog(LogLevel level, String message) {
        println("[" + level.name() + "] " + message);
    }

    private HighFunction getHighFunction(Function func, DecompInterface ifc, TaskMonitor monitor) throws Exception {
        if (func == null) return null;
        
        try {
            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            return res.getHighFunction();
        } catch (Exception e) {
            writeLog(LogLevel.WARNING, "無法反編譯函數 " + func.getName() + " 於 " + func.getEntryPoint() + ": " + e.getMessage());
            return null;
        }
    }

    private List<String> createPcodeList(HighFunction highFunc) {
        List<String> pcodeList = new ArrayList<>();
        if (highFunc == null) {
            return pcodeList;
        }
        
        try {
            Iterator<PcodeOpAST> opiter = highFunc.getPcodeOps();
            while (opiter.hasNext()) {
                PcodeOpAST op = opiter.next();
                pcodeList.add(op.toString());
            }
        } catch (Exception e) {
            writeLog(LogLevel.WARNING, "創建 P-Code 列表時出錯: " + e.getMessage());
        }
        
        return pcodeList;
    }
    
    // 將 "0x..." 字串轉為 Address 物件
    private Address getAddress(String addrStr) {
        try {
            long offset = Long.parseLong(addrStr.substring(2), 16);
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (Exception e) {
            writeLog(LogLevel.ERROR, "轉換地址時出錯 " + addrStr + ": " + e.getMessage());
            return null;
        }
    }

    private Map<String, List<String>> extractPcode(Program program, DecompInterface ifc, TaskMonitor monitor)
            throws Exception {
        Map<String, List<String>> pcodeMap = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        
        // 查找所有可執行的段落，優先使用 .text
        List<MemoryBlock> executableBlocks = new ArrayList<>();
        MemoryBlock textSection = program.getMemory().getBlock(".text");
        
        if (textSection != null && textSection.isExecute()) {
            executableBlocks.add(textSection);
            writeLog(LogLevel.INFO, "找到 .text 段落: " + textSection.getName() + 
                     " (開始: " + textSection.getStart() + ", 結束: " + textSection.getEnd() + ")");
        } else {
            // 如果沒有找到 .text，查找所有可執行段落
            writeLog(LogLevel.INFO, "未找到 .text 段落，搜索所有可執行段落...");
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.isExecute()) {
                    executableBlocks.add(block);
                    writeLog(LogLevel.INFO, "找到可執行段落: " + block.getName() + 
                             " (開始: " + block.getStart() + ", 結束: " + block.getEnd() + ")");
                }
            }
        }
        
        // 如果沒有找到可執行段落，處理所有函數
        if (executableBlocks.isEmpty()) {
            writeLog(LogLevel.WARNING, "未找到可執行段落，處理所有函數...");
            int count = 0;
            Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
            while (funcs.hasNext() && !monitor.isCancelled()) {
                Function func = funcs.next();
                String addrStr = "0x" + func.getEntryPoint().toString();
                HighFunction highFunc = getHighFunction(func, ifc, monitor);
                List<String> pcodeList = createPcodeList(highFunc);
                pcodeMap.put(addrStr, pcodeList);
                count++;
            }
            writeLog(LogLevel.INFO, "處理了 " + count + " 個函數");
        } else {
            // 處理可執行段落中的函數
            AddressSet executableAddresses = new AddressSet();
            for (MemoryBlock block : executableBlocks) {
                executableAddresses.addRange(block.getStart(), block.getEnd());
            }
            
            int total = 0;
            int processed = 0;
            
            // 計算總函數數
            FunctionIterator allFuncs = funcManager.getFunctions(true);
            while (allFuncs.hasNext()) {
                allFuncs.next();
                total++;
            }
            
            // 只處理可執行段落中的函數
            FunctionIterator funcs = funcManager.getFunctions(executableAddresses, true);
            while (funcs.hasNext() && !monitor.isCancelled()) {
                Function func = funcs.next();
                
                // 確認函數在我們的可執行段落內
                if (executableAddresses.contains(func.getEntryPoint())) {
                    String addrStr = "0x" + func.getEntryPoint().toString();
                    HighFunction highFunc = getHighFunction(func, ifc, monitor);
                    List<String> pcodeList = createPcodeList(highFunc);
                    pcodeMap.put(addrStr, pcodeList);
                    processed++;
                    
                    if (processed % 100 == 0) {
                        writeLog(LogLevel.INFO, "已處理 " + processed + " 個函數...");
                        if (monitor != null) {
                            monitor.setProgress(processed);
                            monitor.setMaximum(total);
                        }
                    }
                }
            }
            
            writeLog(LogLevel.INFO, "從可執行段落處理了 " + processed + " 個函數 (總共 " + total + " 個)");
        }
        
        return pcodeMap;
    }

    private void extractGraphs(Program program, TaskMonitor monitor, Map<String, Object> output) throws Exception {
        FunctionManager funcManager = program.getFunctionManager();
        Map<String, List<String>> callees = new HashMap<>(); // 函數調用圖
        Map<String, List<String>> callers = new HashMap<>(); // 反向函數調用圖
        
        // 從可執行段落找出所有函數
        List<MemoryBlock> executableBlocks = new ArrayList<>();
        MemoryBlock textSection = program.getMemory().getBlock(".text");
        
        if (textSection != null && textSection.isExecute()) {
            executableBlocks.add(textSection);
        } else {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.isExecute()) {
                    executableBlocks.add(block);
                }
            }
        }
        
        AddressSet executableAddresses = new AddressSet();
        for (MemoryBlock block : executableBlocks) {
            executableAddresses.addRange(block.getStart(), block.getEnd());
        }
        
        // 如果沒有找到可執行段落，使用所有函數
        FunctionIterator funcs;
        if (executableBlocks.isEmpty()) {
            funcs = funcManager.getFunctions(true);
        } else {
            funcs = funcManager.getFunctions(executableAddresses, true);
        }
        
        // 處理每個函數
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String addrStr = "0x" + func.getEntryPoint().toString();
            
            try {
                // 獲取被呼叫的函數 (callees)
                Set<Function> funcCallees = func.getCalledFunctions(monitor);
                List<String> calleeList = new ArrayList<>();
                for (Function f : funcCallees) {
                    calleeList.add("0x" + f.getEntryPoint().toString());
                }
                callees.put(addrStr, calleeList);
                
                // 獲取呼叫此函數的函數 (callers)
                Set<Function> funcCallers = func.getCallingFunctions(monitor);
                List<String> callerList = new ArrayList<>();
                for (Function f : funcCallers) {
                    callerList.add("0x" + f.getEntryPoint().toString());
                }
                callers.put(addrStr, callerList);
                
            } catch (Exception e) {
                writeLog(LogLevel.WARNING, "處理函數圖時出錯 " + addrStr + ": " + e.getMessage());
            }
        }
        
        // 將圖放入輸出
        output.put("callees", callees); // 函數調用圖
        output.put("callers", callers); // 反向函數調用圖
    }

    @Override
    public void run() throws Exception {
        try {
            // 初始化日誌
            currentLogFileName = "extract_" + new SimpleDateFormat("yyyyMMdd").format(new Date()) + ".log";
            writeLog(LogLevel.INFO, "開始分析: " + currentProgram.getName());
            
            // 設置反編譯器
            DecompInterface ifc = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            ifc.setOptions(options);
            
            if (!ifc.openProgram(currentProgram)) {
                writeLog(LogLevel.ERROR, "無法在反編譯器中打開程序");
                return;
            }

            // 輸出目錄
            String outputDir = "/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/ghidra/automation_20250225/unpackedTuneDB";
            File dirFile = new File(outputDir);
            if (!dirFile.exists()) {
                dirFile.mkdirs();
            }
            
            // 輸出數據結構
            Map<String, Object> outputData = new HashMap<>();
            
            // 提取 P-Code
            writeLog(LogLevel.INFO, "開始提取 P-Code...");
            Map<String, List<String>> pcodeMap = extractPcode(currentProgram, ifc, monitor);
            writeLog(LogLevel.INFO, "提取了 " + pcodeMap.size() + " 個函數的 P-Code");
            outputData.put("pcode", pcodeMap);
            
            // 提取圖結構 (CFG, FCG)
            writeLog(LogLevel.INFO, "開始提取函數圖...");
            extractGraphs(currentProgram, monitor, outputData);
            writeLog(LogLevel.INFO, "完成提取函數圖");
            
            // 獲取輸出檔名
            String programName = currentProgram.getName();
            String malwareStatus = "BENIGN"; // 使用固定的 BENIGN 標記
            
            // 創建輸出文件 - 使用 _BENIGN 作為後綴
            String outputFilePath = outputDir + "/" + programName + "_" + malwareStatus + ".txt";
            
            try (FileWriter writer = new FileWriter(outputFilePath)) {
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                writer.write(gson.toJson(outputData));
                writeLog(LogLevel.INFO, "成功寫入輸出文件: " + outputFilePath);
            } catch (Exception e) {
                writeLog(LogLevel.ERROR, "寫入輸出文件時出錯: " + e.getMessage());
                throw e;
            }

            writeLog(LogLevel.INFO, "分析完成。");
            
        } catch (Exception e) {
            writeLog(LogLevel.ERROR, "腳本執行中發生致命錯誤: " + e.getMessage());
            e.printStackTrace(System.err);
            throw e;
        }
    }
}