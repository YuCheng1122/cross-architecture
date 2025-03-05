//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public class ExtractPcodeAndFunctionCalls extends GhidraScript {

    private Logger extractionLogger;
    private Logger timingLogger;

    /**
     * 配置日誌設置
     * 
     * @param outputDir 輸出目錄路徑
     * @return void
     */
    private void configureLogging(String outputDir) throws IOException {
        // 創建日誌目錄
        File logDir = new File(outputDir, "../logs");
        if (!logDir.exists()) {
            logDir.mkdirs();
        }
        
        // 提取文件名
        String progFileName = getProgramFile().getName();
        
        // 設置提取日誌
        String extractionLogFile = new File(logDir, progFileName + "_extraction.log").getAbsolutePath();
        println("日誌記錄於: " + extractionLogFile);
        
        extractionLogger = Logger.getLogger("extraction_logger_" + progFileName);
        extractionLogger.setLevel(Level.INFO);
        
        FileHandler extractionHandler = new FileHandler(extractionLogFile);
        extractionHandler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String timestamp = dateFormat.format(new Date(record.getMillis()));
                return timestamp + " - " + record.getLevel() + " - " + record.getMessage() + "\n";
            }
        });
        extractionLogger.addHandler(extractionHandler);
        
        // 設置計時日誌
        String timingLogFile = new File(logDir, progFileName + "_timing.log").getAbsolutePath();
        println("計時日誌記錄於: " + timingLogFile);
        
        timingLogger = Logger.getLogger("timing_logger_" + progFileName);
        timingLogger.setLevel(Level.INFO);
        
        FileHandler timingHandler = new FileHandler(timingLogFile);
        timingHandler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String timestamp = dateFormat.format(new Date(record.getMillis()));
                return timestamp + "," + record.getMessage() + "\n";
            }
        });
        timingLogger.addHandler(timingHandler);
    }

    private HighFunction getHighFunction(Function func, DecompInterface ifc, TaskMonitor monitor) throws Exception {
        DecompileResults res = ifc.decompileFunction(func, 60, monitor);
        return res.getHighFunction();
    }

    private List<String> createPcodeList(HighFunction highFunc) {
        List<String> pcodeList = new ArrayList<>();
        Iterator<PcodeOpAST> opiter = highFunc.getPcodeOps();
        while (opiter.hasNext()) {
            PcodeOpAST op = opiter.next();
            pcodeList.add(op.toString());
        }
        return pcodeList;
    }

    // 將 "0x..." 字串轉為 Address 物件
    private Address getAddress(String addrStr) {
        long offset = Long.parseLong(addrStr.substring(2), 16);
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Map<String, List<String>> extractPcode(Program program, DecompInterface ifc, TaskMonitor monitor)
            throws Exception {
        timingLogger.info("開始提取P-Code");
        long startTime = System.currentTimeMillis();
        
        Map<String, List<String>> pcodeMap = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        // 使用迭代器遍歷所有函數
        Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
        int count = 0;
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String addrStr = "0x" + func.getEntryPoint().toString();
            try {
                HighFunction highFunc = getHighFunction(func, ifc, monitor);
                if (highFunc != null) {
                    List<String> pcodeList = createPcodeList(highFunc);
                    pcodeMap.put(addrStr, pcodeList);
                    count++;
                    
                    if (count % 100 == 0) {
                        extractionLogger.info("已處理 " + count + " 個函數");
                    }
                }
            } catch (Exception e) {
                extractionLogger.warning("處理函數 " + addrStr + " 時出錯: " + e.getMessage());
            }
        }
        
        long endTime = System.currentTimeMillis();
        timingLogger.info("P-Code提取完成,耗時," + (endTime - startTime) + "ms,處理函數數," + count);
        extractionLogger.info("總共處理了 " + count + " 個函數");
        
        return pcodeMap;
    }

    private Map<String, List<String>> extractFunctionCalls(Program program, TaskMonitor monitor) throws Exception {
        timingLogger.info("開始提取函數調用關係");
        long startTime = System.currentTimeMillis();
        
        Map<String, List<String>> functionCalls = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        
        Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
        int count = 0;
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String addrStr = "0x" + func.getEntryPoint().toString();
            
            try {
                // 獲取被調用的函數
                Set<Function> calledFuncs = func.getCalledFunctions(monitor);
                List<String> calledList = new ArrayList<>();
                for (Function f : calledFuncs) {
                    calledList.add("0x" + f.getEntryPoint().toString());
                }
                
                functionCalls.put(addrStr, calledList);
                count++;
                
                if (count % 100 == 0) {
                    extractionLogger.info("已處理 " + count + " 個函數調用關係");
                }
            } catch (Exception e) {
                extractionLogger.warning("處理函數調用 " + addrStr + " 時出錯: " + e.getMessage());
            }
        }
        
        long endTime = System.currentTimeMillis();
        timingLogger.info("函數調用提取完成,耗時," + (endTime - startTime) + "ms,處理函數數," + count);
        extractionLogger.info("總共處理了 " + count + " 個函數調用關係");
        
        return functionCalls;
    }

    @Override
    public void run() throws Exception {
        // 記錄開始時間
        Date startTime = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        Program program = currentProgram;
        
        // 設置相對路徑輸出
        String scriptDir = getSourceFile().getParentFile().getAbsolutePath();
        String outputDirectory = new File(scriptDir, "../results").getAbsolutePath();
        
        // 獲取文件名與架構信息
        String progFileName = getProgramFile().getName();
        String arch = program.getLanguage().getProcessor().toString();
        
        // 創建與數據目錄結構相匹配的輸出目錄
        File binaryFile = getProgramFile();
        String relativePath = getRelativePathFromData(binaryFile.getAbsolutePath());
        if (relativePath != null) {
            File resultDir = new File(outputDirectory, relativePath).getParentFile();
            if (!resultDir.exists()) {
                resultDir.mkdirs();
            }
            outputDirectory = resultDir.getAbsolutePath();
        }
        
        // 配置日誌
        configureLogging(outputDirectory);
        
        // 輸出日誌信息
        extractionLogger.info("開始分析文件: " + progFileName);
        extractionLogger.info("架構: " + arch);
        extractionLogger.info("開始時間: " + dateFormat.format(startTime));
        
        // 初始化解編譯接口
        DecompInterface ifc = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        ifc.setOptions(options);
        ifc.openProgram(program);
        
        // 提取P-Code和函數調用
        Map<String, List<String>> pcodeMap = extractPcode(program, ifc, monitor);
        Map<String, List<String>> functionCalls = extractFunctionCalls(program, monitor);
        
        // 整理輸出資料
        Map<String, Object> result = new HashMap<>();
        result.put("pcode", pcodeMap);
        result.put("function_calls", functionCalls);
        
        // 添加日誌信息
        Map<String, String> logInfo = new HashMap<>();
        logInfo.put("file_name", progFileName);
        logInfo.put("architecture", arch);
        logInfo.put("start_time", dateFormat.format(startTime));
        logInfo.put("end_time", dateFormat.format(new Date()));
        result.put("log_info", logInfo);
        
        // 輸出文件
        String outputFileName = progFileName + "_" + arch + ".json";
        File outputFile = new File(outputDirectory, outputFileName);
        
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String jsonString = gson.toJson(result);
        
        FileWriter writer = new FileWriter(outputFile);
        writer.write(jsonString);
        writer.close();
        
        // 輸出結束日誌
        Date endTime = new Date();
        long duration = endTime.getTime() - startTime.getTime();
        
        extractionLogger.info("分析完成！");
        extractionLogger.info("結束時間: " + dateFormat.format(endTime));
        extractionLogger.info("總耗時: " + duration + " 毫秒");
        extractionLogger.info("輸出保存至: " + outputFile.getAbsolutePath());
        
        println("分析完成！");
        println("結束時間: " + dateFormat.format(endTime));
        println("輸出保存至: " + outputFile.getAbsolutePath());
    }
    
    /**
     * 從文件絕對路徑獲取相對於data目錄的路徑
     * 
     * @param absolutePath 文件絕對路徑
     * @return String 相對路徑或null（如果不在data目錄下）
     */
    private String getRelativePathFromData(String absolutePath) {
        String[] pathParts = absolutePath.split("/");
        for (int i = 0; i < pathParts.length; i++) {
            if (pathParts[i].equals("data") && i + 1 < pathParts.length) {
                StringBuilder relativePath = new StringBuilder();
                for (int j = i; j < pathParts.length; j++) {
                    relativePath.append(pathParts[j]);
                    if (j < pathParts.length - 1) {
                        relativePath.append("/");
                    }
                }
                return relativePath.toString();
            }
        }
        return null;
    }
}