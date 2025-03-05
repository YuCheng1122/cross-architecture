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
import ghidra.program.model.pcode.HighSymbol;
import ghidra.util.task.TaskMonitor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.util.*;
import java.util.function.Function;
import java.util.function.Function;

public class ExtractPcodeAndFeatures extends GhidraScript {

    private HighFunction getHighFunction(Function func, DecompInterface ifc, TaskMonitor monitor) throws Exception {
        DecompileResults res = ifc.decompileFunction(func, 60, monitor);
        return res.getHighFunction();
    }

    private List<String> createPcodeList(HighFunction highFunc) {
        List<String> pcodeList = new ArrayList<>();
        if (highFunc == null) {
            return pcodeList;
        }
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
        Map<String, List<String>> pcodeMap = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        // 使用迭代器遍歷所有函數
        Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String addrStr = "0x" + func.getEntryPoint().toString();
            HighFunction highFunc = getHighFunction(func, ifc, monitor);
            List<String> pcodeList = createPcodeList(highFunc);
            pcodeMap.put(addrStr, pcodeList);
        }
        return pcodeMap;
    }

    private Map<String, Integer> countCBranch(Map<String, List<String>> pcodeMap) {
        Map<String, Integer> cbranchMap = new HashMap<>();
        for (String addr : pcodeMap.keySet()) {
            int count = 0;
            for (String line : pcodeMap.get(addr)) {
                String[] tokens = line.split("\\s+");
                if (tokens.length > 1 && !tokens[0].startsWith("(")) {
                    if (tokens[1].equals("CBRANCH")) {
                        count++;
                    }
                }
            }
            cbranchMap.put(addr, count);
        }
        return cbranchMap;
    }

    private void computeFunctionFeatures(Program program, DecompInterface ifc, TaskMonitor monitor,
                                           Map<String, List<String>> pcodeMap,
                                           Map<String, Object> output) throws Exception {
        Map<String, List<Integer>> funcFeatures = new HashMap<>();
        Map<String, List<String>> paramTypes = new HashMap<>();
        Map<String, List<String>> callees = new HashMap<>();
        Map<String, List<String>> callers = new HashMap<>();

        Map<String, Integer> cbranchMap = countCBranch(pcodeMap);
        FunctionManager funcManager = program.getFunctionManager();

        for (String addrStr : pcodeMap.keySet()) {
            Address addr = getAddress(addrStr);
            Function func = funcManager.getFunctionContaining(addr);
            if (func == null) continue;

            // getCalledFunctions/getCallingFunctions 改為回傳 Set<Function>
            Set<Function> calledFuncs = func.getCalledFunctions(monitor);
            List<String> calledFuncsList = new ArrayList<>();
            for (Function f : calledFuncs) {
                calledFuncsList.add("0x" + f.getEntryPoint().toString());
            }

            Set<Function> callingFuncs = func.getCallingFunctions(monitor);
            List<String> callingFuncsList = new ArrayList<>();
            for (Function f : callingFuncs) {
                callingFuncsList.add("0x" + f.getEntryPoint().toString());
            }
            // 注意：此處命名依需求可調整
            callees.put(addrStr, callingFuncsList);
            callers.put(addrStr, calledFuncsList);

            List<Integer> features = new ArrayList<>();
            features.add(callingFuncsList.size());  // 被呼叫數
            features.add(calledFuncsList.size());    // 呼叫其他函數數

            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            HighFunction highFunc = res.getHighFunction();
            int paramCount = 0;
            List<String> paramTypeList = new ArrayList<>();
            if (highFunc != null && highFunc.getLocalSymbolMap() != null) {
                // getSymbols() 已回傳 Iterator，不用再調 iterator()
                Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    HighSymbol symbol = symbols.next();
                    if (symbol.isParameter()) {
                        paramTypeList.add(symbol.getDataType().getName());
                        paramCount++;
                    }
                }
            }
            features.add(paramCount);
            features.add(cbranchMap.get(addrStr));

            funcFeatures.put(addrStr, features);
            paramTypes.put(addrStr, paramTypeList);
        }
        output.put("func_features", funcFeatures);
        output.put("paramType", paramTypes);
        output.put("callees", callees);
        output.put("callers", callers);
    }

    @Override
    public void run() throws Exception {
        try {
            currentLogFileName = "extract_" + new SimpleDateFormat("yyyyMMdd").format(new Date()) + ".log";
            writeLog(LogLevel.INFO, "Starting analysis for: " + currentProgram.getName());
            
            DecompInterface ifc = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            ifc.setOptions(options);
            
            if (!ifc.openProgram(currentProgram)) {
                writeLog(LogLevel.ERROR, "Failed to open program in decompiler");
                return;
            }

            String outputDir = "javaTemp";
            FunctionManager functionManager = currentProgram.getFunctionManager();
            FunctionIterator functions = functionManager.getFunctions(true);
            
            int totalFunctions = 0;
            FunctionIterator countFunctions = functionManager.getFunctions(true);
            while (countFunctions.hasNext()) {
                countFunctions.next();
                totalFunctions++;
            }
            
            int processedCount = 0;
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                processFunction(function, ifc, outputDir);
                
                processedCount++;
                if (monitor != null) {
                    monitor.setProgress(processedCount);
                    monitor.setMaximum(totalFunctions);
                }
            }

            writeLog(LogLevel.INFO, String.format("Analysis completed. Processed %d functions", processedCount));
            
        } catch (Exception e) {
            writeLog(LogLevel.ERROR, "Fatal error during script execution: " + e.getMessage());
            throw e;
        }
    }
}