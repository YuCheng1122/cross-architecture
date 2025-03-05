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

    // 加入 funcNames 參數以同時記錄函數名稱
    private Map<String, List<String>> extractPcode(Program program, DecompInterface ifc, TaskMonitor monitor,
                                                     Map<String, String> funcNames) throws Exception {
        Map<String, List<String>> pcodeMap = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String addrStr = "0x" + func.getEntryPoint().toString();
            HighFunction highFunc = getHighFunction(func, ifc, monitor);
            List<String> pcodeList = createPcodeList(highFunc);
            pcodeMap.put(addrStr, pcodeList);
            funcNames.put(addrStr, func.getName());
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

            // 呼叫與被呼叫函數列表
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
        Program program = currentProgram;
        DecompInterface ifc = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        ifc.setOptions(options);
        ifc.openProgram(program);

        // 用來記錄函數名稱，key 為函數入口地址
        Map<String, String> funcNames = new HashMap<>();
        Map<String, List<String>> pcodeMap = extractPcode(program, ifc, monitor, funcNames);

        // 整理輸出資料：包含函數特徵、p-code 與函數名稱
        Map<String, Object> db = new HashMap<>();
        computeFunctionFeatures(program, ifc, monitor, pcodeMap, db);
        db.put("pcode", pcodeMap);
        db.put("func_names", funcNames);

        // 根據 binary 架構決定輸出檔名
        String arch = program.getLanguage().getProcessor().toString();
        String progFileName = getProgramFile().getName();
        String outputFileName = progFileName + "_" + arch + ".txt";

        // 仍使用原硬碼輸出目錄（後續 bash 腳本會搬移到 results）
        String outputDirectory = "/home/tommy/cross-architecture/Experiment1/src/scripts_with-g＿20250204/ghidra/automation_20250209/unpackedTuneDB";
        File outDir = new File(outputDirectory);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }
        File outputFile = new File(outDir, outputFileName);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String jsonString = gson.toJson(db);

        FileWriter writer = new FileWriter(outputFile);
        writer.write(jsonString);
        writer.close();

        println("Output saved to: " + outputFile.getAbsolutePath());
    }
}
