//Get assembly instructions from .text section
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GetOpcode extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("Starting analysis for: " + currentProgram.getName());
        Map<String, Object> outputData = new HashMap<>();
        outputData.put("program_name", currentProgram.getName());
        
        // Get memory information
        Memory memory = currentProgram.getMemory();
        MemoryBlock textSection = null;
        
        // Find .text section
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().equals(".text")) {
                textSection = block;
                break;
            }
        }
        
        // If no .text section found, return empty result
        if (textSection == null) {
            println("No .text section found in " + currentProgram.getName());
            outputData.put("error", "No .text section found");
            outputData.put("instructions", new ArrayList<>());
            
            String resultPath = getScriptArgs()[0] + "/" + currentProgram.getName() + "_opcode.json";
            try (FileWriter file = new FileWriter(resultPath)) {
                file.write(toPrettyJson(outputData));
                println("Empty results saved to: " + resultPath);
            }
            return;
        }
        
        println("Found .text section, size: " + textSection.getSize() + " bytes");
        
        // Process .text section information
        Map<String, Object> sectionInfo = new HashMap<>();
        sectionInfo.put("name", textSection.getName());
        sectionInfo.put("start", textSection.getStart().toString());
        sectionInfo.put("end", textSection.getEnd().toString());
        sectionInfo.put("size", textSection.getSize());
        sectionInfo.put("permissions", String.format("%s%s%s",
            textSection.isRead() ? "r" : "-",
            textSection.isWrite() ? "w" : "-",
            textSection.isExecute() ? "x" : "-"
        ));
        outputData.put("text_section", sectionInfo);
        
        // Get instructions only from .text section
        List<Map<String, String>> instructionsArray = new ArrayList<>();
        AddressSet textAddresses = new AddressSet(textSection.getStart(), textSection.getEnd());
        InstructionIterator instructions = currentProgram.getListing().getInstructions(textAddresses, true);
        
        // Count total instructions for progress bar
        long totalInstructions = 0;
        InstructionIterator countIterator = currentProgram.getListing().getInstructions(textAddresses, true);
        while (countIterator.hasNext()) {
            countIterator.next();
            totalInstructions++;
        }
        
        println("Processing " + totalInstructions + " instructions...");
        long processedInstructions = 0;
        int lastProgress = 0;
        
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            Map<String, String> instrJson = new HashMap<>();
            
            processedInstructions++;
            int currentProgress = (int)((processedInstructions * 100) / totalInstructions);
            if (currentProgress > lastProgress) {
                println("Progress: " + currentProgress + "%");
                lastProgress = currentProgress;
            }
            
            Address addr = instr.getAddress();
            String mnemonic = instr.getMnemonicString();
            String assembly = instr.toString();
            
            instrJson.put("address", addr.toString());
            instrJson.put("mnemonic", mnemonic);
            instrJson.put("assembly", assembly);
            
            instructionsArray.add(instrJson);
        }
        
        outputData.put("instructions", instructionsArray);
        
        String resultPath = getScriptArgs()[0] + "/" + currentProgram.getName() + "_opcode.json";
        try (FileWriter file = new FileWriter(resultPath)) {
            file.write(toPrettyJson(outputData));
            println("Analysis complete. Results saved to: " + resultPath);
        } catch (Exception e) {
            println("Error saving file: " + e.getMessage());
        }
    }

    private String toPrettyJson(Object obj) {
        return toPrettyJson(obj, 0);
    }

    private String toPrettyJson(Object obj, int indent) {
        String indentStr = "    ".repeat(indent);
        
        if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) {
                    sb.append(",\n");
                }
                first = false;
                sb.append(indentStr).append("    \"").append(entry.getKey()).append("\": ");
                sb.append(toPrettyJson(entry.getValue(), indent + 1));
            }
            sb.append("\n").append(indentStr).append("}");
            return sb.toString();
        } else if (obj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("[\n");
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    sb.append(",\n");
                }
                first = false;
                sb.append(indentStr).append("    ");
                sb.append(toPrettyJson(item, indent + 1));
            }
            sb.append("\n").append(indentStr).append("]");
            return sb.toString();
        } else if (obj instanceof String) {
            return "\"" + ((String) obj).replace("\"", "\\\"") + "\"";
        } else {
            return String.valueOf(obj);
        }
    }
}