import Config
import os
import json
from . import InterfaceGenerate,TargetPointAnalyze

def AnalyzeKernelInterface():
    # function_modeling
    Config.logging.info("#### Analyzing kernel interface")
    
    # generate syzkaller signature
    Config.logging.info("Generating signature for syzkaller")

    syzkaller_signature_cmd=f"{Config.SyzFeaturePath} > {Config.SyzkallerSignaturePath}"
    Config.ExecuteCMD(syzkaller_signature_cmd)
    assert os.path.exists(Config.SyzkallerSignaturePath) and os.stat(Config.SyzkallerSignaturePath).st_size!=0, "Fail to syzkaller signature!!!"
    Config.logging.info(f"Generating syzkaller signature successfully!")
    
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        caseInterfaceWorkingDir=Config.PrepareDir(Config.getInterfaceDirByCase(caseIdx))
        caseBitcodeDir=Config.getBitcodeDirByCase(caseIdx)
        caseKernelSignatureFile=Config.getKernelSignatureByCase(caseIdx)
        if not os.path.exists(caseKernelSignatureFile):
            generating_cmd=f"cd {caseInterfaceWorkingDir} && {Config.FunctionModelBinary} --verbose-level=4 {caseBitcodeDir} 2>&1 | tee log"
            Config.logging.debug(f"[case {caseIdx}] Starting generating kernel signature")
            Config.ExecuteBigCMD(generating_cmd)
            
            if os.path.exists(caseKernelSignatureFile):
                Config.logging.info(f"[case {caseIdx}] Generating kernel signature successfully!")
            else:
                Config.logging.error(f"[case {caseIdx}] Fail to generate kernel signature !!!")
                continue
            
        print(Config.SyzkallerSignaturePath, caseKernelSignatureFile)
        kernelCode2syscall = InterfaceGenerate.MatchSig(Config.SyzkallerSignaturePath, caseKernelSignatureFile)

        caseFinalInterfaceFile=Config.getFinalInterfaceParingResultByCase(caseIdx)
        with open(caseFinalInterfaceFile, mode="w") as f:
            json.dump(kernelCode2syscall, f, indent="\t")
            
        if os.path.exists(caseFinalInterfaceFile):
            Config.logging.info(f"[case {caseIdx}] Final interface result generated successfully!")
        else:
            Config.logging.error(f"[case {caseIdx}] Fail to generate final interface result!!!")
       
                        
    # return all fail cases, [] if all succeed
def IsSyscallInterfaceGenerated():
    return [
        datapoint['idx'] for datapoint in Config.datapoints if not os.path.exists(Config.getFinalInterfaceParingResultByCase(datapoint['idx']))
    ]
        
        
def AnalyzeTargetPoints():
    # kernel analysis
    Config.logging.info("#### Analyzing syscall entry and calculating distance per block")
    
    Config.logging.info("Generating syscall pair map")
    syscall_pair_map_cmd=f"cd {Config.WorkdirPrefix} && {Config.SyzTRMapPath}"
    Config.ExecuteCMD(syscall_pair_map_cmd)
    assert os.path.exists(Config.SyzTRMapPath), "Failed to generate syscall pair map. Please check"
    Config.logging.info(f"Generating syscall pair map successfully!")
    
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        caseFinalInterfaceFile=Config.getFinalInterfaceParingResultByCase(caseIdx)
        caseBitcodeDir=Config.getBitcodeDirByCase(caseIdx)
        caseKernelAnalysisResDir=Config.PrepareDir(Config.getTargetPointAnalysisResultDirByCase(caseIdx))
        
        Config.logging.info(f"[case {caseIdx}] Analyzing syscall entry and calculating distance")
        analyze_cmd=f"cd {caseKernelAnalysisResDir} && {Config.TargetPointAnalysisBinary} --verbose-level=4 -kernel-interface-file={caseFinalInterfaceFile} -multi-pos-points={Config.getMultiPointsSpecificFile(caseIdx)} {caseBitcodeDir} 2>&1 | tee log"
        Config.ExecuteBigCMD(analyze_cmd)
        if os.path.exists(Config.getTargetPointAnalysisDuplicateReport(caseIdx)):
            Config.logging.error(f"[case {caseIdx}] has multi-points!!! need manual check!!!")
            Config.logging.error(f"Duplicate points are reported in {Config.getTargetPointAnalysisDuplicateReport(caseIdx)}")
            Config.logging.error("Please specify getMultiPointsSpecificFile(lambda function) in Config.py according to your multi-points file structure")
            Config.logging.error("Default set to workdir/multi-pts/case_{caseIdx}.txt")
            Config.logging.error("The format of multi-points file. Example: ")
            Config.logging.error("0 some_function_you_want")
            Config.logging.error("1 some_other_function_you_want")
            Config.logging.error("... and_other_function_you_want")
            continue
        if not os.path.exists(Config.getTargetPointAnalysisMidResult(caseIdx)):
            Config.logging.error(f"[case {caseIdx}] fail to analyze target point")
            continue
        Config.logging.info(f"[case {caseIdx}] Finish analyzing syscall entry and calculate distance")
        
        Config.logging.info(f"[case {caseIdx}] Postprocessing the result, preparing for fuzzing")
        TargetPointAnalyze.PrepareForFuzzing(caseIdx,datapoint['recommend syscall'])
        
        
def IsTargetPointAnalyzeSuccessful():
    return [
        datapoint['idx'] for datapoint in Config.datapoints if not os.path.exists(Config.getFuzzInpDirPathByCase(datapoint['idx'])) or os.stat(Config.getFuzzInpDirPathByCase(datapoint['idx'])).st_size==0
    ]