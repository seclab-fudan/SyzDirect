######## This is the main script

import Compilation
import Config
from SyscallAnalyze import SyscallAnalyze
import Fuzz

### Main

if __name__ == "__main__":
    actions=Config.Prepare()

    if Config.Actions.PREPARE_SRC in actions:
        Config.logging.info("Start preparing kernel source for manual instrumentation")
        Compilation.PrepareSourceCode()
        Config.logging.info("Finish preparing kernel source for manual instrumentation")
        exit(1)
        
        
    if Config.Actions.COMPILE_BITCODE in actions:
        Config.logging.info("Start compiling kernel bitcode for later analyzes")
        Compilation.CompileKernelToBitcodeNormal()
        Config.logging.info("Finish compiling kernel bitcode for later analyzes")

    if Config.Actions.ANALYZE_KERNEL in actions:
        Config.Check(Compilation.IsCompilationSuccessful,f"Not all cases have their bitcode not ready, please check or recompile the kernel")
        Config.logging.info("Start analyzing kernel syscall")
        SyscallAnalyze.AnalyzeKernelInterface()
        Config.logging.info("Finish analyzing kernel syscall")
        
    if Config.Actions.ANALYZE_TARGET_POINT in actions:
        Config.Check(SyscallAnalyze.IsSyscallInterfaceGenerated,"Not all cases have their interfaces successfully generated, please check or remove these case from caselist")
        Config.logging.info("Start analyzing target points")
        SyscallAnalyze.AnalyzeTargetPoints()
        Config.logging.info("Finish analyzing target points")
        
        
    if Config.Actions.INSTRUMENT_DISTANCE in actions:
        Config.logging.info("Start instrumenting kernel with distance")
        Config.Check(SyscallAnalyze.IsTargetPointAnalyzeSuccessful,"Not all cases have at least one point instrumented successfully, please check manually according to the message.")
        Compilation.CompileKernelToBitcodeWithDistance()
        Config.logging.info("Finish instrumenting kernel with distance")

    if Config.Actions.FUZZ in actions:    
        Config.logging.info("Start preparing for fuzzing")
        Fuzz.MultirunFuzzer()
        Config.logging.info("Finish preparing for fuzzing")
    

    