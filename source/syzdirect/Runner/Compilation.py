import Config
import os
import shutil

def PrepareSourceCode():
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        kernel_commit=datapoint['kernel commit']
        caseSrcDir=Config.getSrcDirByCase(caseIdx)
        if not os.path.exists(caseSrcDir):
            if Config.LinuxSrcTemplate!=None:
                shutil.copytree(Config.LinuxSrcTemplate,caseSrcDir)
            else:
                clonecmd=f'cd {Config.SrcDirRoot} && git clone https://github.com/torvalds/linux.git case_{caseIdx}'
                Config.ExecuteCMD(clonecmd)
        assert os.path.exists(caseSrcDir)
        
        checkoutcmd=f"cd {caseSrcDir} && git checkout -f {kernel_commit}"
        Config.ExecuteCMD(checkoutcmd)
        
        applykcovcmd=f"cd {caseSrcDir} && git apply {Config.KcovPatchPath}"
        if Config.ExecuteCMD(applykcovcmd)[1].find("patch failed") != -1:
            Config.logging.error(f"[case {caseIdx}] Fail to apply kcov patch!!! Please manually apply!!!")
        
        
        Config.logging.info(f"[case {caseIdx}] Finished preparing source code")
        
    
    
    
def CompileKernelToBitcodeNormal():
    emit_contents=f'''#!/bin/sh
CLANG={Config.ClangPath}
if [ ! -e $CLANG ]
then
    exit
fi
OFILE=`echo $* | sed -e 's/^.* \(.*\.o\) .*$/\\1/'`
if [ "x$OFILE" != x -a "$OFILE" != "$*" ] ; then
    $CLANG -emit-llvm -g "$@" >/dev/null 2>&1 > /dev/null
    if [ -f "$OFILE" ] ; then
        BCFILE=`echo $OFILE | sed -e 's/o$/llbc/'`
        #file $OFILE | grep -q "LLVM IR bitcode" && mv $OFILE $BCFILE || true
        if [ `file $OFILE | grep -c "LLVM IR bitcode"` -eq 1 ]; then
            mv $OFILE $BCFILE
        else
            touch $BCFILE
        fi
    fi
fi
exec $CLANG "$@"
    
    '''
    if os.path.exists(Config.EmitScriptPath):
        os.remove(Config.EmitScriptPath)
    with open(Config.EmitScriptPath,"w") as f:
        f.write(emit_contents)
    os.chmod(Config.EmitScriptPath,0o775)
    
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        configPath=datapoint['config path']
        caseBCDir=Config.getBitcodeDirByCase(caseIdx)
        
        if IsCompilationSuccessfulByCase(caseBCDir):
            Config.logging.info(f"[case {caseIdx}] Already compiled. Skip")
            continue
        elif os.path.exists(caseBCDir):
            shutil.rmtree(caseBCDir, ignore_errors=True)
        
        Config.logging.info(f"[case {caseIdx}] starting compiling, target output to {caseBCDir}")
        Config.PrepareDir(caseBCDir)
        
        cpcmd=f"cp {configPath} {os.path.join(caseBCDir, '.config')}"
        Config.ExecuteCMD(cpcmd)
        
        DisabledConfigs=[
            "CONFIG_KASAN","CONFIG_KCSAN","CONFIG_UBSAN","CONFIG_HAVE_DEBUG_KMEMLEAK"
        ]
        with open(os.path.join(caseBCDir, '.config'), "a") as f:
            f.writelines([f"{c}=n\n" for c in DisabledConfigs])
            f.writelines("\nCONFIG_KCOV=y\n")

        
        
        compile_command = f"cd {Config.getSrcDirByCase(caseIdx)} && git checkout -- scripts/Makefile.kcov && make clean && make mrproper && yes | make CC={Config.EmitScriptPath} O={caseBCDir} oldconfig && make CC=\'{Config.EmitScriptPath}\' O={caseBCDir} -j{Config.CPUNum}"
        # print(Config.ExecuteCMD(compile_command))
        os.system(compile_command)
        if IsCompilationSuccessfulByCase(caseBCDir):
            Config.logging.info(f"[case {caseIdx}] Successfully compiled bitcode")
        else:
            Config.logging.info(f"[case {caseIdx}] Error compiling bitcode!!!")
            
        
    
def CompileKernelToBitcodeWithDistance():
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        configPath=datapoint['config path']
        tfmap=Config.ParseTargetFunctionsInfoFile(caseIdx)
        
        caseKernelRoot=Config.PrepareDir(Config.getInstrumentedKernelDirByCase(caseIdx))
        
        caseSrcDir=Config.getSrcDirByCase(caseIdx)
        for xidx in tfmap.keys():
            tempBuildDir=Config.PrepareDir(os.path.join(caseKernelRoot,"temp_build"))
            targetFunction=tfmap[xidx][0]
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Starting instrumenting kernel with distance")
            dst_config=os.path.join(tempBuildDir,".config")
            currentDistDir=Config.getDistanceResultDir(caseIdx,xidx)
            
            kcov_config = '''# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=%s -fsanitize-coverage-distance-dir=%s -fsanitize-coverage-target-function=%s
kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)      += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so

export CFLAGS_KCOV := $(kcov-flags-y)
    '''%(caseSrcDir, currentDistDir, targetFunction)
            with open(os.path.join(caseSrcDir,"scripts/Makefile.kcov"), mode="w") as f:
                f.write(kcov_config)
            mk_cmd=f"cd {caseSrcDir}; make clean; make mrproper"
            Config.ExecuteCMD(mk_cmd)
            
            shutil.copyfile(configPath,dst_config)
            with open(dst_config,"a") as f:
                f.write("\nCONFIG_UBSAN=n\n")
                f.writelines("\nCONFIG_KCOV=y\n")
                
            compile_script = '''#!/bin/sh
cd %s
CC=\"%s\"
make ARCH=x86_64 CC=$CC O=%s olddefconfig
make ARCH=x86_64 CC=$CC O=%s -j%s
    '''%(caseSrcDir, Config.ClangPath, tempBuildDir,tempBuildDir, Config.CPUNum)

            compile_script_path = os.path.join(currentDistDir, "distance_kernel_compile.sh")
            with open(compile_script_path, mode="w") as f:
                f.write(compile_script)
            
            Config.ExecuteBigCMD("chmod +x %s"%compile_script_path)
            Config.ExecuteBigCMD(compile_script_path)

            targetOutBzimage=os.path.join(tempBuildDir,"arch/x86/boot/bzImage")
            targetVMLinux=os.path.join(tempBuildDir,"vmlinux")
            if not os.path.exists(targetOutBzimage):
                Config.logging.error(f"[case {caseIdx} xidx {xidx}] Fail to instrument kernel with distance!!! Please check!!!!")
                continue
        
            
            shutil.copyfile(targetVMLinux,os.path.join(caseKernelRoot,f"vmlinux_{xidx}"))
            shutil.copyfile(targetOutBzimage,Config.getInstrumentedKernelImageByCaseAndXidx(caseIdx,xidx))
            shutil.rmtree(tempBuildDir)
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Instrument kernel with distance succeed!")
            
            
            
    
    
    

def IsCompilationSuccessfulByCase(caseBCDir):
    bc_bzImage_path = os.path.join(caseBCDir, "arch/x86/boot/bzImage")
    return os.path.exists(caseBCDir) and os.path.exists(bc_bzImage_path)
        
    
    # return all fail cases, [] if all succeed
def IsCompilationSuccessful():
    return [
        datapoint['idx'] for datapoint in Config.datapoints if not IsCompilationSuccessfulByCase(Config.getBitcodeDirByCase(datapoint['idx']))
    ]