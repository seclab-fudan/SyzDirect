import json
import Config
import os
import shutil


rcalltrimthreshold=10
filesystems=["sysfs", "rootfs", "ramfs", "tmpfs", "devtmpfs", "debugfs", "securityfs", "sockfs", "pipefs", "anon_inodefs", "devpts", "ext3", "ext2", "ext4", "hugetlbfs", "vfat", "ecryptfs", "fuseblk", "fuse", "rpc_pipefs", "nfs", "nfs4", "nfsd", "binfmt_misc", "autofs", "xfs", "jfs", "msdos", "ntfs", "minix", "hfs", "hfsplus", "qnx4", "ufs", "btrfs", "configfs", "ncpfs", "qnx6", "exofs", "befs", "vxfs", "gfs2","gfs2meta", "fusectl", "bfs", "nsfs", "efs", "cifs", "efivarfs", "affs", "tracefs", "bdev", "ocfs2", "ocfs2_dlmfs", "hpfs", "proc", "afs", "reiserfs", "jffs2", "romfs", "aio", "sysv", "v7", "udf", "ceph", "pstore", "adfs", "9p", "hostfs", "squashfs", "cramfs", "iso9660", "coda", "nilfs2", "logfs", "overlay", "f2fs", "omfs", "ubifs", "openpromfs", "bpf", "cgroup", "cgroup2", "cpuset", "mqueue", "aufs", "selinuxfs", "dax", "erofs", "virtiofs", "exfat", "binder", "zonefs", "pvfs2", "incremental-fs", "esdfs"]
syscallblacklist=["mq_open","syz_open_procfs","epoll_create","eventfd","signalfd","timerfd_create","pidfd_open","pidfd_getfd", "memfd_create","memfd_secret"]

def PrepareForFuzzing(caseIdx, recommend_syscalls):
    
    TheFuzzerPath = Config.FuzzerDir
    StaticAnalysisfileName =  Config.getTargetPointAnalysisMidResult(caseIdx)
    assert os.path.exists(StaticAnalysisfileName), f"{StaticAnalysisfileName} not found. Please check."
    
    call2Wrapper = {
        "sendmsg$NL80211_CMD_SET_INTERFACE": "syz_80211_join_ibss",
    }
    
    if len(recommend_syscalls)>0:
        Config.logging.info(f"[case {caseIdx}] Currently in crash mode, recommend syscall: {recommend_syscalls}")
    case2csts,all_calls =ParseConstraint(StaticAnalysisfileName, recommend_syscalls)
    
    tcall2rcall=Config.LoadJson(Config.TRMapPath)
    callTraceFile = os.path.join(TheFuzzerPath, "sys/linux/gen/calltrace.json")
    Refine_Input_File_Path=os.path.join(TheFuzzerPath,"constinp.json")

    Config.PrepareDir(Config.getConstOutDirPathByCase(caseIdx)) 
    Config.PrepareDir(Config.getFuzzResultDirByCase(caseIdx))
    Config.PrepareDir(Config.getFuzzInpDirPathByCase(caseIdx))
    
    Case2Func=Config.ParseTargetFunctionsInfoFile(caseIdx)

    for xidx in case2csts.keys():
        constraints = case2csts[xidx]

        Config.logging.info(f"[case {caseIdx} xidx {xidx}] Paring")
        
        
        Config.PrepareDir(Config.getFuzzResultDirByCaseAndXidx(caseIdx,xidx))

        new_syzkaller_path = Config.getCustomizedSyzByCaseAndXidx(caseIdx,xidx)

        if os.path.exists(new_syzkaller_path):
            shutil.rmtree(new_syzkaller_path)

        
        with open(Refine_Input_File_Path, "w") as fp:
            json.dump(constraints, fp)
        
            
        Config.ExecuteCMD(f"cd {TheFuzzerPath}; make clean")
        assert not os.path.exists(Config.FuzzerBinDir), "fuzzer make clean fails"

        Config.ExecuteBigCMD(f"cd {TheFuzzerPath}; make")
        os.remove(Refine_Input_File_Path)
        
        refinedFile=Config.getConstOutFilePathByCaseAndXidx(caseIdx,xidx)
        if os.path.exists(callTraceFile) and os.path.exists(Config.FuzzerBinDir):
            shutil.move(Config.FuzzerBinDir, os.path.join(new_syzkaller_path, "bin"))
            shutil.copytree(
                os.path.join(TheFuzzerPath, "sys/linux/test"),
                os.path.join(new_syzkaller_path, "sys/linux/test"))
            shutil.move(
                callTraceFile,
                refinedFile)
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Generated customized fuzzer")
        else:
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] No customized fuzzer")
    
        outList = []
        targetCalls = all_calls[xidx]
        orginTargetCalls = targetCalls
        
        # handle status 2: 
        fileSystemMountCall = None 
        
        if os.path.exists(refinedFile):
                refineCalls = Config.LoadJson(refinedFile)
                for refinedCall in refineCalls:
                    oriName = GetRawCallName(refinedCall)
                    targetCalls.add(oriName)
                    targetCalls.add(refinedCall)
                    if refinedCall.startswith("syz_mount_image"):
                        fileSystemMountCall = oriName
        
        for rawCall, wrapper in call2Wrapper.items():
            if rawCall in targetCalls:
                targetCalls.add(wrapper)
            if rawCall in orginTargetCalls:
                orginTargetCalls.add(wrapper)
        
        targetCalls = FilterGeneralSyscall(targetCalls)

        assert str(xidx) in Case2Func.keys(), f"idx {xidx} target func not found!"
        if str(xidx) in Case2Func.keys():
            relativepath = Case2Func[str(xidx)][1].replace(Config.getSrcDirByCase(caseIdx),"")
            print("relativepath",relativepath)
            relatedFS=""
            if relativepath[:3]=="fs/":
                pos = relativepath[3:].find("/")
                relatedFScandidate=relativepath[3:][:pos]
                if relatedFScandidate in filesystems:
                    relatedFS=relatedFScandidate
                    Config.logging.info(f" idx {xidx}: target function file: ",relativepath)

        rcallNum = 0
        for tcall in targetCalls:
            rcalls = []
            oriName = GetRawCallName(tcall)
            if oriName not in tcall2rcall:
                # pass
                print(f"{tcall} {oriName} without related syscall")
            else:
                rcalls = list(tcall2rcall[oriName]['TrimVersion'])
                rcalls = FilterGeneralSyscall(rcalls)

                if len(rcalls) > 10:
                    mountCallNum = len(tuple(filter(lambda x: "mount" in x, rcalls)))
                    # print(tcall, "sdafasd", fileSystemMountCall)
                    if mountCallNum > 10 and fileSystemMountCall is not None and fileSystemMountCall in rcalls: 
                        newRcalls = [] 
                        newRcalls.append(fileSystemMountCall)
                        newRcalls.extend((filter(lambda x: "mount" not in x, rcalls)))
                        print(f"{xidx} enter here, {tcall} ori rcalls: {rcalls}, filter rcalls: {newRcalls}")
                        rcalls = newRcalls
                if len(rcalls)>rcalltrimthreshold:
                    ### Classify rcall by syscall
                    ### Rule 1 : generalize open$
                    RCallMap={}
                    def MultiMapInsert(Map,key,element):
                        nonlocal RCallMap
                        if key not in Map.keys():
                            Map[key]=[]
                        Map[key].append(element)

                    for rcall in rcalls:
                        pos = rcall.find("$")
                        if pos == -1:
                            if rcall[-1].isdigit():
                                MultiMapInsert(RCallMap,rcall[:-1],rcall)
                            else:
                                MultiMapInsert(RCallMap,rcall,rcall)
                        else:
                            general_rcall=rcall[:pos]
                            if general_rcall[-1].isdigit():
                                MultiMapInsert(RCallMap,general_rcall[:-1],rcall)
                            else:
                                MultiMapInsert(RCallMap,general_rcall,rcall)

                    ## openat

                    if "openat" in RCallMap.keys() and len(RCallMap["openat"])>10:
                        RCallMap["openat"]=["openat"]
                        RCallMap["open"]=["open"]
                    if "dup" in RCallMap.keys():
                        RCallMap["dup"]=["dup"]
                    if "creat" in RCallMap.keys():
                        RCallMap["creat"]=["creat"]
                    if "socket" in RCallMap.keys() and len(RCallMap["socket"])>10:
                        RCallMap["socket"]=["socket"]
                    if "accept" in RCallMap.keys() and len(RCallMap["accept"])>10:
                        RCallMap["accept"]=["accept"]
                    if "accept" in RCallMap.keys() and RCallMap["accept"]==["accept$inet","accept4$inet"]:
                        RCallMap["accept"]=["accept$inet"]
                    rcalls=[]
                    
                    ### Rule 2 : blacklist
                    # syz_open_dev
                    if "syz_open_dev" in RCallMap.keys() and len(RCallMap["syz_open_dev"])>=5:
                        del RCallMap["syz_open_dev"]
                    if "syz_init_net_socket" in RCallMap.keys() and len(RCallMap["syz_init_net_socket"])>10:
                        del RCallMap["syz_init_net_socket"]


                    for general_name in syscallblacklist:
                        if general_name in RCallMap.keys():
                            del RCallMap[general_name]

                    for value in RCallMap.values():
                        rcalls=rcalls+value # value is a list
                rcallNum += len(rcalls)


            ### Rule 3 : add syz_mount_image$squashfs
            # target function in squashfs
            if len(relatedFS)>0:
                if not tcall.startswith(f"syz_mount_image${relatedFS}"):
                    rcalls.append(f"syz_mount_image${relatedFS}")
                else:
                    print(f"idx {xidx} add",f"syz_mount_image${relatedFS}","to tcall",tcall,".skip.")
            outList.append({"Target": tcall, "Relate": rcalls})
        

        outFile = Config.getFuzzInpDirPathByCaseAndXidx(caseIdx,xidx)
        if os.path.exists(outFile):
            os.remove(outFile)
        with open(outFile, "w") as fp2:
            json.dump(outList, fp2)
        


def ParseConstraint(filename,recommend_syscalls=[]):
    runCase2cst = dict()
    new_tcall_res = dict()
    new_index2sys = dict()
    
    labels = ["Name", "Value", "Type"]
    rawItems = Config.LoadJson(filename)
    

    for xidxItem in rawItems:
        xidx = int(xidxItem['case index'])

        xCsts = {}
        isInvalid = True 
        
        for cinfo in xidxItem['target syscall infos']:
            callCsts = cinfo['constraints']
            target_call = cinfo['target syscall']
            for cstType, currTypeCsts in callCsts.items():
                if cstType == "int":
                    for currCst in currTypeCsts:
                        cstVal = int(currCst['value'])
                        assert cstVal >= 0
                        xCsts[currCst['name']] = (cstVal, cstType, target_call)
                elif cstType == "string":
                    currCst = currTypeCsts
                    xCsts[currCst] = (0, 'str', target_call)
                else:
                    Config.logging.error(f'[case {caseIdx} xidx {xidx}]Unexpected value,,,Something went wrong... cstType: {cstType}') 
                    
                
            if len(callCsts) == 0: 
                xCsts['invalid_abc'] = (0, "invalid", target_call)
            else:
                isInvalid = False 
        
        if isInvalid: 
            xCsts.clear()
        
        formatCsts = list([
                dict(zip(labels, [cstName, *cstItem]))
                for cstName, cstItem in xCsts.items()
        ])
        
        new_tcall_res[xidx] = {}
        new_index2sys[xidx] = set()
        for cinfo in xidxItem['target syscall infos']:
            rawTcall = cinfo['target syscall']
            rank = cinfo['rank']
            if "$" in rawTcall:
                rawTcall = rawTcall[:rawTcall.find("$")]    
            if rank not in new_tcall_res[xidx]:
                new_tcall_res[xidx][rank] = []

            new_index2sys[xidx].add(rawTcall)
            new_tcall_res[xidx][rank].append(cinfo['target syscall'])
                   

        runCase2cst[xidx] = formatCsts
        
    if len(recommend_syscalls)>0:
        idx_xidx_calls = FilterSyscall(new_index2sys, new_tcall_res, recommend_syscalls=[])
    else:   
        
        idx_xidx_calls=dict()
        
        for xidx,rankMap in new_tcall_res.items():
            for rank, tcalls in rankMap.items():
                if xidx not in idx_xidx_calls.keys():
                    idx_xidx_calls[xidx] = set()
                for call in tcalls:
                    idx_xidx_calls[xidx].add(call)
        
        print(idx_xidx_calls)
        
    
    return runCase2cst, idx_xidx_calls
    

def FilterSyscall(new_index2sys, new_tcall_res, recommend_syscalls):
    MAX_TCALL_RANK = 2

    new_final_index2tcall = dict() # xidx -> tcall


    
    for xidx, tcall_ori in new_index2sys.items():
        new_final_index2tcall[xidx] = set()

        tcall_res_idx = new_tcall_res[xidx]
        tcall_res_idx_sorted = sorted(tcall_res_idx.items(), key=lambda x:x[0])
        
        if len(recommend_syscalls)>0:
            # crash mode
            for recommend_tcall in recommend_syscalls:
                if recommend_tcall in tcall_ori:
                    rank_now = 0
                    for tcall_res_idx_sorted_item in tcall_res_idx_sorted:
                        if rank_now > MAX_TCALL_RANK:
                            break
                        rank = tcall_res_idx_sorted_item[0]
                        sys_list = tcall_res_idx_sorted_item[1]
                        match_flag = False
                        for sys in sys_list:
                            if "$" not in sys:
                                if sys == recommend_tcall:
                                    new_final_index2tcall[xidx].add(sys)
                                    match_flag = True
                            else:
                                real_sys = sys.split("$")[0]
                                if real_sys == recommend_tcall:
                                    new_final_index2tcall[xidx].add(sys)
                                    match_flag = True

                        if match_flag:
                            rank_now += 1
                else:
                    new_final_index2tcall[xidx].add(recommend_tcall)
        else:
            for ri, tcall_res_idx_sorted_item in enumerate(tcall_res_idx_sorted, start=1):
                if ri > MAX_TCALL_RANK:
                    break
                rank = tcall_res_idx_sorted_item[0]
                sys_list = tcall_res_idx_sorted_item[1]
                for sys in sys_list:
                    new_final_index2tcall[xidx].add(sys)

    return new_final_index2tcall


def GetRawCallName(call):
    if call.endswith("_rf1"):
        if call.endswith("$tmp_rf1"):
            call = call[:len(call) - 8]
        else:
            call = call[:len(call) - 4]
    return call

def GetGeneralCallName(call):
    if "$" in call:
        call = call[:call.find("$")]
    if call == "syz_mount_image":
        call = "mount"
    return call 


def FilterGeneralSyscall(calls):
    shouldRemove = set()
    for call in calls:
        if "$" in call:
            rawCall = call[:call.find("$")]
            if rawCall in calls:
                shouldRemove.add(rawCall)
    for rawcall in shouldRemove:
        calls.remove(rawcall)
    return calls 