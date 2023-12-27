#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Instruction.h"
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"  
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/BasicBlock.h" 
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include <llvm/IR/LegacyPassManager.h>
#include <map> 
#include <vector> 
#include "llvm/IR/CFG.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h" 
#include "llvm/IR/IRBuilder.h"

#include "DeviceExtractor.h"
#include "Config.h"
#include "Common.h"

#include "Utils.h"

#include "DataFlowAnalysis.h"

using namespace llvm;

map<std::string, Function*> DeviceExtractorPass::ProcessFileOperations(Value* handlerStruct) {
    auto result = map<std::string, Function*>();
    if (handlerStruct == nullptr) {
        return result;
    }
    if (auto constantStruct = dyn_cast<ConstantStruct>(handlerStruct)) {
        // file operations
        outs() << "file operations: " << *constantStruct << "\n";
        if (constantStruct->getType()->getName() != "struct.file_operations") {
            return result;
        }
        auto handlerRead = constantStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["read"]);
        auto handlerWrite = constantStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["write"]);
        auto handlerIoctl = constantStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["unlocked_ioctl"]);
        auto handlerOpen = constantStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["open"]);
        auto handlerMmap = constantStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["mmap"]);
        if (handlerRead && isa<Function>(handlerRead)) {
            result["read"] = dyn_cast<Function>(handlerRead);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerRead)->getName().str()] = {1, 2, 4, 0};
        }
        if (handlerWrite && isa<Function>(handlerWrite)) {
            result["write"] = dyn_cast<Function>(handlerWrite);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerWrite)->getName().str()] = {1, 2, 4, 0};
        } else {
            handlerWrite = constantStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["write_iter"]);
            if (handlerWrite && isa<Function>(handlerWrite)) {
                result["write"] = dyn_cast<Function>(handlerWrite);
            }
        }
        if (handlerIoctl && isa<Function>(handlerIoctl)) {
            result["ioctl"] = dyn_cast<Function>(handlerIoctl);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerIoctl)->getName().str()] = {1, 2, 4};
        }
        if (handlerOpen && isa<Function>(handlerOpen)) {
            result["open"] = dyn_cast<Function>(handlerOpen);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerOpen)->getName().str()] = {0, 1};
        }
        if (handlerMmap && isa<Function>(handlerMmap)) {
            result["mmap"] = dyn_cast<Function>(handlerMmap);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerMmap)->getName().str()] = {1, 2};
        }
    }

    return result;
}

map<std::string, Function*> DeviceExtractorPass::ProcessPosixClockOperations(Value* handlerStruct) {
    auto result = map<std::string, Function*>();
    if (handlerStruct == nullptr) {
        return result;
    }
    if (auto constantStruct = dyn_cast<ConstantStruct>(handlerStruct)) {
        // file operations
        auto handlerIoctl = constantStruct->getOperand(Ctx->StructFieldIdx["posix_clock_operations"]["ioctl"]);
        auto handlerOpen = constantStruct->getOperand(Ctx->StructFieldIdx["posix_clock_operations"]["open"]);
        auto handlerRead = constantStruct->getOperand(Ctx->StructFieldIdx["posix_clock_operations"]["read"]);
        if (handlerIoctl && isa<Function>(handlerIoctl)) {
            result["ioctl"] = dyn_cast<Function>(handlerIoctl);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerIoctl)->getName().str()] = {1, 2, 4};
        }
        if (handlerOpen && isa<Function>(handlerOpen)) {
            result["open"] = dyn_cast<Function>(handlerOpen);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerOpen)->getName().str()] = {1, 2};
        }
        if (handlerRead && isa<Function>(handlerRead)) {
            result["read"] = dyn_cast<Function>(handlerRead);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerRead)->getName().str()] = {1, 0, 2, 4};
        }
    }

    return result;
}

map<std::string, Function*> DeviceExtractorPass::ProcessBlockDeviceOperations(Value* handlerStruct) {
    auto result = map<std::string, Function*>();
    if (handlerStruct == nullptr) {
        return result;
    }
    if (auto constantStruct = dyn_cast<ConstantStruct>(handlerStruct)) {
        // file operations
        auto handlerIoctl = constantStruct->getOperand(Ctx->StructFieldIdx["block_device_operations"]["ioctl"]);
        auto handlerOpen = constantStruct->getOperand(Ctx->StructFieldIdx["block_device_operations"]["open"]);
        if (handlerIoctl && isa<Function>(handlerIoctl)) {
            result["ioctl"] = dyn_cast<Function>(handlerIoctl);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerIoctl)->getName().str()] = {1, 0, 2, 4};
        }
        if (handlerOpen && isa<Function>(handlerOpen)) {
            result["open"] = dyn_cast<Function>(handlerOpen);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerOpen)->getName().str()] = {1, 2};
        }
    }

    return result;
}

map<string, Function*> DeviceExtractorPass::ProcessTtyOperations(Value* handlerStruct) {
    auto result = map<std::string, Function*>();
    if (handlerStruct == nullptr) {
        return result;
    }
    if (auto constantStruct = dyn_cast<ConstantStruct>(handlerStruct)) {
        // file operations
        auto handlerIoctl = constantStruct->getOperand(Ctx->StructFieldIdx["tty_operations"]["ioctl"]);
        auto handlerOpen = constantStruct->getOperand(Ctx->StructFieldIdx["tty_operations"]["open"]);
        auto handlerWrite = constantStruct->getOperand(Ctx->StructFieldIdx["tty_operations"]["write"]);
        if (handlerIoctl && isa<Function>(handlerIoctl)) {
            result["ioctl"] = dyn_cast<Function>(handlerIoctl);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerIoctl)->getName().str()] = {1, 2, 4};
        } else {
            handlerIoctl = constantStruct->getOperand(Ctx->StructFieldIdx["tty_operations"]["compat_ioctl"]);
            if (handlerIoctl && isa<Function>(handlerIoctl)) {
                result["ioctl"] = dyn_cast<Function>(handlerIoctl);
                GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerIoctl)->getName().str()] = {1, 2, 4};
            }
        }
        if (handlerOpen && isa<Function>(handlerOpen)) {
            result["open"] = dyn_cast<Function>(handlerOpen);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerOpen)->getName().str()] = {0, 1};
        }
        if (handlerWrite && isa<Function>(handlerWrite)) {
            result["write"] = dyn_cast<Function>(handlerWrite);
            GlobalCtx.FunctionArgMap[dyn_cast<Function>(handlerWrite)->getName().str()] = {1, 2, 4};
        }
    }

    return result;
}

// string DeviceExtractorPass::ExtractDevNameFromFunction(Function* f) {

// }

string DeviceExtractorPass::ExtractDevNameFromFunction(Function* f) {
    if (f == nullptr) {
        return "";
    }
    string devName = "";
    for (auto& BB: *f) {
        for (auto &I: BB) {
            if (auto CI = dyn_cast<CallInst>(&I)) {
                if (CI->getCalledFunction() && CI->getCalledFunction()->hasName()) {
                    auto calledFuncName = CI->getCalledFunction()->getName();
                    if (calledFuncName == "register_chrdev_region") {
                        outs() << "register chrdev region: " << *CI << "\n";
                        if (devName == "" || devName == "?") {
                            devName = getDeviceString(CI->getArgOperand(2));
                        }
                    } else if (calledFuncName == "alloc_chrdev_region") {
                        outs() << "alloc_chrdev_region: " << *CI << "\n";
                        if (devName == "" || devName == "?") {
                            devName = getDeviceString(CI->getArgOperand(3));
                        }
                    } else if (calledFuncName == "device_create") {
                        outs() << "device_create: " << *CI << "\n";
                        if (devName == "" || devName == "?") {
                            devName = getDeviceString(CI->getArgOperand(4));
                        }
                    } else if (calledFuncName == "dev_set_name") {
                        outs() << "dev_set_name: " << *CI << "\n";
                        if (devName == "" || devName == "?") {
                            devName = getDeviceString(CI->getArgOperand(1));
                        }
                    }
                }
            }
        }
    }
    return devName;
}

string DeviceExtractorPass::ExtractBlockDevNameFromFunction(Function* f) {
    if (f == nullptr) {
        return "";
    }
    string devName = "";
    for (auto& BB: *f) {
        for (auto &I: BB) {
            if (auto CI = dyn_cast<CallInst>(&I)) {
                if (CI->getCalledFunction() && CI->getCalledFunction()->hasName()) {
                    auto calledFuncName = CI->getCalledFunction()->getName();
                    if (calledFuncName == "__register_blkdev" || calledFuncName == "unregister_blkdev") {
                        outs() << "register blkdev: " << *CI << "\n";
                        if (devName == "" || devName == "?") {
                            devName = getDeviceString(CI->getArgOperand(1));
                        }
                    } 
                }
            }
        }
    }
    return devName;
}


void DeviceExtractorPass::ProcessMiscDeviceInit(CallInst* callInst) {
    outs() << "[*] new misc call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = MISCDEVICE;
    deviceInfoItem->major = -1;
    deviceInfoItem->name = "";
    auto arg = callInst->getArgOperand(0);
    if (auto gv = dyn_cast<GlobalVariable>(arg)) {
        if (gv->getValueType()->isStructTy()) {
            if (auto constStruct = dyn_cast<ConstantStruct>(gv->getInitializer())) {
                outs() << *constStruct << "\n";
                auto minorVal = constStruct->getOperand(0);
                auto minor = getIntValue(minorVal);
                outs() << "[+] Minor: " << minor << "\n";
                deviceInfoItem->minor = minor;
                auto deviceNameVal = constStruct->getOperand(1);
                auto deviceName = getDeviceString(deviceNameVal);
                deviceInfoItem->name = deviceName;
                outs() << "[+] Device name: " << deviceName << "\n";
                auto fileOperations = getStructValue(constStruct->getOperand(2));
                if (fileOperations == nullptr && Ctx->GlobalStructMap.count(constStruct->getOperand(2)->getName().str())) {
                    outs() << *(Ctx->GlobalStructMap[constStruct->getOperand(2)->getName().str()]) << '\n';
                    fileOperations = getStructValue(Ctx->GlobalStructMap[constStruct->getOperand(2)->getName().str()]);
                }
                if (fileOperations) {
                    outs() << "[+] Operations: " << *fileOperations << "\n";
                    deviceInfoItem->OperationStruct = fileOperations;
                    deviceInfoItem->SyscallHandler = ProcessFileOperations(fileOperations);
                }
            }
        }
    } else {
        outs() << "[-] local variable: " << *arg << "\n";
    }
    if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
        auto caller = callInst->getFunction();
        string devName = ExtractDevNameFromFunction(caller);
        if (devName == "" || devName == "?" || devName == "%s") {
            // more aggressively 
            auto M = caller->getParent();
            for (auto &F: *M) {
                devName = ExtractDevNameFromFunction(&F);
                if (devName != "" && devName != "?" && devName != "%s") {
                    break;
                }
            }
        }
    }   
    Ctx->SubsystemInfo.push_back(deviceInfoItem);
    
}

void DeviceExtractorPass::ProcessCdevInit(CallInst* callInst) {
    outs() << "[*] new cdev call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CDEV;
    auto cdevArg = callInst->getArgOperand(0);
    for (auto user: cdevArg->users()) {
        // extract device major & minor id
        if (auto callInst = dyn_cast<CallInst>(user)) {
            if (callInst->getCalledFunction()->getName() == "cdev_add") {
                auto deviceTVal = callInst->getArgOperand(1);
                auto deviceT = getIntValue(deviceTVal);
                int major = deviceT >> 20;
                int minor = deviceT & 0xfffff;
                deviceInfoItem->major = major;
                deviceInfoItem->minor = minor;
                outs() << "[+] Major: " << major << "\n";
                outs() << "[+] Minor: " << minor << "\n";
            } 
        } 
    }
    // extract dev name
    auto caller = callInst->getFunction();
    string devName = ExtractDevNameFromFunction(caller);
    if (devName == "" || devName == "?" || devName == "%s") {
        // more aggressively 
        auto M = caller->getParent();
        for (auto &F: *M) {
            devName = ExtractDevNameFromFunction(&F);
            if (devName != "" && devName != "?" && devName != "%s") {
                break;
            }
        }
    }
    deviceInfoItem->name = devName;
    auto fopsArg = callInst->getArgOperand(1);
    auto fops = getStructValue(fopsArg);
    if (!fops && Ctx->GlobalStructMap.count(fopsArg->getName().str())) {
        outs() << *(Ctx->GlobalStructMap[fopsArg->getName().str()]) << '\n';
        fops = getStructValue(Ctx->GlobalStructMap[fopsArg->getName().str()]);
        // memFops = Ctx->
    }
    if (fops) {
        deviceInfoItem->OperationStruct = fops;
        deviceInfoItem->SyscallHandler = ProcessFileOperations(fops);
        Ctx->SubsystemInfo.push_back(deviceInfoItem);
    }
}


void DeviceExtractorPass::ProcessSndRegisterDevice(CallInst* callInst) {
    outs() << "[*] new snd call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;

    auto caller = callInst->getFunction();
    string devName = ExtractDevNameFromFunction(caller);
    if (devName == "" || devName == "?" || devName == "%s") {
        // more aggressively 
        auto M = caller->getParent();
        for (auto &F: *M) {
            devName = ExtractDevNameFromFunction(&F);
            if (devName != "" && devName != "?" && devName != "%s") {
                break;
            }
        }
    }
    deviceInfoItem->name = devName;
    auto fopsArg = callInst->getArgOperand(3);
    auto fops = getStructValue(fopsArg);
    deviceInfoItem->OperationStruct = fops;
    deviceInfoItem->SyscallHandler = ProcessFileOperations(fops);
    Ctx->SubsystemInfo.push_back(deviceInfoItem);

}

void DeviceExtractorPass::ProcessCdevAdd(CallInst* callInst) {
    outs() << "[*] new cdev add: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;
    deviceInfoItem->name = "?";
    auto cdevArg = callInst->getArgOperand(0);

    auto cdevAliasSet = GetAliasOfStructType(cdevArg, "struct.cdev");
    
    for (auto cdevAlias: *cdevAliasSet) {
        for (auto user : cdevAlias->users()) { 
            if (auto gepInst = dyn_cast<GetElementPtrInst>(user)) {
                auto offsetVal = gepInst->getOperand(2);
                auto offsetInt = dyn_cast<ConstantInt>(offsetVal);
                // get access of the fops field
                if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["cdev"]["ops"]) {
                    auto fopsVal = ExtractPtrAssignment(gepInst);
                    if (fopsVal) {
                        auto fopsStruct = getStructValue(fopsVal);
                        if (fopsStruct) {
                            deviceInfoItem->OperationStruct = fopsStruct;
                            deviceInfoItem->SyscallHandler = ProcessFileOperations(fopsStruct);
                        }
                    }
                } 
                
            } else if (auto subCallInst = dyn_cast<CallInst>(user)) {
                auto func = subCallInst->getCalledFunction();
                if (func && func->hasName() && func->getName() == "cdev_init") {
                    // in the previous case
                    return;
                }
            }
        }
    }
    if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
        auto M = callInst->getFunction()->getParent();
        for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
            Function& func = *mi;
            if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
                deviceInfoItem->name = ExtractDevNameFromFunction(&func);
            }
        }
    }
    if (deviceInfoItem->OperationStruct && deviceInfoItem->name != "?") {
        Ctx->SubsystemInfo.push_back(deviceInfoItem);
    }
}


void DeviceExtractorPass::ProcessRegisterChrdev(CallInst* callInst) {
    outs() << "[*] new chrdev call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;
    // major
    auto majorArg = callInst->getArgOperand(0);
    auto major = getIntValue(majorArg);
    deviceInfoItem->major = major;
    outs() << "[+] Major: " << major << "\n";
    // dev name
    auto deviceNameArg = callInst->getArgOperand(1);
    auto deviceName = getDeviceString(deviceNameArg);
    deviceInfoItem->name = deviceName;
    outs() << "[+] Device name: " << deviceName << "\n";
    // fops 
    auto fopsArg = callInst->getArgOperand(2);
    auto fops = getStructValue(fopsArg);
    deviceInfoItem->OperationStruct = fops;
    deviceInfoItem->SyscallHandler = ProcessFileOperations(fops);
    Ctx->SubsystemInfo.push_back(deviceInfoItem);
}

void DeviceExtractorPass::Process__RegisterChrdev(CallInst* callInst) {
    outs() << "[*] new _chrdev call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;
    // major and minor
    auto majorArg = callInst->getArgOperand(0);
    auto minorArg = callInst->getArgOperand(1);
    int major = getIntValue(majorArg);
    int minor = getIntValue(minorArg);
    deviceInfoItem->major = major;
    deviceInfoItem->minor = minor;
    outs() << "[+] Major: " << major << "\n";
    outs() << "[+] Minor: " << minor << "\n";
    // dev name
    auto deviceNameArg = callInst->getArgOperand(3);
    auto deviceName = getDeviceString(deviceNameArg);
    deviceInfoItem->name = deviceName;
    outs() << "[+] Device name: " << deviceName << "\n";
    // fops 
    auto fopsArg = callInst->getArgOperand(4);
    auto fops = getStructValue(fopsArg);
    deviceInfoItem->OperationStruct = fops;
    deviceInfoItem->SyscallHandler = ProcessFileOperations(fops);
    Ctx->SubsystemInfo.push_back(deviceInfoItem);
}

void DeviceExtractorPass::ProcessRegisterBlkdev(CallInst* callInst) {
    outs() << "[*] new blkdev call: " << *callInst << "\n";
    auto majorArg = callInst->getArgOperand(0);
    int major = getIntValue(majorArg);
    if (major != -1) {
        auto deviceNameArg = callInst->getArgOperand(1);
        auto deviceName = getDeviceString(deviceNameArg);
        bool flag = false;
        for (auto item : Ctx->SubsystemInfo) {
            if (item->ItemType == DEVICE) {
                auto deviceInfoItem = static_cast<DeviceInfoItem*>(item);
                if (deviceInfoItem->type == BLOCKDEVICE && deviceInfoItem->major == major) {
                    if (item->name == "?" || item->name == "") {
                        item->name = deviceName;
                    }
                    // insert block device
                    flag = true;
                    break;
                }
            }
        }
        if (!flag) {
            DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
            deviceInfoItem->ItemType = DEVICE;
            deviceInfoItem->type = BLOCKDEVICE;
            deviceInfoItem->major = major;
            deviceInfoItem->name = deviceName;
            Ctx->SubsystemInfo.push_back(deviceInfoItem);
        }
    }
}

Value* DeviceExtractorPass::ExtractPtrAssignment(Value* ptrValue) {
    for (auto user: ptrValue->users()) {
        outs() << "\t User: " << *user << "\n";
        if (auto storeInst = dyn_cast<StoreInst>(user)) {
            return storeInst->getValueOperand();
        } else if (auto callInst = dyn_cast<CallInst>(user)) {
            if (callInst->getCalledFunction()->getName() == "sprintf") {
                return callInst->getArgOperand(1);
            }
        }
    }
    return nullptr;

}

set<Value*>* DeviceExtractorPass::GetAliasOfStructType(Value* value, string structName) {
    auto Inst = dyn_cast<Instruction>(value);
    if (!Inst) {
        return new set<Value*>({value});
    }
    set<Value*>* aliasSet = new set<Value*>();
    DFA->getAliasPointers(Inst, *aliasSet, Ctx->FuncPAResults[Inst->getFunction()]);
    set<Value*>* resSet = new set<Value*>();
    for (auto A : *aliasSet) {
        if (auto aliasPtr = dyn_cast<PointerType>(A->getType())) {
            auto ElemType = aliasPtr->getElementType();
            if (ElemType) {
                if (auto aliasStruct = dyn_cast<StructType>(ElemType)) {
                    outs() << "Alias: " << *A << " " << aliasStruct->getName() << "\n";
                    if (aliasStruct->getName() == structName) {
                        resSet->insert(A);
                    }
                }
            }
        }
    }
    delete aliasSet;
    return resSet;
}

set<Value*>* DeviceExtractorPass::GetAliasSet(Value* value) {
    auto Inst = dyn_cast<Instruction>(value);
    if (!Inst) {
        return nullptr;
    }
    set<Value*>* aliasSet = new set<Value*>();
    DFA->getAliasPointers(Inst, *aliasSet, Ctx->FuncPAResults[Inst->getFunction()]);
    return aliasSet;
}

void DeviceExtractorPass::ProcessAddDisk(CallInst* callInst) {
    outs() << "[*] new adddisk: " << *callInst << "\n";
    auto diskArg = callInst->getArgOperand(1);
    outs() << "[+] Disk: " << *diskArg << "\n";

    auto deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = BLOCKDEVICE;
    deviceInfoItem->name = "?";

    // get alias of disk ptr
    auto diskAliasSet = GetAliasOfStructType(diskArg, "struct.gendisk");
    
    for (auto diskAlias: *diskAliasSet) {
        for (auto user : diskAlias->users()) { 
            if (auto gepInst = dyn_cast<GetElementPtrInst>(user)) {
                auto offsetVal = gepInst->getOperand(2);
                auto offsetInt = dyn_cast<ConstantInt>(offsetVal);
                // get access of the fops field
                if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["gendisk"]["fops"]) {
                    auto fopsVal = ExtractPtrAssignment(gepInst);
                    if (fopsVal) {
                        auto fopsStruct = getStructValue(fopsVal);
                        if (fopsStruct) {
                            deviceInfoItem->OperationStruct = fopsStruct;
                            deviceInfoItem->SyscallHandler = ProcessBlockDeviceOperations(fopsStruct);
                        }
                    }
                // get device name 
                } else if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["gendisk"]["disk_name"]) {
                    auto nameVal = ExtractPtrAssignment(gepInst);
                    if (nameVal) {
                        auto nameStr = getDeviceString(nameVal);
                        if (nameStr != "?" && nameStr != "") {
                            if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
                                deviceInfoItem->name = nameStr;
                            } else {
                                deviceInfoItem->name += " " + nameStr;
                            }
                        } 
                    }
                }
                
            } else if (auto subCallInst = dyn_cast<CallInst>(user)) {
                if (subCallInst->getCalledFunction() && subCallInst->getCalledFunction()->getName() == "register_cdrom") {
                    if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
                        deviceInfoItem->name = "cdrom";
                    } else {
                        deviceInfoItem->name += " cdrom";
                    }
                }
            }
        }

    }

    if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
        // search for some additional name
        auto M = callInst->getFunction()->getParent();
        for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
            Function& func = *mi;
            if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
                deviceInfoItem->name = ExtractBlockDevNameFromFunction(&func);
            }
        }
    }

    Ctx->SubsystemInfo.push_back(deviceInfoItem);

}

void DeviceExtractorPass::ProcessTtyRegisterDriver(CallInst* callInst) {
    outs() << "[*] new tty call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;
    deviceInfoItem->name = "?";
    auto driverArg = callInst->getArgOperand(0);

    // extract name
    auto driverAliasSet = GetAliasOfStructType(driverArg, "struct.tty_driver");
    for (auto alias : *driverAliasSet) {
        for (auto user : alias->users()) {
            if (auto gepInst = dyn_cast<GetElementPtrInst>(user)) {
                auto offsetVal = gepInst->getOperand(2);
                auto offsetInt = dyn_cast<ConstantInt>(offsetVal);
                if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["tty_driver"]["name"]) {
                    auto nameVal = ExtractPtrAssignment(gepInst);
                    if (nameVal) {
                        auto nameStr = getDeviceString(nameVal);
                        if (nameStr != "?" && nameStr != "") {
                            deviceInfoItem->name = nameStr;
                        }
                    }
                } else if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["tty_driver"]["ops"]) {
                    auto opsVal = ExtractPtrAssignment(gepInst);
                    if (opsVal) {
                        auto opsStruct = getStructValue(opsVal);
                        if (opsStruct) {
                            deviceInfoItem->OperationStruct = opsStruct;
                            deviceInfoItem->SyscallHandler = ProcessTtyOperations(opsStruct);
                        }
                    }
                }
            }
        }
    }


    if (deviceInfoItem->OperationStruct) {
        Ctx->SubsystemInfo.push_back(deviceInfoItem);
    }
}

void DeviceExtractorPass::ProcessPosixClockRegister(CallInst* callInst) {
    outs() << "[*] new posix clock call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;
    deviceInfoItem->name = "?";
    auto clockArg = callInst->getArgOperand(0);

    auto clockAliasSet = GetAliasOfStructType(clockArg, "struct.posix_clock");
    for (auto alias : *clockAliasSet) {
        for (auto user : alias->users()) {
            if (auto gepInst = dyn_cast<GetElementPtrInst>(user)) {
                auto offsetVal = gepInst->getOperand(2);
                auto offsetInt = dyn_cast<ConstantInt>(offsetVal);
                if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["posix_clock"]["ops"]) {
                    auto opsVal = ExtractPtrAssignment(gepInst);
                    if (opsVal) {
                        auto opsStruct = getStructValue(opsVal);
                        if (opsStruct) {
                            deviceInfoItem->OperationStruct = opsStruct;
                            deviceInfoItem->SyscallHandler = ProcessPosixClockOperations(opsStruct);
                        }
                    }
                }
            }
        }
    }

    if (deviceInfoItem->name == "?" || deviceInfoItem->name == "") {
        auto caller = callInst->getFunction();
        string devName = ExtractDevNameFromFunction(caller);
        if (devName == "" || devName == "?" || devName == "%s") {
            // more aggressively 
            auto M = caller->getParent();
            for (auto &F: *M) {
                devName = ExtractDevNameFromFunction(&F);
                if (devName != "" && devName != "?" && devName != "%s") {
                    break;
                }
            }
        }
    }   


    if (deviceInfoItem->OperationStruct) {
        Ctx->SubsystemInfo.push_back(deviceInfoItem);
    }
}

void DeviceExtractorPass::ProcessAnonInodeGetfile(CallInst* callInst) {
    outs() << "[*] new anon_inode call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = CHARDEVICE;
    deviceInfoItem->name = "?";

    // extract dev name 
    auto devNameVal = callInst->getArgOperand(0);
    auto devName = getDeviceString(devNameVal);
    if (devName[0] == '[') {
        devName = devName.substr(1, devName.size() - 2);
    }
    if (devName != "?" && devName != "") {
        deviceInfoItem->name = devName;
    }
    

    // extract fops 
    auto fopsVal = callInst->getArgOperand(1);
    auto fopsStruct = getStructValue(fopsVal);
    if (!fopsStruct && Ctx->GlobalStructMap.count(fopsVal->getName().str())) {
        fopsStruct = Ctx->GlobalStructMap[fopsVal->getName().str()];
    }
    if (fopsStruct) {
        deviceInfoItem->OperationStruct = fopsStruct;
        deviceInfoItem->SyscallHandler = ProcessFileOperations(fopsStruct);
    }

    Ctx->SubsystemInfo.push_back(deviceInfoItem);

}

void DeviceExtractorPass::ProcessDebugfsCreateFile(CallInst* callInst) {
    outs() << "[*] new debugfs call: " << *callInst << "\n";
    DeviceInfoItem* deviceInfoItem = new DeviceInfoItem();
    deviceInfoItem->ItemType = DEVICE;
    deviceInfoItem->type = DEBUGFSDEVICE;
    auto filenameArg = callInst->getArgOperand(0);
    auto filename = getDeviceString(filenameArg);
    deviceInfoItem->name = filename;
    outs() << "[+] Filename: " << filename << "\n";
    auto directoryArg = callInst->getArgOperand(2);
    auto fopsArg = callInst->getArgOperand(4);
    auto fops = getStructValue(fopsArg);
    deviceInfoItem->OperationStruct = fops;
    deviceInfoItem->SyscallHandler = ProcessFileOperations(fops);
    Ctx->SubsystemInfo.push_back(deviceInfoItem);
}

bool DeviceExtractorPass::doInitialization(Module * M) {
    if (DFA == nullptr) {
        DFA = new DataFlowAnalysis(Ctx);
    }
    return false;
}

bool DeviceExtractorPass::doModulePass(Module * M) {
    for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
        Function& func = *mi;
        if (func.hasName()) {
            // misc device
            if (func.getName().str() == "misc_register") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessMiscDeviceInit(callInst);
                    }
                }
            // /dev/ device
            } else if (func.getName().str() == "cdev_init") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessCdevInit(callInst);
                    }
                }
            } else if (func.getName().str() == "register_chrdev") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessRegisterChrdev(callInst);
                    }
                }
            } else if (func.getName().str() == "__register_chrdev") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        Process__RegisterChrdev(callInst);
                    }
                }
            } else if (func.getName().str() == "cdev_add") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessCdevAdd(callInst);
                    }
                }
            // debugfs 
            // filename, prot, dir, xxx, fops
            // } else if (func.getName().str() == "debugfs_create_file" || func.getName().str() == "debugfs_create_file_unsafe") {
            //     for (auto user : func.users()) {
            //         if (auto callInst = dyn_cast<CallInst>(user)) {
            //             ProcessDebugfsCreateFile(callInst);
            //         }
            //     }
            // block device
            } else if (func.getName().str() == "device_add_disk") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessAddDisk(callInst);
                    }
                }
            // tty operations
            } else if (func.getName().str() == "tty_register_driver") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessTtyRegisterDriver(callInst);
                    }
                }
            // sound device
            } else if (func.getName().str() == "snd_register_device" || func.getName().str() == "snd_register_oss_device") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessSndRegisterDevice(callInst);
                    }
                }
            // anon inode getfile
            } else if (func.getName().str() == "anon_inode_getfile") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessAnonInodeGetfile(callInst);
                    }
                }
            // posix clock
            } else if (func.getName().str() == "posix_clock_register") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessPosixClockRegister(callInst);
                    }
                }
            // collect some additional dev names
            } else if (func.getName().str() == "__register_blkdev") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessRegisterBlkdev(callInst);
                    }
                }
            }
        }
    }
    return false;
} 

map<string, string> cgroupStrMap = {
    {"prioidx", "net_prio.prioidx"},
    {"ifpriomap", "net_prio.ifpriomap"},
    {"allow", "devices.allow"},
    {"deny", "devices.deny"},
    {"list", "devices.list"},
    {"state", "freezer.state"},
    {"self_freezing", "freezer.self_freezing"},
    {"parent_freezing", "freezer.parent_freezing"}
};

bool DeviceExtractorPass::doFinalization(Module * M) {

    // process mem dev 
    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) { 
        GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
        if (g == nullptr) {
            continue;
        }
        if (g->getName() == "devlist") {
            auto memdevlistArray = dyn_cast<ConstantArray>(g->getInitializer());
            if (!memdevlistArray) continue;
            for (int i = 0; i < memdevlistArray->getNumOperands(); i++) {
                auto memdev = dyn_cast<ConstantStruct>(memdevlistArray->getOperand(i));
                if (memdev && memdev->getType()->getName() == "struct.memdev") {
                    outs() << "memdev: " << *memdev << "\n";
                    auto deviceInfoItem = new DeviceInfoItem();
                    deviceInfoItem->ItemType = DEVICE;
                    deviceInfoItem->type = CHARDEVICE;
                    deviceInfoItem->name = getDeviceString(memdev->getOperand(0));
                    auto memFops = getStructValue(memdev->getOperand(2));
                    if (memFops == nullptr && Ctx->GlobalStructMap.count(memdev->getOperand(2)->getName().str())) {
                        memFops = getStructValue(Ctx->GlobalStructMap[memdev->getOperand(2)->getName().str()]);
                        // memFops = Ctx->
                    }
                    deviceInfoItem->OperationStruct = memFops;
                    deviceInfoItem->SyscallHandler = ProcessFileOperations(memFops);
                    Ctx->SubsystemInfo.push_back(deviceInfoItem);
                }
            }
        } 
        if (g->hasInitializer()) {
            auto constStruct = dyn_cast<ConstantStruct>(g->getInitializer());
            // posix clock
            if (constStruct && constStruct->getType()->getName() == "struct.posix_clock_operations") {
                auto deviceInfoItem = new DeviceInfoItem();
                deviceInfoItem->ItemType = DEVICE;
                deviceInfoItem->type = CHARDEVICE;
                deviceInfoItem->OperationStruct = constStruct;
                deviceInfoItem->SyscallHandler = ProcessPosixClockOperations(constStruct);
                string devName = "";
                for (auto &F: *M) {
                    devName = ExtractDevNameFromFunction(&F);
                    if (devName != "" && devName != "?" && devName != "%s") {
                        break;
                    }
                }
                deviceInfoItem->name = devName;
                Ctx->SubsystemInfo.push_back(deviceInfoItem);
            } else if (auto constArray = dyn_cast<ConstantArray>(g->getInitializer())) {
                for (auto i = 0; i < constArray->getNumOperands(); i++) {
                    auto constStruct = dyn_cast<ConstantStruct>(constArray->getOperand(i));
                    if (constStruct && constStruct->getType()->getName() == "struct.cftype") {
                        auto deviceInfoItem = new DeviceInfoItem();
                        deviceInfoItem->ItemType = DEVICE;
                        deviceInfoItem->type = CHARDEVICE;
                        deviceInfoItem->OperationStruct = constStruct;
                        auto devNameVal = getDeviceString(constStruct->getOperand(Ctx->StructFieldIdx["cftype"]["name"]));
                        char tmp[devNameVal.length() + 1];
                        strcpy(tmp, devNameVal.c_str());
                        devNameVal = string(tmp);
                        if (cgroupStrMap.count(devNameVal)) {
                            devNameVal = cgroupStrMap[devNameVal];
                        }
                        deviceInfoItem->name = devNameVal;
                        auto writeHandler = constStruct->getOperand(Ctx->StructFieldIdx["cftype"]["write"]);
                        if (writeHandler == nullptr || !isa<Function>(writeHandler)) {
                            writeHandler = constStruct->getOperand(Ctx->StructFieldIdx["cftype"]["write_u64"]);
                        }
                        if (writeHandler && isa<Function>(writeHandler)) {
                            deviceInfoItem->SyscallHandler["write"] = dyn_cast<Function>(writeHandler);
                            Ctx->SubsystemInfo.push_back(deviceInfoItem);
                        }
                    } else if (constStruct && constStruct->getType()->getName() == "struct.ctl_table") {
                        auto deviceInfoItem = new DeviceInfoItem();
                        deviceInfoItem->ItemType = DEVICE;
                        deviceInfoItem->type = CHARDEVICE;
                        deviceInfoItem->OperationStruct = constStruct;
                        auto devNameVal = getDeviceString(constStruct->getOperand(Ctx->StructFieldIdx["ctl_table"]["procname"]));
                        char tmp[devNameVal.length() + 1];
                        strcpy(tmp, devNameVal.c_str());
                        devNameVal = string(tmp);
                        deviceInfoItem->name = devNameVal;
                        auto devMode = constStruct->getOperand(Ctx->StructFieldIdx["ctl_table"]["mode"]);
                        auto devModeVal = dyn_cast<ConstantInt>(devMode);
                        if (!devModeVal || ((devModeVal->getZExtValue() & 0222) == 0)) {
                            continue;
                        }
                        auto writeHandler = constStruct->getOperand(Ctx->StructFieldIdx["ctl_table"]["proc_handler"]);
                        if (writeHandler && isa<Function>(writeHandler)) {
                            deviceInfoItem->SyscallHandler["write"] = dyn_cast<Function>(writeHandler);
                            Ctx->SubsystemInfo.push_back(deviceInfoItem);
                        }
                    } else {
                        break;
                    }   
                }
            }
        }
    }

    // // device_create
    // for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
    //     Function& func = *mi;
    //     if (func.hasName()) {
    //         // misc device
    //         if (func.getName().str() == "device_create") {
    //             for (auto user : func.users()) {
    //                 if (auto callInst = dyn_cast<CallInst>(user)) {
    //                     outs() << "[+] device create: " << *callInst << "\n";
    //                 }
    //             }
    //         } else if (func.getName().str() == "alloc_chrdev_region") {
    //             for (auto user : func.users()) {
    //                 if (auto callInst = dyn_cast<CallInst>(user)) {
    //                     outs() << "[+] alloc_chrdev_region: " << *callInst << "\n";
    //                 }
    //             }
    //         }
    //     }
    // }
    return false;
}