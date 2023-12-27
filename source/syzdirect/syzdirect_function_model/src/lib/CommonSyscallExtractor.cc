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

#include "CommonSyscallExtractor.h"
#include "Config.h"
#include "Common.h"

#include "Utils.h"

#include "Signature.h"
#include "ArgMapParser.h"

bool CommonSyscallExtractorPass::doInitialization(Module *M) {
    if (DFA == nullptr) {
        DFA = new DataFlowAnalysis(Ctx);
    }
    if (CopyFuncs == nullptr) {
        CopyFuncs = new map<string, tuple<int8_t, int8_t, int8_t>>();
        SetCopyFuncs(*CopyFuncs);
    }
    if (DataFetchFuncs == nullptr) {
        DataFetchFuncs = new map<string, pair<int8_t, int8_t>>();
        SetDataFetchFuncs(*DataFetchFuncs);
    }
    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) {
        GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
        if (g == nullptr) {
            continue;
        }
        if (g->getValueType()->isStructTy()) {
            if (auto structType = dyn_cast<StructType>(g->getValueType())) {
                auto structTypeName = structType->getName();
                if (structTypeName == "struct.key_type") {
                    outs() << *g << "\n";
                    auto structVal = getStructValue(g);
                    if (!structVal && Ctx->GlobalStructMap.count(g->getName().str())) {
                        structVal = getStructValue(Ctx->GlobalStructMap[g->getName().str()]);
                    }
                    if (structVal) {
                        if (auto constStruct = dyn_cast<ConstantStruct>(structVal)) {
                            auto stringVal = constStruct->getOperand(Ctx->StructFieldIdx["key_type"]["name"]);
                            auto keyName = getDeviceString(stringVal);
                            if (keyName != "?") {
                                outs() << "key: " << keyName << "\n";
                                KeyNames.insert(keyName);
                            }
                        }
                    }
                } else if (structTypeName == "struct.xattr_handler") {
                    outs() << *g << "\n";
                    auto structVal = getStructValue(g);
                    if (!structVal && Ctx->GlobalStructMap.count(g->getName().str())) {
                        structVal = getStructValue(Ctx->GlobalStructMap[g->getName().str()]);
                    }
                    if (structVal) {
                        if (auto constStruct = dyn_cast<ConstantStruct>(structVal)) {
                            auto stringVal = constStruct->getOperand(Ctx->StructFieldIdx["xattr_handler"]["name"]);
                            auto xattrName = getDeviceString(stringVal);
                            if (xattrName != "?") {
                                outs() << "xattr: " << xattrName << "\n";
                                XattrNames.insert(xattrName);
                            }
                        }
                    }
                }
            }

        }
    }
    return false;
}

bool CommonSyscallExtractorPass::doFinalization(Module *M) {
    return false;
}

map<pair<string, string>, string> ProcessedSyscall;

void CommonSyscallExtractorPass::GetStringCmpInFuncArgImpl(Function* func, int argIdx, set<Value*>* targetVal, set<pair<Value*, int>>* visited, set<string>* comparedStr) {
    if (visited->count({func, argIdx})) {
        return;
    }
    visited->insert({func, argIdx});
    auto arg = func->getArg(argIdx);
    targetVal->insert(arg);
    for (auto &BB: *func) {
        for (auto &I: BB) {
            if (auto castInst = dyn_cast<CastInst>(&I)) {
                auto val = castInst->getOperand(0);
                if (targetVal->find(val) != targetVal->end()) {
                    targetVal->insert(castInst);
                }
            } else if (auto unaryInst = dyn_cast<UnaryInstruction>(&I)) {
                auto val = unaryInst->getOperand(0);
                if (targetVal->find(val) != targetVal->end()) {
                    targetVal->insert(castInst);
                }
            } else if (auto binaryInst = dyn_cast<BinaryOperator>(&I)) {
                auto val = binaryInst->getOperand(0);
                if (targetVal->find(val) != targetVal->end()) {
                    targetVal->insert(binaryInst);
                }
                val = binaryInst->getOperand(1);
                if (targetVal->find(val) != targetVal->end()) {
                    targetVal->insert(binaryInst);
                }
            } else if (auto phiInst = dyn_cast<PHINode>(&I)) {
                for (int i = 0; i < phiInst->getNumIncomingValues(); i++) {
                    auto val = phiInst->getIncomingValue(i);
                    if (targetVal->find(val) != targetVal->end()) {
                        targetVal->insert(phiInst);
                    }
                }
            } else if (auto callInst = dyn_cast<CallInst>(&I)) {
                auto callee = callInst->getCalledFunction();
                if (callee && callee->hasName()) {
                    auto calleeName = callee->getName().str();
                    
                    if (calleeName == "strcmp" || calleeName == "strncmp" || calleeName == "memcmp") {
                        auto arg0 = callInst->getArgOperand(0);
                        auto arg1 = callInst->getArgOperand(1);
                        if (targetVal->find(arg0) != targetVal->end() || targetVal->find(arg1) != targetVal->end()) {
                            auto str = getDeviceString(callInst->getArgOperand(1));
                            if (str != "?") {
                                comparedStr->insert(str);
                            }
                        }
                    } else if (DataFetchFuncs->count(calleeName)) {
                        auto item = DataFetchFuncs->at(calleeName);
                        auto dst = item.first;
                        auto src = item.second;
                        if (targetVal->find(callInst->getArgOperand(src)) != targetVal->end()) {
                            if (dst == -1) {
                                targetVal->insert(callInst);
                            } else {
                                targetVal->insert(callInst->getArgOperand(dst));
                            }
                        }
                    }  else if (CopyFuncs->count(calleeName)) {
                        auto item = CopyFuncs->at(calleeName);
                        auto dst = get<1>(item);
                        auto src = get<0>(item);
                        if (targetVal->find(callInst->getArgOperand(src)) != targetVal->end()) {
                            targetVal->insert(callInst->getArgOperand(dst));
                        }
                    } else {
                        for (int i = 0; i < callee->arg_size(); i++) {
                            auto argx = callInst->getArgOperand(i);
                            if (targetVal->find(argx) != targetVal->end()) {
                                if (callee->getInstructionCount() > 0) { 
                                    GetStringCmpInFuncArgImpl(callee, i, targetVal, visited, comparedStr);
                                } else {
                                    for (auto newCallee: Ctx->Callees[callInst]) {
                                        GetStringCmpInFuncArgImpl(newCallee, i, targetVal, visited, comparedStr);
                                    }
                                }
                            }
                        }
                    } 
                } else {
                    auto callees = Ctx->Callees[callInst];
                    for (auto callee: callees) {
                        for (int i = 0; i < callee->arg_size(); i++) {
                            if (i >= callInst->getNumArgOperands()) {
                                break;
                            }
                            auto argx = callInst->getArgOperand(i);
                            if (targetVal->find(argx) != targetVal->end()) {
                                outs() << callee->getName() << " " << i << "\n";
                                GetStringCmpInFuncArgImpl(callee, i, targetVal, visited, comparedStr);
                            }
                        }
                    }
                }
            }
        }

    }
}

set<string>* CommonSyscallExtractorPass::GetStringCmpInFuncArg(Function* func, int argIdx) {
    set<Value*> *targetVal = new set<Value*>();
    set<pair<Value*, int>>* visited = new set<pair<Value*, int>>();
    set<string> *comparedStr = new set<string>();
    GetStringCmpInFuncArgImpl(func, argIdx, targetVal, visited, comparedStr);
    return comparedStr;
}

bool CommonSyscallExtractorPass::doModulePass(Module *M) {
    for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
        Function& func = *mi;
        if (func.hasName()) {
            auto funcName = func.getName().str();
            if (SyscallHandlerToSyscall.count(funcName)) {
                auto syscalls = SyscallHandlerToSyscall[funcName];
                for (auto syscall: syscalls) {
                    if (ProcessedSyscall.count({funcName, syscall})) {
                        continue;
                    }
                    outs() << syscall << " " << funcName << "\n";
                    vector<vector<int>> argMap = getArgMapByFunc(&func);
                    auto argConstMap = getTargetBlocksInFuncByArgMap(&func, argMap, syscall);
                    if (funcName == "__se_sys_keyctl") {
                        argConstMap[1] = ConstBlockMap();
                        argConstMap[2] = ConstBlockMap();
                        argConstMap[3] = ConstBlockMap();
                        argConstMap[4] = ConstBlockMap();
                    }
                    for (auto item: argConstMap) {
                        auto idx = item.first;
                        auto basicBlockMap = item.second;
                        outs() << "\t Arg " << idx << "\n";
                        if (StringCompareSyscallArg.count(syscall) && idx == StringCompareSyscallArg[syscall]) {
                            auto comparedStr = GetStringCmpInFuncArg(&func, idx);
                            argConstMap[idx] = ConstBlockMap();
                            for (auto str: *comparedStr) {
                                argConstMap[idx].push_back(new CMDConst(nullptr, CastOpPath(), nullptr, nullptr, OperandPath(), str));
                            }
                            delete comparedStr;
                            if (SyscallStringSetMap.count(syscall)) {
                                outs() << "TQL " << syscall << "\n";
                                auto strSet = SyscallStringSetMap[syscall];
                                for (auto str: *strSet) {
                                    outs() << str << "\n";
                                    argConstMap[idx].push_back(new CMDConst(nullptr, CastOpPath(), nullptr, nullptr, OperandPath(), str));
                                }
                            }
                        }
                        for (auto x: basicBlockMap) {
                            auto constant = x->value;
                            if (constant) {
                                outs() << "\t\t" << constant->getZExtValue() << "\n";
                            }
                        }
                    }
                    auto signature = new Signature(&func, syscall, syscall, argConstMap);
                    Ctx->AllSignatures.push_back(signature);
                    ProcessedSyscall[{funcName, syscall}] = syscall;
                }
            }
        }
    }
    return false;
}