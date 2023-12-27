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

#include "FilesystemExtractor.h"
#include "Config.h"
#include "Common.h"
#include "Utils.h"

using namespace llvm;


string getFilesystemNameString(Value *currVal) {
    const GEPOperator *gep = dyn_cast<GEPOperator>(currVal);
    const llvm::GlobalVariable *strGlobal = nullptr;
    if(gep != nullptr) {
        strGlobal = dyn_cast<GlobalVariable>(gep->getPointerOperand());
    }
    if (strGlobal != nullptr && strGlobal->hasInitializer()) {
        const Constant *currConst = strGlobal->getInitializer();
        const ConstantDataArray *currDArray = dyn_cast<ConstantDataArray>(currConst);
        string res = "";
        raw_string_ostream ss(res);
        if(currDArray != nullptr) {
            ss << currDArray->getAsCString();
        } else {
            ss << *currConst;
        }
        return ss.str();
    }
    return "?";
}

GlobalVariable* FilesystemExtractorPass::getGlobalVaraible(StringRef varName)
{
    GlobalVariable* globalVar = nullptr;
    for(pair<Module*, StringRef> item : Ctx->Modules)
    {
        Module* M = item.first;
        GlobalVariable* tmp = M->getGlobalVariable(varName);
        if(tmp != nullptr && tmp->hasInitializer())
        {
            globalVar = tmp;
            break;
        }
    }
    return globalVar;
}

Function* FilesystemExtractorPass::getFunctionFromModules(StringRef funcName)
{
   Function* func = nullptr; 
   for(pair<Module*, StringRef> item : Ctx->Modules)
    {
        Module* M = item.first;
        Function* tmp = M->getFunction(funcName);
        if(tmp != nullptr && !tmp->isDeclaration() && tmp->getInstructionCount() > 0)
        {
            func = tmp;
            break;
        }
    }
    return func;
}

#define MAX_DEPTH_FIND_OPERATIONS 5

void FilesystemExtractorPass::getFileOperationsFromFillSuper(Function* F, FilesystemInfoItem* filesystemInfoItem, set<Function*>& visited, unsigned depth)
{

    if(visited.count(F))
    {
        return;
    }
    if(depth > MAX_DEPTH_FIND_OPERATIONS)
        return;
    visited.insert(F);
    if(F->getName() == "inode_init_always")
        return;
    outs() << "getFileOperationsFromFillSuper: " << F->getName() << "\n";
    for(inst_iterator iter = inst_begin(F); iter != inst_end(F); iter++)
    {
        Instruction* I = &*iter;
        if(I->getOpcode() == Instruction::Call)
        {
            CallInst* callInst = dyn_cast<CallInst>(I);
            if(Ctx->Callees[callInst].size() > 1)
                continue;
            for(Function* callee:Ctx->Callees[callInst])
            {
                getFileOperationsFromFillSuper(callee, filesystemInfoItem, visited, depth+1);
            }
        }
        else if(I->getOpcode() == Instruction::GetElementPtr)
        {
            GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(I);
            if(!gepInst->getSourceElementType()->isStructTy())
            {
                continue;
            }
            if(gepInst->getSourceElementType()->getStructName() == "struct.inode")
            {
                if(!gepInst->getResultElementType()->isPointerTy())
                {
                    continue;
                }
                if(!gepInst->getResultElementType()->getPointerElementType()->isStructTy())
                    continue;
                if(gepInst->getResultElementType()->getPointerElementType()->getStructName() == "struct.file_operations")
                {
                    for(User* user:gepInst->users())
                    {
                        if(StoreInst* storeInst = dyn_cast<StoreInst>(user))
                        {
                            Value* op = storeInst->getValueOperand();
                            GlobalVariable* globalVar = dyn_cast<GlobalVariable>(op);
                            if(globalVar == nullptr)
                            {
                                if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(op))
                                {
                                    globalVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
                                }
                            }
                            if(globalVar != nullptr)
                            {
                                if(!globalVar->hasInitializer())
                                {
                                    globalVar = getGlobalVaraible(globalVar->getName());
                                }
                            }
                            if(globalVar != nullptr)
                            {
                                bool flag = false;
                                for(GlobalVariable* gv:filesystemInfoItem->fileOperations)
                                {
                                    if(gv->getName() == globalVar->getName())
                                    {
                                        flag = true;
                                        break;
                                    }
                                }
                                if(flag)
                                    continue;
                                filesystemInfoItem->fileOperations.push_back(globalVar);
                            }
                        }
                    }
                }
            }
        }
    }
}

Function* FilesystemExtractorPass::findGetTreeFromInitFsCtx(Function* initFsCtx)
{
    Function* res = nullptr;
    Value* targetOp = nullptr;
    for(inst_iterator iter = inst_begin(initFsCtx); iter != inst_end(initFsCtx); iter++)
    {
        Instruction* I = &*iter;
        if(I->getOpcode() == Instruction::GetElementPtr)
        {
            GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(I);
            if(!gepInst->getSourceElementType()->isStructTy())
            {
                continue;
            }
            if(gepInst->getSourceElementType()->getStructName() == "struct.fs_context")
            {
                if(!gepInst->getResultElementType()->isPointerTy())
                {
                    continue;
                }
                if(!gepInst->getResultElementType()->getPointerElementType()->isStructTy())
                    continue;
                if(gepInst->getResultElementType()->getPointerElementType()->getStructName() == "struct.fs_context_operations")
                {
                    for(User* user:gepInst->users())
                    {
                        if(StoreInst* storeInst = dyn_cast<StoreInst>(user))
                        {
                            targetOp = storeInst->getValueOperand();
                            break;
                        }
                    }
                }

            }
        }
        if(targetOp != nullptr)
            break;
    }
    if(targetOp)
    {
        GlobalVariable* globalVar = dyn_cast<GlobalVariable>(targetOp);
        if(globalVar == nullptr)
        {
            if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(targetOp))
            {
                globalVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
            }
        }
        if(globalVar != nullptr)
        {
            if(!globalVar->hasInitializer())
            {
                globalVar = getGlobalVaraible(globalVar->getName());
            }
        }
        if(globalVar != nullptr)
        {
            ConstantStruct* constStruct = dyn_cast<ConstantStruct>(globalVar->getInitializer());
            Constant* getTreeFuncPtr = constStruct->getOperand(Ctx->StructFieldIdx["fs_context_operations"]["get_tree"]);
            if(!getTreeFuncPtr->isNullValue())
            {
                Function* getTree = dyn_cast<Function>(getTreeFuncPtr);
                if(getTree->getInstructionCount() == 0)
                    getTree = getFunctionFromModules(getTree->getName());
                if(getTree != nullptr)
                    res = getTree;
            }
        }
    }
    return res;
}

void FilesystemExtractorPass::getFileOperationsFromEntry(Function* F, FilesystemInfoItem* filesystemInfoItem, set<Function*>& visited, unsigned depth)
{
    if(visited.count(F))
    {
        return;
    }
    if(depth > MAX_DEPTH_FIND_OPERATIONS)
        return;
    visited.insert(F);
    if(F->getName() == "inode_init_always" || F->getName() == "init_specail_inode")
        return;
    for(inst_iterator iter = inst_begin(F); iter != inst_end(F); iter++)
    {
        Instruction* I = &*iter;
        if(I->getOpcode() == Instruction::Call)
        {
            CallInst* callInst = dyn_cast<CallInst>(I);
            if(Ctx->Callees[callInst].size() > 1)
                continue;
            
            for(Function* callee:Ctx->Callees[callInst])
            {
                if(!callee->isVarArg())
                {
                    for(Value* arg: callInst->args())
                    {
                        if(Function* calledBack = dyn_cast<Function>(arg))
                        {
                            if(calledBack->getInstructionCount() == 0)
                                calledBack = getFunctionFromModules(calledBack->getName());
                            if(calledBack != nullptr)
                            {
                                getFileOperationsFromEntry(calledBack, filesystemInfoItem, visited, depth+1);
                            }
                        }
                    }
                }
                getFileOperationsFromEntry(callee, filesystemInfoItem, visited, depth+1);
            }
            
            
        }
        else if(I->getOpcode() == Instruction::GetElementPtr)
        {
            GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(I);
            if(!gepInst->getSourceElementType()->isStructTy())
            {
                continue;
            }
            if(gepInst->getSourceElementType()->getStructName() == "struct.inode")
            {
                if(!gepInst->getResultElementType()->isPointerTy())
                {
                    continue;
                }
                if(!gepInst->getResultElementType()->getPointerElementType()->isStructTy())
                    continue;
                if(gepInst->getResultElementType()->getPointerElementType()->getStructName() == "struct.file_operations")
                {
                    for(User* user:gepInst->users())
                    {
                        if(StoreInst* storeInst = dyn_cast<StoreInst>(user))
                        {
                            Value* op = storeInst->getValueOperand();
                            GlobalVariable* globalVar = dyn_cast<GlobalVariable>(op);
                            if(globalVar == nullptr)
                            {
                                if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(op))
                                {
                                    globalVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
                                }
                            }
                            if(globalVar != nullptr)
                            {
                                if(!globalVar->hasInitializer())
                                {
                                    globalVar = getGlobalVaraible(globalVar->getName());
                                }
                            }
                            if(globalVar != nullptr)
                            {
                                bool flag = false;
                                for(GlobalVariable* gv:filesystemInfoItem->fileOperations)
                                {
                                    if(gv->getName() == globalVar->getName())
                                    {
                                        flag = true;
                                        break;
                                    }
                                }
                                if(flag)
                                    continue;
                                filesystemInfoItem->fileOperations.push_back(globalVar);
                            }
                        }
                    }
                }
            }
        }
    }
}

std::map<std::string, uint> PassGetTreeWrapper = {
    {"get_tree_keyed", 1},
    {"get_tree_single", 1},
    {"get_tree_nodev", 1},
    {"get_tree_bdev", 1},
    {"get_tree_mtd", 1},
};


void FilesystemExtractorPass::HandleFsTypeStruct(GlobalVariable* globalVar, FilesystemInfoItem* filesystemInfoItem)
{
    ConstantStruct* constStruct = dyn_cast<ConstantStruct>(globalVar->getInitializer());
    outs() << "[+] global variable defination: " << *globalVar << "\n";
    outs() << "[+] type: " << globalVar->getValueType()->getStructName() << "\n";
    // constStruct->ge
    Constant* filesystemNameVal = constStruct->getOperand(Ctx->StructFieldIdx["file_system_type"]["name"]);
    string filesystemName = getFilesystemNameString(filesystemNameVal);
    outs() << "str: " << filesystemName << "\n";
    filesystemInfoItem->name = filesystemName;
    filesystemInfoItem->filesystemTypeStruct = globalVar;
    Constant* mountFuncPtr = constStruct->getOperand(Ctx->StructFieldIdx["file_system_type"]["mount"]);
    Constant* initfsctxFuncPtr = constStruct->getOperand(Ctx->StructFieldIdx["file_system_type"]["init_fs_context"]);
    if(!mountFuncPtr->isNullValue())
    {
        Function* mountFunc = dyn_cast<Function>(mountFuncPtr);
        if(mountFunc->getInstructionCount() == 0)
        {
            mountFunc = getFunctionFromModules(mountFunc->getName());
        }
        if(mountFunc->getInstructionCount() != 0)
        {
            Function* fillSuperFunc = nullptr;
            for(inst_iterator iter = inst_begin(mountFunc); iter != inst_end(mountFunc); iter++)
            {
                Instruction* I = &*iter;
                if(I->getOpcode() == Instruction::Call)
                {
                    CallInst* callInst = dyn_cast<CallInst>(I);
                    if(callInst->getCalledFunction() != nullptr && callInst->getCalledFunction()->getName() == "mount_bdev")
                    {
                        fillSuperFunc = dyn_cast<Function>(callInst->getArgOperand(4));
                        outs() << "fill super func: " << fillSuperFunc->getName() << "\n";
                        break;
                    }
                    else if(callInst->getCalledFunction() != nullptr && callInst->getCalledFunction()->getName() == "mount_nodev")
                    {
                        fillSuperFunc = dyn_cast<Function>(callInst->getArgOperand(3));
                        outs() << "fill super func: " << fillSuperFunc->getName() << "\n";
                        break;
                    }
                    else if(callInst->getCalledFunction() != nullptr && callInst->getCalledFunction()->getName() == "mount_single")
                    {
                        fillSuperFunc = dyn_cast<Function>(callInst->getArgOperand(3));
                        outs() << "fill super func: " << fillSuperFunc->getName() << "\n";
                        break;
                    }
                }
            }
            if(fillSuperFunc != nullptr)
            {
                if(fillSuperFunc->getInstructionCount() == 0)
                {
                    fillSuperFunc = getFunctionFromModules(fillSuperFunc->getName());
                }
                if(fillSuperFunc->getInstructionCount() != 0) {
                    set<Function*> visited;
                    getFileOperationsFromFillSuper(fillSuperFunc, filesystemInfoItem, visited, 1); 
                    filesystemInfoItem->SyscallHandler.push_back(make_pair("mount", fillSuperFunc));
                }
            }
            else
            {
                set<Function*> visited;
                getFileOperationsFromFillSuper(mountFunc, filesystemInfoItem, visited, 1); 
                filesystemInfoItem->SyscallHandler.push_back(make_pair("mount", mountFunc));
            }
        }
    }
    if(!initfsctxFuncPtr->isNullValue())
    {
        Function* initfsctxFunc = dyn_cast<Function>(initfsctxFuncPtr);
        if(initfsctxFunc->getInstructionCount() == 0)
            initfsctxFunc = getFunctionFromModules(initfsctxFunc->getName());
        if(initfsctxFunc != nullptr)
        {
            Function* getTree = findGetTreeFromInitFsCtx(initfsctxFunc);
            if (getTree == nullptr) {
                return; 
            }
            Function* fillSuperFunc = nullptr;
            for (auto iter = inst_begin(getTree); iter != inst_end(getTree); iter++) {
                Instruction* I = &*iter; 
                if (I->getOpcode() != Instruction::Call) {
                    continue;
                }
                CallInst* callInst = dyn_cast<CallInst>(I);
                Function* calledFunc = callInst->getCalledFunction();
                if (calledFunc == nullptr) {
                    continue;
                }
                auto res = PassGetTreeWrapper.find(calledFunc->getName().str());
                if (res != PassGetTreeWrapper.end()) {
                    fillSuperFunc = dyn_cast<Function>(callInst->getArgOperand((*res).second));
                    outs() << "fill super func (from initFsCtx): " << fillSuperFunc->getName() << "\n"; 
                    if (fillSuperFunc->getInstructionCount() == 0) {
                        fillSuperFunc = getFunctionFromModules(fillSuperFunc->getName());
                    }
                    if (fillSuperFunc->getInstructionCount() != 0) {
                        filesystemInfoItem->SyscallHandler.push_back(make_pair("mount", fillSuperFunc));
                    }
                    break; 
                }
            }
            set<Function*> visited;
            getFileOperationsFromEntry(getTree, filesystemInfoItem, visited, 0);
        }
    }
    
    
}

vector<GlobalVariable*> getOperStruct(Module* M, const char* StrucName)
{
    vector<GlobalVariable*> res;
    for(auto gv = M->global_begin(); gv != M->global_end(); gv++)
    {
        GlobalVariable* globalVar = &(*gv); 
        if (globalVar == nullptr) {
            continue;
        }
        if (globalVar->getValueType()->isStructTy())
        {
            if (!globalVar->isConstant() || !globalVar->hasInitializer()) {
                continue;
            }
            if(globalVar->getName().endswith(StrucName))
            {
                res.push_back(globalVar);
            }
            else if(globalVar->getValueType()->getStructName().str() == string("struct.")+StrucName)
            {
                res.push_back(globalVar);
            }
        }
    }
    return res;
}

vector<pair<string, Function*>> FilesystemExtractorPass::getHandlerFromFileOperations(GlobalVariable* globalVar)
{
    vector<pair<string, Function*>> res = vector<pair<string, Function*>>();
    ConstantStruct* constStruct = dyn_cast<ConstantStruct>(globalVar->getInitializer());
    if (!constStruct && Ctx->GlobalStructMap.count(globalVar->getName().str())) {
        constStruct = dyn_cast<ConstantStruct>(Ctx->GlobalStructMap[globalVar->getName().str()]);
    } 
    if (!constStruct) return res;
    Constant* handlerRead = constStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["read"]);
    Constant* handlerWrite = constStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["write"]);
    Constant* handlerIoctl = constStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["unlocked_ioctl"]);
    Constant* handlerOpen = constStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["open"]);
    Constant* handlerMmap = constStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["mmap"]);
    if (handlerRead && isa<Function>(handlerRead))
    {
        Function* readFunc = dyn_cast<Function>(handlerRead);
        if(readFunc != nullptr)
        {
            if(readFunc->getInstructionCount() == 0)
            {
                readFunc = getFunctionFromModules(readFunc->getName());
            }
        }
        if(readFunc != nullptr)
        {
            res.push_back(make_pair("read", readFunc));
            GlobalCtx.FunctionArgMap[readFunc->getName().str()] = {1, 2, 4, 0};
        }
    }
    if (handlerWrite && isa<Function>(handlerWrite))
    {
        Function* writeFunc = dyn_cast<Function>(handlerWrite);
        if(writeFunc != nullptr)
        {
            if(writeFunc->getInstructionCount() == 0)
            {
                writeFunc = getFunctionFromModules(writeFunc->getName());
            }
        }
        if(writeFunc != nullptr)
        {
            res.push_back(make_pair("write", writeFunc));
            GlobalCtx.FunctionArgMap[writeFunc->getName().str()] = {1, 2, 4, 0};
        }
    }
    else
    {
        handlerWrite = constStruct->getOperand(Ctx->StructFieldIdx["file_operations"]["write_iter"]);
        if(handlerWrite && isa<Function>(handlerWrite))
        {
            Function* writeFunc = dyn_cast<Function>(handlerWrite);
            if(writeFunc != nullptr && writeFunc->getInstructionCount() == 0)
            {
                writeFunc = getFunctionFromModules(writeFunc->getName());
            }
            if(writeFunc != nullptr)
            {
                res.push_back(make_pair("write", writeFunc));
            }
        }
    }
    if (handlerIoctl && isa<Function>(handlerIoctl))
    {
        Function* ioctlFunc = dyn_cast<Function>(handlerIoctl);
        if(ioctlFunc != nullptr)
        {
            if(ioctlFunc->getInstructionCount() == 0)
            {
                ioctlFunc = getFunctionFromModules(ioctlFunc->getName());
            }
        }
        if(ioctlFunc != nullptr)
        {
            res.push_back(make_pair("ioctl", ioctlFunc));
            if(ioctlFunc->getName() == "autofs_root_ioctl")
            {
                outs() << "get autofs_root_ioctl" << "\n";
            }
            GlobalCtx.FunctionArgMap[ioctlFunc->getName().str()] = {1, 2, 4};
        }
    }
    if (handlerOpen && isa<Function>(handlerOpen))
    {
        Function* openFunc = dyn_cast<Function>(handlerOpen);
        if(openFunc != nullptr)
        {
            if(openFunc->getInstructionCount() == 0)
            {
                openFunc = getFunctionFromModules(openFunc->getName());
            }
        }
        if(openFunc != nullptr)
        {
            res.push_back(make_pair("open", openFunc));
            GlobalCtx.FunctionArgMap[openFunc->getName().str()] = {0, 1};
        }
    }
    if (handlerMmap && isa<Function>(handlerMmap))
    {
        Function* mmapFunc = dyn_cast<Function>(handlerMmap);
        if(mmapFunc != nullptr)
        {
            if(mmapFunc->getInstructionCount() == 0)
            {
                mmapFunc = getFunctionFromModules(mmapFunc->getName());
            }
        }
        if(mmapFunc != nullptr)
        {
            res.push_back(make_pair("mmap", mmapFunc));
            GlobalCtx.FunctionArgMap[mmapFunc->getName().str()] = {1, 2};
        }
    }
    return res;
}

map<string, vector<string>> xattrHandlerSyscallMap = {
    // {"get", {"getxattr", "lgetxattr", "fgetxattr"}}, 
    // {"set", {"setxattr", "lsetxattr", "fsetxattr"}},
    {"get", {"getxattr",}}, 
    {"set", {"setxattr",}},
};

vector<pair<string, Function*>> FilesystemExtractorPass::getHandlerFromASOperations(GlobalVariable* globalVar)
{
    vector<pair<string, Function*>> res = vector<pair<string, Function*>>();
    ConstantStruct* constStruct = dyn_cast<ConstantStruct>(globalVar->getInitializer());
    if (!constStruct && Ctx->GlobalStructMap.count(globalVar->getName().str())) {
        constStruct = dyn_cast<ConstantStruct>(Ctx->GlobalStructMap[globalVar->getName().str()]);
    } 
    if (!constStruct) return res;
    auto &asStructMap = Ctx->StructFieldIdx["address_space_operations"];

    for (auto readFuncName: {"readpage", "readpages"}) {
        Constant* handler = constStruct->getOperand(asStructMap[readFuncName]);
        if (!handler || !isa<Function>(handler)) {
            continue;
        }
        Function* readFunc = dyn_cast<Function>(handler);
        if(readFunc != nullptr && readFunc->getInstructionCount() == 0) {
            readFunc = getFunctionFromModules(readFunc->getName());
        }
        if(readFunc != nullptr) {
            res.push_back(make_pair("read", readFunc));
        }
    } 
    return res;
}

void FilesystemExtractorPass::ProcessRegisterFilesystem(CallInst* callInst)
{
    FilesystemInfoItem* filesystemInfoItem = new FilesystemInfoItem();
    filesystemInfoItem->ItemType = FILESYSTEM;
    Value* arg = callInst->getOperand(0);
    if(GlobalVariable* globalVar = dyn_cast<GlobalVariable>(arg))
    {
        outs() << "[*] global variable: " << *arg << "\n";
        outs() << "[*] type: " << *globalVar->getType() << "\n";
        if(globalVar->getValueType()->isStructTy())
        {
            if(globalVar->hasInitializer())
            {
                HandleFsTypeStruct(globalVar, filesystemInfoItem);
            }
            else
            {
                outs() << "[-] global variable declaration: " << *arg << "\n";
                GlobalVariable* globalVar = getGlobalVaraible(arg->getName());
                if(globalVar != nullptr)
                {
                    outs() << "[+] get global variable: " << *globalVar << "\n";
                    HandleFsTypeStruct(globalVar, filesystemInfoItem);
                }
            }
        }

    }
    else if(ConstantExpr* constantExpr = dyn_cast<ConstantExpr>(arg))
    {
        outs() << "[+] constant cast: " << *arg << "\n";
        if(constantExpr->isCast())
        {
            if(GlobalVariable* globalVar = dyn_cast<GlobalVariable>(constantExpr->getOperand(0)))
            {
                if(globalVar->hasInitializer())
                {
                    HandleFsTypeStruct(globalVar, filesystemInfoItem);
                }
                else
                {
                    outs() << "[-] global variable declaration: " << *arg << "\n";
                    globalVar = getGlobalVaraible(arg->getName());
                    if(globalVar != nullptr)
                    {
                        outs() << "[+] get global variable: " << *globalVar << "\n";
                        HandleFsTypeStruct(globalVar, filesystemInfoItem);
                    }
                }
            }

        }
    }
    else
    {
        outs() << "[-] local variable: " << *arg << "\n";
        outs() << "[-] variable name: " << arg->getName() << "\n";
        outs() << "[-] in function: " << callInst->getFunction()->getName() << "\n";
    }

    SpecialFSItem* SpecialFileSystemInfoItem=NULL;
    for(auto p:filesystemInfoItem->SyscallHandler){
            
        if(p.first!="mount")
            continue;
        Function* mntFunc=p.second;
        OP << "SpecialFSdebug: " << p.first << "|" << p.second->getName() << "\n";
        for (inst_iterator i = inst_begin(mntFunc), e = inst_end(mntFunc); 
            i != e; ++i) {
            if (CallInst *CI = dyn_cast<CallInst>(&*i)) {

                auto getCalledF=CI->getCalledFunction();
                if (getCalledF && getCalledF->getName()=="simple_fill_super" && CI->getNumOperands()==4){
                    
                    if(ConstantExpr* files_desc=dyn_cast<ConstantExpr>(CI->getOperand(2))){
                        if(GetElementPtrInst* GEP=dyn_cast<GetElementPtrInst>(files_desc->getAsInstruction())){
                            if(GlobalVariable* GBV=dyn_cast<GlobalVariable>(GEP->getPointerOperand())){
                                if(GBV->hasInitializer()){
                                    const Constant *currConst = GBV->getInitializer();
                                    const ConstantArray *currArray = dyn_cast<ConstantArray>(currConst);
                                    for(int i=0;i<currArray->getNumOperands();i++){
                                        Value* currentV=currArray->getOperand(i);
                                        if(isa<ConstantAggregateZero>(currentV)){
                                            continue;
                                        }
                                        ConstantStruct* tree_descr=dyn_cast<ConstantStruct>(currentV);



                                        string subdevname = "";
                                        Value* NameStr=tree_descr->getOperand(0);
                                        raw_string_ostream ss(subdevname);
                                        if(auto temp=dyn_cast<ConstantExpr>(NameStr)){
                                            auto GEP=dyn_cast<GetElementPtrInst>(temp->getAsInstruction());
                                            if(GlobalVariable* GVStr=dyn_cast<GlobalVariable>(GEP->getPointerOperand())){
                                                if(GVStr->hasInitializer()){
                                                    NameStr=GVStr->getInitializer();
                                                }
                                                
                                            }
                                            
                                        }
                                        if(!SpecialFileSystemInfoItem){
                                            SpecialFileSystemInfoItem=new SpecialFSItem(filesystemInfoItem);
                                            delete filesystemInfoItem;
                                        }                                        
                                        
                                        if(ConstantDataArray* currDArray=dyn_cast<ConstantDataArray>(NameStr)){
                                            ss << currDArray->getAsCString();
                                            auto the_ops=dyn_cast<GlobalVariable>(tree_descr->getOperand(1));
                                            if (the_ops->hasInitializer()){
                                                vector<pair<string, Function*>> res = getHandlerFromFileOperations(the_ops);
                                                for (auto p: res){
                                                    Function* f=p.second;
                                                    SpecialFileSystemInfoItem->Func2Dev[f]=subdevname;
                                                }
                                            }
                                        }
                                        
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (SpecialFileSystemInfoItem)
        filesystemInfoItem=SpecialFileSystemInfoItem;

       
    
    Ctx->SubsystemInfo.push_back(filesystemInfoItem);
}


vector<Module*> FilesystemExtractorPass::getRelatedModule(Module* M)
{
    vector<Module*> res;
    string srcFileName = M->getSourceFileName();
    if(count(srcFileName.begin(), srcFileName.end(), '/') == 1)
    {
        res.push_back(M);
        return res;
    }
    else if(count(srcFileName.begin(), srcFileName.end(), '/') > 1)
    {
        string prefix = srcFileName.substr(0, srcFileName.rfind("/"));
        for(pair<Module*, StringRef> item : Ctx->Modules)
        {
            Module* m = item.first;
            if(m->getSourceFileName().find(prefix) == 0)
            {
                res.push_back(m);
            }
        }
    }
    return res;
    
}

bool FilesystemExtractorPass::doInitialization(Module* M)
{
    return false;
}

bool FilesystemExtractorPass::doModulePass(Module* M)
{
    bool corner = false;
    for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
    {
        Function* F = &*mi;
        // corner case
        if (F->hasName() && F->getName().str() == "vfs_kern_mount" && corner == false) 
        {
            for (User* user: F->users()) 
            {
                if (CallInst* callInst = dyn_cast<CallInst>(user)) 
                {
                    corner = true;
                    ProcessRegisterFilesystem(callInst);
                }
            }
        }
        if(F->hasName() && F->getName().str() == "register_filesystem")
        {
            for(User* user : F->users())
            {
                if(CallInst* callInst = dyn_cast<CallInst>(user))
                {
                    ProcessRegisterFilesystem(callInst);
                    vector<Module*> relatedModule = getRelatedModule(M);
                    for(Module* m: relatedModule)
                    {
                        outs() << "related modules\n";
                        outs() << m->getSourceFileName() << "\n";
                    }
                    FilesystemInfoItem* filesystemInfoItem = static_cast<FilesystemInfoItem*>(Ctx->SubsystemInfo[Ctx->SubsystemInfo.size() - 1]);
                    vector<GlobalVariable*> shouldRemove;
                    for(GlobalVariable* gv: filesystemInfoItem->fileOperations)
                    {
                        bool flag = false;
                        for(Module* m : relatedModule)
                        {
                            if(m->getGlobalVariable(gv->getName()) != nullptr)
                            {
                                outs() << "global variable name: " << gv->getName() << "\n";
                                if(m->getGlobalVariable(gv->getName()) == gv)
                                {
                                    flag = true;
                                    break;
                                }
                            }       
                        }
                        if(flag)
                            continue;
                        shouldRemove.push_back(gv);
                    }
                    for(GlobalVariable* gv : shouldRemove)
                    {
                        filesystemInfoItem->fileOperations.erase(find(filesystemInfoItem->fileOperations.begin(), filesystemInfoItem->fileOperations.end(), gv));
                    }
                    if(filesystemInfoItem->name != "debugfs")
                    {
                        for(Module* m: relatedModule)
                        {       
                            vector<GlobalVariable*> fileOperations = getOperStruct(m, "file_operations");
                            for(GlobalVariable* gv : fileOperations)
                            {
                                outs() << "file operations name: " << gv->getName() << "\n";
                                outs() << "file operations type: " << gv->getValueType()->getStructName() << "\n";
                                if(find(filesystemInfoItem->fileOperations.begin(), filesystemInfoItem->fileOperations.end(), gv) != filesystemInfoItem->fileOperations.end())
                                    continue;
                                filesystemInfoItem->fileOperations.push_back(gv);
                            }
                        } 
                        set<GlobalVariable*> asOperStructs;
                        for (Module* m: relatedModule) {       
                            vector<GlobalVariable*> asOperations = getOperStruct(m, "address_space_operations");
                            for(GlobalVariable* gv : asOperations) {
                                asOperStructs.insert(gv);
                            }
                        }
                        for (GlobalVariable* gv: asOperStructs) {
                            auto res = getHandlerFromASOperations(gv);
                            bool flag = false;
                            for(pair<string, Function*> item: res) {
                                for(pair<string, Function*> i:filesystemInfoItem->SyscallHandler)
                                {
                                    if(item.first == i.first && item.second->getName() == i.second->getName())
                                    {
                                        flag = true;
                                        break;
                                    }
                                }
                                if(flag)
                                    continue;
                                filesystemInfoItem->SyscallHandler.push_back(item);
                            }
                        }
                    }
                    for(GlobalVariable* globalVar:filesystemInfoItem->fileOperations)
                    {
                        vector<pair<string, Function*>> res = getHandlerFromFileOperations(globalVar);
                        for(pair<string, Function*> item: res)
                        {
                            bool flag = false;
                            for(pair<string, Function*> i:filesystemInfoItem->SyscallHandler)
                            {
                                if(item.first == i.first && item.second->getName() == i.second->getName())
                                {
                                    flag = true;
                                    break;
                                }
                            }
                            if(flag)
                                continue;
                            filesystemInfoItem->SyscallHandler.push_back(item);
                        }
                    }
                }
            }
            
        }
    }

    auto xattrHandlers = getOperStruct(M, "xattr_handler");
    auto xattrHandlerStruc = Ctx->StructFieldIdx["xattr_handler"];
    for (auto handler : xattrHandlers) {
        vector<pair<string, Function*>> res = vector<pair<string, Function*>>();
        ConstantStruct* constStruct = dyn_cast<ConstantStruct>(handler->getInitializer());
        if (!constStruct) {
            outs() << "what???? should have " << handler->getName().str() << " in module: " << M->getName() << '\n' ;
            continue;
        }
        Constant* handlerGet = constStruct->getOperand(xattrHandlerStruc["get"]);
        Constant* handlerSet = constStruct->getOperand(xattrHandlerStruc["set"]);

        for (auto iterIdx: {0, 1}) {
            auto fieldName = "name"; 
            if (iterIdx == 1) {
                fieldName = "prefix";
            }
            Constant* strConst = constStruct->getOperand(xattrHandlerStruc[fieldName]);
            if (!strConst) {
                outs() << "no field: " << fieldName << '\n';
                continue;
            }
            string strVal = "";
            auto t2 = dyn_cast<ConstantExpr>(strConst);
            if (!t2) {
                continue;
            }
            auto t3 = t2->getAsInstruction(); 
            if (!t3) {
                continue;
            }
            auto t4 = dyn_cast<GetElementPtrInst>(t3);
            if (!t4) {
                continue;
            }
            auto t5 = t4->getPointerOperand();
            if (!t5) {
                continue;
            }
            auto t6 = dyn_cast<GlobalVariable>(t5);
            if (t6 && t6->hasInitializer()) {                                  
                auto t8 = dyn_cast<ConstantDataArray>(t6->getInitializer()); 
                if (t8) {
                    strVal = t8->getAsCString().str();
                }
            } else {   
                continue;
            }
            if (iterIdx == 1) {
                strVal += "*";
            }
            vector<pair<string, Function*>> SyscallHandler; 
            for (auto &handlerItem: xattrHandlerSyscallMap) {
                Constant* handlerPtr = constStruct->getOperand(xattrHandlerStruc[handlerItem.first]);
                if (!handlerPtr || !isa<Function>(handlerPtr)) {
                    continue;
                }
                Function* handlerFunc = dyn_cast<Function>(handlerPtr);
                if (handlerFunc != nullptr && handlerFunc->getInstructionCount() == 0) {
                    handlerFunc = getFunctionFromModules(handlerFunc->getName());
                }
                if (handlerFunc == nullptr) {
                    continue; 
                }
                for (auto syscall: handlerItem.second) {
                    SyscallHandler.push_back(make_pair(syscall, handlerFunc));
                }
            } 
            if (SyscallHandler.size() > 0) {
                FilesystemInfoItem* filesystemInfoItem = new FilesystemInfoItem();
                filesystemInfoItem->ItemType = FILESYSTEM;
                filesystemInfoItem->name = strVal;
                filesystemInfoItem->SyscallHandler = SyscallHandler;
                filesystemInfoItem->filesystemTypeStruct = nullptr;
                Ctx->SubsystemInfo.push_back(filesystemInfoItem);
            }
        }
    }
    return false;
}

bool FilesystemExtractorPass::doFinalization(Module* M)
{
    return false;
}

SpecialFSItem::SpecialFSItem(){}

SpecialFSItem::SpecialFSItem(FilesystemInfoItem* InfoItem){
    /* from infoitem */
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    /* from FilesystemInfoItem */
    this->filesystemTypeStruct=InfoItem->filesystemTypeStruct;
    this->fileOperations=InfoItem->fileOperations;
    this->SyscallHandler=InfoItem->SyscallHandler;
}



string FilesystemInfoItem::generateDeviceSignature(Function*){
    return name;
}



string SpecialFSItem::generateDeviceSignature(Function* func){
    if (Func2Dev.count(func) && Func2Dev[func]!=""){
        return name+" "+Func2Dev[func];
    }
    else
        return name;
}

