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

#include "NetworkInterfaceExtractor.h"
#include "Config.h"
#include "Common.h"

#include "Utils.h"

#include "DbgInfoHelper.h"

#include "CodeFeatures.h"

using namespace llvm;

NetlinkInfoItem::NetlinkInfoItem()
{
}

vector<string> NetlinkInfoItem::generateSendmsgSignature()
{
    vector<string> res;
    string str = "sendmsg";
    string socketStr = "socket-[";
    socketStr += to_string(this->family);
    socketStr += "]-[";
    socketStr += to_string(this->type);
    socketStr += "]-[";
    socketStr += to_string(this->protocol);
    socketStr += "]";
    str += "|D[" + socketStr + "]";
    if(this->SendmsgHandler == nullptr || this->SendmsgHandler->getName().str() == "") {
        // handler为none没有意义，直接返回
        return res; 
    }
    string handlerName = this->SendmsgHandler->getName().str();
    vector<CMDConst*> constValues = getValueInSwitchCase(this->SendmsgHandler);
    
    res.push_back(str + "|C[]|C[]" + " 0" + " " + handlerName);

    for(CMDConst* cmdConst : constValues)
    {
        BasicBlock *targetBB = cmdConst->targetBlock;
        Function *targetFunc = targetBB->getParent();
        int idx = -1;
        for (auto it = targetFunc->begin(), end = targetFunc->end(); it != end; it++) {
            idx += 1;
            BasicBlock *it2BB = &*it;
            if (it2BB == targetBB) {
                break;
            }
        }
        string tmp = str;
        tmp = tmp + "|C[" + to_string(cmdConst->value->getZExtValue()) + "]|C[]";
        tmp = tmp + " " + "1";
        tmp = tmp + " " + targetFunc->getName().str();
        tmp = tmp + " " + to_string(idx);
        tmp = tmp + " " + handlerName;
        res.push_back(tmp);
    }
    return res;
}

NetlinkInfoItem::NetlinkInfoItem(NetworkInterfaceInfoItem* InfoItem)
{
    this->family = InfoItem->family;
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    this->type = InfoItem->type;
    this->protocol = InfoItem->protocol;
    this->SyscallHandler = InfoItem->SyscallHandler;
    this->CreateFunction = InfoItem->CreateFunction;
    this->SendmsgHandler = NULL;
}

RtnetlinkInfoItem::RtnetlinkInfoItem(NetlinkInfoItem* InfoItem)
{
    this->family = InfoItem->family;
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    this->type = InfoItem->type;
    this->protocol = InfoItem->protocol;
    this->SyscallHandler = InfoItem->SyscallHandler;
    this->CreateFunction = InfoItem->CreateFunction;
    this->SendmsgHandler = InfoItem->SendmsgHandler;
}

vector<string> RtnetlinkInfoItem::generateSendmsgSignature()
{
    vector<string> res;
    string str = "sendmsg";
    string socketStr = "socket-[";
    socketStr += to_string(this->family);
    socketStr += "]-[";
    socketStr += to_string(this->type);
    socketStr += "]-[";
    socketStr += to_string(this->protocol);
    socketStr += "]";
    str += "|D[" + socketStr + "]";

    if(this->SendmsgHandler == nullptr || this->SendmsgHandler->getName().str() == "") {
        return res; 
    }
    string handlerName = this->SendmsgHandler->getName().str();

    res.push_back(str + "|C[]|C[]" + " 0 " + handlerName);
    
    for(auto item: this->RtnetlinkHandlers)
    {
        res.push_back(str + "|C[" + to_string(get<1>(item)) + "]|C[]" + " 0 " + handlerName);
        Function* subHandler = get<2>(item);
        if (subHandler) {
            string subHandlerName = subHandler->getName().str();
            if (subHandlerName != "")
                res.push_back(str + "|C[" + to_string(get<1>(item)) + "]|C[]" + " 0 " + subHandlerName);
        }
        Function* subDumpHandler = get<3>(item);
        if (subDumpHandler) {
            string subHandlerName = subDumpHandler->getName().str();
            if (subHandlerName != "") {
                res.push_back(str + "|C[" + to_string(get<1>(item)) + "]|C[]" + " 0 " + subHandlerName);
            }
        }
    }
    return res;
}

GenlInfoItem::GenlInfoItem(NetlinkInfoItem* InfoItem)
{
    this->family = InfoItem->family;
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    this->type = InfoItem->type;
    this->protocol = InfoItem->protocol;
    this->SyscallHandler = InfoItem->SyscallHandler;
    this->CreateFunction = InfoItem->CreateFunction;
    this->SendmsgHandler = InfoItem->SendmsgHandler;
}

vector<string> GenlInfoItem::generateSendmsgSignature()
{
    vector<string> res;
    string str = "sendmsg";
    string socketStr = "socket-[";
    socketStr += to_string(this->family);
    socketStr += "]-[";
    socketStr += to_string(this->type);
    socketStr += "]-[";
    socketStr += to_string(this->protocol);
    socketStr += "]";
    str += "|D[" + socketStr + "]";

    if(this->SendmsgHandler == nullptr || this->SendmsgHandler->getName().str() == "") {
        return res; 
    }
    string handlerName = this->SendmsgHandler->getName().str();
    
    res.push_back(str + "|P[S[]C[]]|C[]" + " 0 " + handlerName);
   
    for(GenlFamilyInfo* genlFamilyInfo:this->GenlInfos)
    {
        char tmp[genlFamilyInfo->familyName.length() + 1];
        strcpy(tmp, genlFamilyInfo->familyName.c_str());
        string s = str + "|P[S[" + tmp + "]";
        if(genlFamilyInfo->GenlHandlers.size() == 0)
        {
            res.push_back(s + "C[]]|C[]" + " 0 " + handlerName);
            continue;
        }
        for(auto item:genlFamilyInfo->GenlHandlers)
        {
            bool hasSig = false;
            string prefix = s + "C[" + to_string(get<0>(item)) + "]]|C[]" + " 0 ";
            Function* subHandler = get<1>(item);
            if (subHandler && subHandler->getName().str() != "") {
                res.push_back(prefix + subHandler->getName().str());
                hasSig = true;
            }
            subHandler = get<2>(item);
            if (subHandler && subHandler->getName().str() != "") {
                res.push_back(prefix + subHandler->getName().str());
                hasSig = true;
            }
            if (!hasSig)
                res.push_back(prefix + handlerName);
        }
    }
    return res;
}

XfrmInfoItem::XfrmInfoItem(NetlinkInfoItem* InfoItem)
{
    this->family = InfoItem->family;
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    this->type = InfoItem->type;
    this->protocol = InfoItem->protocol;
    this->SyscallHandler = InfoItem->SyscallHandler;
    this->CreateFunction = InfoItem->CreateFunction;
    this->SendmsgHandler = InfoItem->SendmsgHandler;
}

vector<string> XfrmInfoItem::generateSendmsgSignature()
{
    vector<string> res;
    string str = "sendmsg";
    string socketStr = "socket-[";
    socketStr += to_string(this->family);
    socketStr += "]-[";
    socketStr += to_string(this->type);
    socketStr += "]-[";
    socketStr += to_string(this->protocol);
    socketStr += "]";
    str += "|D[" + socketStr + "]";

    if(this->SendmsgHandler == nullptr || this->SendmsgHandler->getName().str() == "") {
        return res; 
    }
    string handlerName = this->SendmsgHandler->getName().str();
    
    res.push_back(str + "|C[]|C[]" + " 0 " + handlerName);
    for(auto item: this->XfrmHandlers) {
        for (auto func: {get<1>(item), get<2>(item)}) {
            if (func != nullptr && func->getName().str() != "") {
               res.push_back(str + "|C[" + to_string(get<0>(item)) + "]|C[]" + " 0 " + func->getName().str());
            }
        }
    }
    return res;
}

NetfilterInfoItem::NetfilterInfoItem(NetlinkInfoItem* InfoItem)
{
    this->family = InfoItem->family;
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    this->type = InfoItem->type;
    this->protocol = InfoItem->protocol;
    this->SyscallHandler = InfoItem->SyscallHandler;
    this->CreateFunction = InfoItem->CreateFunction;
    this->SendmsgHandler = InfoItem->SendmsgHandler;
}

vector<string> NetfilterInfoItem::generateSendmsgSignature()
{
    vector<string> res;
    string str = "sendmsg";
    string socketStr = "socket-[";
    socketStr += to_string(this->family);
    socketStr += "]-[";
    socketStr += to_string(this->type);
    socketStr += "]-[";
    socketStr += to_string(this->protocol);
    socketStr += "]";
    str += "|D[" + socketStr + "]";

    if(this->SendmsgHandler == nullptr || this->SendmsgHandler->getName().str() == "") {
        return res; 
    }
    string handlerName = this->SendmsgHandler->getName().str();
    
    res.push_back(str + "|C[]|C[]" + " 0 " + handlerName);

    for(NfSubsysInfo* nfSubsysInfo : this->NfSubsysInfos)
    {
        string s = str + "|P[C[" + to_string(nfSubsysInfo->subsysID) + "]";
        if(nfSubsysInfo->NetfilterHandlers.size() == 0)
        {
            res.push_back(s + "C[]]|C[]" + " 0 " + handlerName);
            continue;
        }
        for(auto item:nfSubsysInfo->NetfilterHandlers)
        {
            res.push_back(s + "C[" + to_string(item.first) + "]]|C[]" + " 0 " + handlerName + " 0 " + item.second->getName().str());
        }
    }
    return res;
}

RDMAInfoItem::RDMAInfoItem(NetlinkInfoItem* InfoItem)
{
    this->family = InfoItem->family;
    this->ItemType = InfoItem->ItemType;
    this->name = InfoItem->name;
    this->type = InfoItem->type;
    this->protocol = InfoItem->protocol;
    this->SyscallHandler = InfoItem->SyscallHandler;
    this->CreateFunction = InfoItem->CreateFunction;
    this->SendmsgHandler = InfoItem->SendmsgHandler;
}

vector<string> RDMAInfoItem::generateSendmsgSignature()
{
    vector<string> res;
    string str = "sendmsg";
    string socketStr = "socket-[";
    socketStr += to_string(this->family);
    socketStr += "]-[";
    socketStr += to_string(this->type);
    socketStr += "]-[";
    socketStr += to_string(this->protocol);
    socketStr += "]";
    str += "|D[" + socketStr + "]";
    if(this->RDMAHandlers.size() == 0)
    {
        res.push_back(str + "|C[]|C[]");
        return res;
    }
    for(auto item : this->RDMAHandlers)
    {
        unsigned msgtype = (get<0>(item) << 10) | get<1>(item);
        res.push_back(str + "|C[" + to_string(msgtype) + "]|C[]");
    }
    return res;
}


string networkSyscalls[] = {
    "ioctl",
    "sendmsg", 
    "recvmsg",
    "setsockopt",
    "getsockopt",
    "bind", 
    "connect", 
    "accept", 
    "listen",
    "getname",
};

void generateNetworkSyscallsArgMapProtoOps(Function* handlerFunc, string syscall)
{
    if(syscall == "ioctl")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4};
    }
    else if(syscall == "sendmsg")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 0};
    }
    else if(syscall == "recvmsg")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 0, 4};
    }
    else if(syscall == "setsockopt" || syscall == "getsockopt")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4, 8, 0, 16};
    }
    else if(syscall == "bind")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4};
    }
    else if(syscall == "connect")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4, 0};
    }
    else if(syscall == "accept")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 0, 0, 0};
    }
    else if(syscall == "listen")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 0};
    }
    else if(syscall == "getname")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 0, 0};
    }
}

void generateNetworkSyscallsArgMapProto(Function* handlerFunc, string syscall)
{
    if(syscall == "ioctl")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4};
    }
    else if(syscall == "sendmsg")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 0};
    }
    else if(syscall == "recvmsg")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 0, 0, 4, 0};
    }
    else if(syscall == "setsockopt" || syscall == "getsockopt")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4, 8, 0, 16};
    }
    else if(syscall == "bind")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4};
    }
    else if(syscall == "connect")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 2, 4};
    }
    else if(syscall == "accept")
    {
        GlobalCtx.FunctionArgMap[handlerFunc->getName().str()] = {1, 0, 0, 0};
    }
}

void NetworkInterfaceExtractorPass::getProtoOpsFromCreateFunction(Function* F, ConstantStruct** protoOps, set<Function*>&visited, int depth)
{
    outs() << "in function: " << F->getName() << "\n";
    if(depth > 1)
    {
        return;
    }
    if(visited.count(F))
    {
        return;
    }
    if(*protoOps != nullptr)
        return;
    visited.insert(F);
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
                if(callee->isVarArg())
                {
                    continue;
                }
                getProtoOpsFromCreateFunction(callee, protoOps, visited, depth + 1);
                if(*protoOps != nullptr)
                    return;
            }
        }
        else if(I->getOpcode() == Instruction::GetElementPtr)
        {
            GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(I);
            if(!gepInst->getSourceElementType()->isStructTy())
            {
                continue;
            }
            if(gepInst->getSourceElementType()->getStructName() == "struct.socket")
            {
                if(!gepInst->getResultElementType()->isPointerTy())
                {
                    continue;
                }
                if(!gepInst->getResultElementType()->getPointerElementType()->isStructTy())
                    continue;
                if(gepInst->getResultElementType()->getPointerElementType()->getStructName() == "struct.proto_ops")
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
                                auto ops = getStructValue(globalVar);
                                if(ops == nullptr && Ctx->GlobalStructMap.count(ops->getName().str()))
                                    ops = getStructValue(Ctx->GlobalStructMap[ops->getName().str()]);
                                if(ops)
                                {
                                    ConstantStruct* opsStruct = dyn_cast<ConstantStruct>(ops);
                                    *protoOps = opsStruct;
                                    return;
                                }
                            }                         
                        }
                    }
                }
            }
        }
    }
}


// handle netlink
Function* NetworkInterfaceExtractorPass::getSendmsgHandler(Value* cfgOp)
{
    vector<Value*> toFindList;
    toFindList.push_back(cfgOp);
    for(User* user:cfgOp->users())
    {
        if(BitCastInst* bitcastInst = dyn_cast<BitCastInst>(user))
        {
            toFindList.push_back(user);
        }
    }
    for(Value* v:toFindList)
    {
        for(User* user: v->users())
        {
            if(CallInst* callInst = dyn_cast<CallInst>(user))
            {
                if(callInst->isIndirectCall())
                    continue;
                if(callInst->getCalledFunction()->getName().startswith("llvm.memcpy"))
                {
                    BitCastOperator* bitcastOperator = dyn_cast<BitCastOperator>(callInst->getArgOperand(1));
                    if(GlobalVariable* globalVar = dyn_cast<GlobalVariable>(bitcastOperator->getOperand(0)))
                    {
                        ConstantStruct* constantStruct = dyn_cast<ConstantStruct>(globalVar->getInitializer());
                        Value* val = constantStruct->getOperand(Ctx->StructFieldIdx["netlink_kernel_cfg"]["input"]);
                        if(Function* targetFunc = dyn_cast<Function>(val))
                        {
                            if(targetFunc->isDeclaration() || targetFunc->getInstructionCount() == 0)
                            {
                                targetFunc = getFunctionFromModules(targetFunc->getName());
                            }
                            outs() << "target function: " << targetFunc->getName() << "\n";
                            for(inst_iterator iter = inst_begin(targetFunc); iter != inst_end(targetFunc); iter++)
                            {
                                Instruction* I = &*iter;
                                if(CallInst* callInst = dyn_cast<CallInst>(I))
                                {
                                    if(callInst->isIndirectCall() || callInst->isInlineAsm())
                                        continue;
    
                                    outs() << callInst->getCalledFunction()->getName() << "\n";
                                    if(callInst->getCalledFunction()->getName() == "netlink_rcv_skb")
                                    {
                                        targetFunc = dyn_cast<Function>(callInst->getArgOperand(1));
                                        return targetFunc;
                                    }
                                }
                            }
                            return targetFunc;
                        }
                    }
                }
            }
        }
    }
    return nullptr;
}

// handle rtnetlink
vector<tuple<unsigned, unsigned, Function*, Function*>> NetworkInterfaceExtractorPass::getRtnetlinkHandlers()
{
    vector<tuple<unsigned, unsigned, Function*, Function*>> res;
    for(auto item:Ctx->Modules)
    {
        Module* M = item.first;
        for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
        {
            Function* F = &*mi;
            if(F->hasName())
            {
                if(F->getName().str() == "rtnl_register")
                {
                    for(User* user:F->users())
                    {
                        if(CallInst* callInst = dyn_cast<CallInst>(user))
                        {
                           Value* op1 = callInst->getArgOperand(0);
                           Value* op2 = callInst->getArgOperand(1);
                           ConstantInt* constantInt1 = dyn_cast<ConstantInt>(op1);
                           ConstantInt* constantInt2 = dyn_cast<ConstantInt>(op2);
                           if(constantInt1 && constantInt2)
                           {
                               Value* op3 = callInst->getArgOperand(2);
                               Value* op4 = callInst->getArgOperand(3);
                               Function* doitFunc = dyn_cast<Function>(op3);
                               Function* dumpitFunc = dyn_cast<Function>(op4);
                               if(op3->getValueID() != Value::ConstantPointerNullVal && !doitFunc)
                               {
                                   outs() << "not found doit func in function: " << callInst->getFunction()->getName() << "\n";
                               }
                               if(op4->getValueID() != Value::ConstantPointerNullVal && !dumpitFunc)
                               {
                                   outs() << "not found dumpit func in function: " << callInst->getFunction()->getName() << "\n";
                               }
                               res.push_back(tuple<unsigned, unsigned, Function*, Function*>(constantInt1->getZExtValue(), constantInt2->getZExtValue(), doitFunc, dumpitFunc));
                           }
                           else
                           {
                               outs() << "not constant value in function: " << callInst->getFunction()->getName() << "\n";
                           }
                        }
                    }
                }
            }
        }
    }
    return res;
}

// handle generic netlink
vector<tuple<unsigned, Function*, Function*>> NetworkInterfaceExtractorPass::getGenlFamilyHandlers(ConstantStruct* familyStruct)
{
    vector<tuple<unsigned, Function*, Function*>> res;
    Value* ops = familyStruct->getOperand(Ctx->StructFieldIdx["genl_family"]["ops"] - 1);
    if(GEPOperator* gepOp = dyn_cast<GEPOperator>(ops))
    {
        ops = gepOp->getOperand(0);
    }
    outs() << "genl family ops: " << *ops << "\n";
    GlobalVariable* opsVar = dyn_cast<GlobalVariable>(ops);
    if(opsVar == nullptr)
    {
        if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(ops))
        {
            opsVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
        }
    }
    if(opsVar != nullptr)
    {
        if(!opsVar->hasInitializer() && Ctx->GlobalStructMap.count(opsVar->getName().str()))
            opsVar = dyn_cast<GlobalVariable>(Ctx->GlobalStructMap[opsVar->getName().str()]);
    }
    if(opsVar != nullptr)
    {
        ConstantArray* opsArray = dyn_cast<ConstantArray>(opsVar->getInitializer());
        for(int i =  0; i < opsArray->getNumOperands(); i++)
        {
            ConstantStruct* opStruct = dyn_cast<ConstantStruct>(opsArray->getOperand(i));
            auto cmd = opStruct->getOperand(Ctx->StructFieldIdx["genl_ops"]["cmd"]);
            auto cmdVal = getIntValue(cmd);
            Function* doitFunc = dyn_cast<Function>(opStruct->getOperand(Ctx->StructFieldIdx["genl_ops"]["doit"]));
            Function* dumpitFunc = dyn_cast<Function>(opStruct->getOperand(Ctx->StructFieldIdx["genl_ops"]["dumpit"]));
            res.push_back(tuple<unsigned, Function*, Function*>(cmdVal, doitFunc, dumpitFunc));
        }
    }
    if (Ctx->StructFieldIdx["genl_family"]["small_ops"] - 1 < 0 || Ctx->StructFieldIdx["genl_family"]["small_ops"] - 1 >= familyStruct->getNumOperands()) {
        return res;
    }

    Value* smallOps = familyStruct->getOperand(Ctx->StructFieldIdx["genl_family"]["small_ops"] - 1);
    if(GEPOperator* gepOp = dyn_cast<GEPOperator>(smallOps))
    {
        smallOps = gepOp->getOperand(0);
    }
    outs() << "genl family small ops: " << *smallOps << "\n";
    GlobalVariable* smallOpsVar = dyn_cast<GlobalVariable>(smallOps);
    if(smallOpsVar == nullptr)
    {
        if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(smallOps))
        {
            smallOpsVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
        }
    }
    if(smallOpsVar != nullptr)
    {
        if(!smallOpsVar->hasInitializer() && Ctx->GlobalStructMap.count(smallOpsVar->getName().str()))
            smallOpsVar = dyn_cast<GlobalVariable>(Ctx->GlobalStructMap[smallOpsVar->getName().str()]);
    }
    if(smallOpsVar != nullptr)
    {
        ConstantArray* smallOpsArray = dyn_cast<ConstantArray>(smallOpsVar->getInitializer());
        for(int i =  0; i < smallOpsArray->getNumOperands(); i++)
        {
            ConstantStruct* smallOpStruct = dyn_cast<ConstantStruct>(smallOpsArray->getOperand(i));
            auto cmd = smallOpStruct->getOperand(Ctx->StructFieldIdx["genl_small_ops"]["cmd"]);
            auto cmdVal = getIntValue(cmd);
            Function* doitFunc = dyn_cast<Function>(smallOpStruct->getOperand(Ctx->StructFieldIdx["genl_small_ops"]["doit"]));
            Function* dumpitFunc = dyn_cast<Function>(smallOpStruct->getOperand(Ctx->StructFieldIdx["genl_small_ops"]["dumpit"]));
            res.push_back(tuple<unsigned, Function*, Function*>(cmdVal, doitFunc, dumpitFunc));
        }
    }
    return res;
}

GenlFamilyInfo* NetworkInterfaceExtractorPass::getGenlFamilyInfo(ConstantStruct* familyStruct)
{
    GenlFamilyInfo* genlFamilyInfo = new GenlFamilyInfo();
    genlFamilyInfo->familyStruct = familyStruct;
    string familyName = getDeviceString(familyStruct->getOperand(Ctx->StructFieldIdx["genl_family"]["name"]));
    genlFamilyInfo->familyName = familyName;
    Value* policyOp = familyStruct->getOperand(Ctx->StructFieldIdx["genl_family"]["policy"]);
    GlobalVariable* policyVar = dyn_cast<GlobalVariable>(policyOp);
    if(policyVar == nullptr)
    {
        if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(policyOp))
        {
            policyVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
        }
    }
    if(policyVar != nullptr)
    {
        auto policyStructVal = getStructValue(policyVar);
        if(policyStructVal == nullptr && Ctx->GlobalStructMap.count(policyStructVal->getName().str()))
            policyStructVal = getStructValue(Ctx->GlobalStructMap[policyStructVal->getName().str()]);
        if(policyStructVal != nullptr)
        {
            ConstantStruct* policyStruct = dyn_cast<ConstantStruct>(policyStructVal);
            genlFamilyInfo->policy = policyStruct;
        }
        else
        {
            genlFamilyInfo->policy = nullptr;
        }
    }
    else
    {
        genlFamilyInfo->policy = nullptr; 
    }

    genlFamilyInfo->GenlHandlers = getGenlFamilyHandlers(familyStruct);
    return genlFamilyInfo;

}

vector<GenlFamilyInfo*> NetworkInterfaceExtractorPass::getGenlInfos()
{
    vector<GenlFamilyInfo*> res;
    for(auto item:Ctx->Modules)
    {
        Module* M = item.first;
        for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
        {
            Function* F = &*mi;
            if(F->hasName())
            {
                if(F->getName().str() == "genl_register_family")
                {
                    for(User* user:F->users())
                    {
                        if(CallInst* callInst = dyn_cast<CallInst>(user))
                        {
                            Value* FamilyOp = callInst->getArgOperand(0);
                            GlobalVariable* globalVar = dyn_cast<GlobalVariable>(FamilyOp);
                            if(globalVar == nullptr)
                            {
                                if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(FamilyOp))
                                {
                                    globalVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
                                }
                            }
                            if(globalVar != nullptr)
                            {
                                auto familyStructVal = getStructValue(globalVar);
                                if(familyStructVal == nullptr && Ctx->GlobalStructMap.count(familyStructVal->getName().str()))
                                    familyStructVal = getStructValue(Ctx->GlobalStructMap[familyStructVal->getName().str()]);
                                if(familyStructVal)
                                {
                                    ConstantStruct* familyStruct = dyn_cast<ConstantStruct>(familyStructVal);
                                    res.push_back(getGenlFamilyInfo(familyStruct));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return res;
}

// handle xfrm
vector<tuple<unsigned, Function*, Function*>> NetworkInterfaceExtractorPass::getXfrmHandlers()
{
    outs() << "processing xfrm\n";
    vector<tuple<unsigned, Function*, Function*>> res;
    Value* xfrmDispatch = Ctx->GlobalStructMap["xfrm_dispatch"];
    if(xfrmDispatch == nullptr)
    {
        for(auto item : Ctx->Modules)
        {
            Module* M = item.first;
            if (endsWith(M->getSourceFileName(), "net/xfrm/xfrm_user.c"))
            {
                for (auto gv = M->global_begin(); gv != M->global_end(); gv++) { 
                    GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
                    if (g == nullptr) {
                        continue;
                    }
                    outs() << "global name: " << g->getName() << "\n";
                    if (g->getName() == "xfrm_dispatch")
                    {
                        xfrmDispatch = g;
                    }
                }
            }
        }
    }
    GlobalVariable* globalVar = dyn_cast<GlobalVariable>(xfrmDispatch);
    if(globalVar == nullptr)
        return res;
    outs() << "get target global struct" << "\n";
    ConstantArray* xfrmDispathArray = dyn_cast<ConstantArray>(globalVar->getInitializer());
    if(xfrmDispathArray == nullptr)
        return res;
    outs() << "aaa\n";
    for(int i = 0; i < xfrmDispathArray->getNumOperands(); i++)
    {
        int type = i + XFRM_MSG_BASE;
        ConstantStruct* xfrmLinkStruct = dyn_cast<ConstantStruct>(xfrmDispathArray->getOperand(i));
        if(xfrmLinkStruct == nullptr)
            continue;
        Function* doitFunc = dyn_cast<Function>(xfrmLinkStruct->getOperand(Ctx->StructFieldIdx["xfrm_link"]["doit"]));
        Function* dumpitFunc = dyn_cast<Function>(xfrmLinkStruct->getOperand(Ctx->StructFieldIdx["xfrm_link"]["dumpit"]));
        res.push_back(tuple<unsigned, Function*, Function*>(type, doitFunc, dumpitFunc));

    }
    outs() << "bbb\n";
    return res;
}

// handle netfilter
map<unsigned, Function*> NetworkInterfaceExtractorPass::getNfSubsysHandlers(ConstantStruct* nfSubsysStruct)
{
    map<unsigned, Function*> res;
    Value* callbacks = nfSubsysStruct->getOperand(Ctx->StructFieldIdx["nfnetlink_subsystem"]["cb"]);
    if(GEPOperator* gepOp = dyn_cast<GEPOperator>(callbacks))
    {
        callbacks = gepOp->getOperand(0);
    }
    GlobalVariable* cbVar = dyn_cast<GlobalVariable>(callbacks);
    if(cbVar == nullptr)
    {
        if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(callbacks))
        {
            cbVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
        }
    }
    if(cbVar != nullptr)
    {
        if(!cbVar->hasInitializer() && Ctx->GlobalStructMap.count(cbVar->getName().str()))
            cbVar = dyn_cast<GlobalVariable>(Ctx->GlobalStructMap[cbVar->getName().str()]);
    }
    if(cbVar != nullptr)
    {
        ConstantArray* cbArray = dyn_cast<ConstantArray>(cbVar->getInitializer());
        for(int i = 0; i < cbArray->getNumOperands(); i++)
        {
            ConstantStruct* cbStruct = dyn_cast<ConstantStruct>(cbArray->getOperand(i));
            if(cbStruct == nullptr)
                continue;
            Function* handler = dyn_cast<Function>(cbStruct->getOperand(Ctx->StructFieldIdx["nfnl_callback"]["call"]));
            res[i] = handler;
        }
    }
    return res;
}

NfSubsysInfo* NetworkInterfaceExtractorPass::getNfSubsysInfo(ConstantStruct* subsysStruct)
{
    NfSubsysInfo* nfsubsysInfo = new NfSubsysInfo();
    nfsubsysInfo->subsysStruct = subsysStruct;
    string subsysName = getDeviceString(subsysStruct->getOperand(Ctx->StructFieldIdx["nfnetlink_subsystem"]["name"]));
    nfsubsysInfo->subsysName = subsysName;
    ConstantInt* subsysID = dyn_cast<ConstantInt>(subsysStruct->getOperand(Ctx->StructFieldIdx["nfnetlink_subsystem"]["subsys_id"]));
    nfsubsysInfo->subsysID = subsysID->getZExtValue();
    nfsubsysInfo->NetfilterHandlers = getNfSubsysHandlers(subsysStruct);
    return nfsubsysInfo;
}

// handle rdma
vector<tuple<unsigned, unsigned, Function*, Function*>> NetworkInterfaceExtractorPass::getRDMAHandlers()
{
    vector<tuple<unsigned, unsigned, Function*, Function*>> res;
    for(auto item:Ctx->Modules)
    {
        Module* M = item.first;
        for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
        {
            Function* F = &*mi;
            if(F->hasName())
            {
                if(F->getName().str() == "rdma_nl_register")
                {
                    for(User* user:F->users())
                    {
                        if(CallInst* callInst = dyn_cast<CallInst>(user))
                        {
                            Value* op1 = callInst->getArgOperand(0);
                            ConstantInt* constantInt1 = dyn_cast<ConstantInt>(op1);
                            if(constantInt1)
                            {
                                Value* callbacks = callInst->getArgOperand(1);
                                if(GEPOperator* gepOp = dyn_cast<GEPOperator>(callbacks))
                                {
                                    callbacks = gepOp->getOperand(0);
                                }
                                GlobalVariable* cb_table = dyn_cast<GlobalVariable>(callbacks);
                                if(cb_table == nullptr)
                                {
                                    if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(callbacks))
                                    {
                                        cb_table = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
                                    }
                                }
                                if(cb_table != nullptr)
                                {
                                    if(!cb_table->hasInitializer() && Ctx->GlobalStructMap.count(cb_table->getName().str()))
                                        cb_table = dyn_cast<GlobalVariable>(Ctx->GlobalStructMap[cb_table->getName().str()]);
                                }
                                if(cb_table != nullptr)
                                {
                                    ConstantArray* cbArray = dyn_cast<ConstantArray>(cb_table->getInitializer());
                                    for(int i = 0; i < cbArray->getNumOperands(); i++)
                                    {
                                        ConstantStruct* cbStruct = dyn_cast<ConstantStruct>(cbArray->getOperand(i));
                                        if(cbStruct == nullptr)
                                            continue;
                                        Function* doit = dyn_cast<Function>(cbStruct->getOperand(Ctx->StructFieldIdx["rdma_nl_cbs"]["doit"]));
                                        Function* dump = dyn_cast<Function>(cbStruct->getOperand(Ctx->StructFieldIdx["rdma_nl_cbs"]["dump"]));
                                        res.push_back(tuple<unsigned, unsigned, Function*, Function*>(constantInt1->getZExtValue(), i, doit, dump));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return res;
}

vector<NfSubsysInfo*> NetworkInterfaceExtractorPass::getNfInfos()
{
    vector<NfSubsysInfo*> res;
    for(auto item:Ctx->Modules)
    {
        Module* M = item.first;
        for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
        {
            Function* F = &*mi;
            if(F->hasName())
            {
                if(F->getName().str() == "nfnetlink_subsys_register")
                {
                    for(User* user:F->users())
                    {
                        if(CallInst* callInst = dyn_cast<CallInst>(user))
                        {
                            Value* subSysOp = callInst->getArgOperand(0);
                            GlobalVariable* globalVar = dyn_cast<GlobalVariable>(subSysOp);
                            if(globalVar == nullptr)
                            {
                                if(BitCastOperator* bitcastOp = dyn_cast<BitCastOperator>(subSysOp))
                                {
                                    globalVar = dyn_cast<GlobalVariable>(bitcastOp->getOperand(0));
                                }
                            }
                            if(globalVar != nullptr)
                            {
                                auto subSysStructVal = getStructValue(globalVar);
                                if(subSysStructVal == nullptr && Ctx->GlobalStructMap.count(subSysStructVal->getName().str()))
                                    subSysStructVal = getStructValue(Ctx->GlobalStructMap[subSysStructVal->getName().str()]);
                                if(subSysStructVal)
                                {
                                    ConstantStruct* subsysStruct = dyn_cast<ConstantStruct>(subSysStructVal);
                                    res.push_back(getNfSubsysInfo(subsysStruct));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return res;
}


void NetworkInterfaceExtractorPass::ProcessNetlinkKernelCreate(NetworkInterfaceInfoItem* infoItem, CallInst* callInst)
{
    outs() << "in process netlink kernel create\n";
    NetlinkInfoItem* netlinkInfoItem = new NetlinkInfoItem(infoItem);
    Value* op = callInst->getArgOperand(1);
    if(ConstantInt* constantInt = dyn_cast<ConstantInt>(op))
    {
        int protocol = constantInt->getZExtValue();
        netlinkInfoItem->protocol = protocol;
    }
    Value* cfgOp = callInst->getArgOperand(3);
    outs() << "call netlink_kernel_create in function: " << callInst->getFunction()->getName() << "\n";
    Function* targetFunc = getSendmsgHandler(cfgOp);
    netlinkInfoItem->SendmsgHandler = targetFunc;
    if(netlinkInfoItem->protocol == NETLINK_ROUTE)
    {
        RtnetlinkInfoItem* rtnetlinkInfoItem = new RtnetlinkInfoItem(netlinkInfoItem);
        rtnetlinkInfoItem->RtnetlinkHandlers = getRtnetlinkHandlers();
        Ctx->SubsystemInfo.push_back(rtnetlinkInfoItem);
        return;
    }
    else if(netlinkInfoItem->protocol == NETLINK_GENERIC)
    {
        GenlInfoItem* genlInfoItem = new GenlInfoItem(netlinkInfoItem);
        genlInfoItem->GenlInfos = getGenlInfos();
        Ctx->SubsystemInfo.push_back(genlInfoItem);
        return;
    }
    else if(netlinkInfoItem->protocol == NETLINK_XFRM)
    {
        XfrmInfoItem* xfrmInfoItem = new XfrmInfoItem(netlinkInfoItem);
        xfrmInfoItem->XfrmHandlers = getXfrmHandlers();
        Ctx->SubsystemInfo.push_back(xfrmInfoItem);
        return;
    }
    else if(netlinkInfoItem->protocol == NETLINK_NETFILTER)
    {
        NetfilterInfoItem* netfilterInfoItem = new NetfilterInfoItem(netlinkInfoItem);
        netfilterInfoItem->NfSubsysInfos = getNfInfos();
        Ctx->SubsystemInfo.push_back(netfilterInfoItem);
        return;
    }
    else if(netlinkInfoItem->protocol == NETLINK_RDMA)
    {
        RDMAInfoItem* rdmaInfoItem = new RDMAInfoItem(netlinkInfoItem);
        rdmaInfoItem->RDMAHandlers = getRDMAHandlers();
        Ctx->SubsystemInfo.push_back(rdmaInfoItem);
        return;
    }
    Ctx->SubsystemInfo.push_back(netlinkInfoItem);
}

void NetworkInterfaceExtractorPass::ProcessNetlink(NetworkInterfaceInfoItem* infoItem)
{
    outs() << "in process netlink\n";
    for(auto item:Ctx->Modules)
    {
        Module* M = item.first;
        for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
        {
            Function* F = &*mi;
            if(F->hasName())
            {
                if(F->getName().str() == "__netlink_kernel_create")
                {
                    for(User* user:F->users())
                    {
                        if(CallInst* callInst = dyn_cast<CallInst>(user))
                        {
                            ProcessNetlinkKernelCreate(infoItem, callInst);
                        }
                    }
                }
            }
        }
    }
}

void NetworkInterfaceExtractorPass::ProcessInetProtosw(ConstantStruct* protosw) {
    auto constantStruct = protosw;
    auto type = constantStruct->getOperand(Ctx->StructFieldIdx["inet_protosw"]["type"]);
    auto typeVal = getIntValue(type);
    auto protocol = constantStruct->getOperand(Ctx->StructFieldIdx["inet_protosw"]["protocol"]);
    auto protocolVal = getIntValue(protocol);
    outs() << "type: " << typeVal << ", protocol: " << protocolVal << "\n";
    auto proto = constantStruct->getOperand(Ctx->StructFieldIdx["inet_protosw"]["prot"]);
    auto protoVal = getStructValue(proto);
    if (!protoVal && Ctx->GlobalStructMap.count(proto->getName().str())) {
        protoVal = getStructValue(Ctx->GlobalStructMap[proto->getName().str()]);
    }   
    
    if (protoVal) {
        outs() << "protoVal: " << *protoVal << "\n";
        auto protoStruct = dyn_cast<ConstantStruct>(protoVal);
        auto name = protoStruct->getOperand(Ctx->StructFieldIdx["proto"]["name"]);
        auto nameStr = getDeviceString(name);
        outs() << "name: " << nameStr << "\n";
        auto ops = constantStruct->getOperand(Ctx->StructFieldIdx["inet_protosw"]["ops"]);
        outs() << "ops:" << *ops << "\n";
        auto opsVal = getStructValue(ops);
        if (!opsVal && Ctx->GlobalStructMap.count(ops->getName().str())) {
            opsVal = getStructValue(Ctx->GlobalStructMap[ops->getName().str()]);
        }
        if (opsVal) {
            outs() << "opsVal: " << *opsVal << "\n";
            auto opsStruct = dyn_cast<ConstantStruct>(opsVal);
            NetworkInterfaceInfoItem* infoItem = nullptr;
            for (auto item: Ctx->SubsystemInfo) {
                if (item->ItemType == NETWORK && item->name == nameStr) {
                    infoItem = static_cast<NetworkInterfaceInfoItem*>(item);
                    break;
                }
            }
            if (infoItem == nullptr) {
                infoItem = new NetworkInterfaceInfoItem();
                Ctx->SubsystemInfo.push_back(infoItem);
                infoItem->name = nameStr;
                infoItem->family = getIntValue(opsStruct->getOperand(Ctx->StructFieldIdx["proto_ops"]["family"]));
                infoItem->ItemType = NETWORK;
            }
            infoItem->type = typeVal;
            infoItem->protocol = protocolVal;
            for (auto syscall: networkSyscalls) {
                auto handler = opsStruct->getOperand(Ctx->StructFieldIdx["proto_ops"][syscall]);
                if (auto handlerFunc = dyn_cast<Function>(handler)) {
                    infoItem->SyscallHandler[syscall] = handlerFunc;
                    generateNetworkSyscallsArgMapProtoOps(handlerFunc, syscall);
                }
            }
            for (auto syscall: networkSyscalls) {
                auto handler = protoStruct->getOperand(Ctx->StructFieldIdx["proto"][syscall]);
                if (auto handlerFunc = dyn_cast<Function>(handler)) {
                    infoItem->SyscallHandler[syscall] = handlerFunc;
                    generateNetworkSyscallsArgMapProto(handlerFunc, syscall);
                }
            }
        }
    }
}


void NetworkInterfaceExtractorPass::ProcessInetRegisterProtosw(CallInst* callInst) {
    outs() << "[*] new inet call: " << *callInst << "\n";
    // struct inet_protosw *
    auto protoswPtr = callInst->getArgOperand(0);
    outs() << "protoswPtr: " << *protoswPtr << "\n";
    if (auto protoswGV = dyn_cast<GlobalVariable>(protoswPtr)) {
        if (protoswGV->hasInitializer()) {
            auto initializer = protoswGV->getInitializer();
            auto constantStruct = dyn_cast<ConstantStruct>(initializer);
            if (constantStruct) {
                ProcessInetProtosw(constantStruct);
            }
        }
    } else {
        // inetsw array

    }
}

set<Value*>* NetworkInterfaceExtractorPass::GetAliasOfStructType(Value* value, string structName) {
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

Value* NetworkInterfaceExtractorPass::ExtractPtrAssignment(Value* ptrValue) {
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

void NetworkInterfaceExtractorPass::ProcessProtoRegister(CallInst* callInst) {
    outs() << "[*] new proto call: " << *callInst << "\n";

    // find corresponding sock register in the same function
    auto func = callInst->getFunction();
    bool found = false;
    bool isBt = false;
    CallInst* socketRegisterCall = nullptr;
    for (auto& BB: *func) {
        for (auto& I: BB) {
            if (auto candidateCall =  dyn_cast<CallInst>(&I)) {
                if (candidateCall->getCalledFunction() && candidateCall->getCalledFunction()->getName() == "sock_register") {
                    socketRegisterCall = candidateCall;
                    outs() << "sock_register: " << *candidateCall << "\n";
                    found = true;
            } else if (candidateCall->getCalledFunction() && candidateCall->getCalledFunction()->getName() == "bt_sock_register") {
                    socketRegisterCall = candidateCall;
                    outs() << "bt_sock_register: " << *candidateCall << "\n";
                    found = true;
                    isBt = true;
                }
            }
     }
    }
    if (!found) {
        outs() << "sock_register not found\n";
        // try to find sock register in the context
        return;
    } 

    // extract struct proto & struct net_proto_family
    auto protoStruct = getStructValue(callInst->getArgOperand(0));
    if (!protoStruct && Ctx->GlobalStructMap.count(callInst->getArgOperand(0)->getName().str())) {
        protoStruct = getStructValue(Ctx->GlobalStructMap[callInst->getArgOperand(0)->getName().str()]);
    }
    auto familyStruct = getStructValue(socketRegisterCall->getArgOperand(0));
    if (!familyStruct && Ctx->GlobalStructMap.count(socketRegisterCall->getArgOperand(0)->getName().str())) {
        familyStruct = getStructValue(Ctx->GlobalStructMap[socketRegisterCall->getArgOperand(0)->getName().str()]);
    }
    if (isBt) {
        familyStruct = getStructValue(socketRegisterCall->getArgOperand(1));
        if (!familyStruct && Ctx->GlobalStructMap.count(socketRegisterCall->getArgOperand(1)->getName().str())) {
            familyStruct = getStructValue(Ctx->GlobalStructMap[socketRegisterCall->getArgOperand(1)->getName().str()]);
        }
    }
    if (protoStruct) {
        outs() << "protoStruct: " << *protoStruct << "\n";
    } 
    if (familyStruct) {
        outs() << "familyStruct: " << *familyStruct << "\n";
    } 
    if (!protoStruct || !familyStruct) {
        return;
    }
    NetworkInterfaceInfoItem *infoItem = new NetworkInterfaceInfoItem();
    infoItem->ItemType = NETWORK;
    // process proto struct
    auto protoConstantStruct = dyn_cast<ConstantStruct>(protoStruct);
    auto name = protoConstantStruct->getOperand(Ctx->StructFieldIdx["proto"]["name"]);
    auto nameStr = getDeviceString(name);
    outs() << "name: " << nameStr << "\n";

    for (auto syscall: networkSyscalls) {
        auto handler = protoConstantStruct->getOperand(Ctx->StructFieldIdx["proto"][syscall]);
        if (auto handlerFunc = dyn_cast<Function>(handler)) {
            infoItem->SyscallHandler[syscall] = handlerFunc;
            generateNetworkSyscallsArgMapProto(handlerFunc, syscall);
        }
    }

    // process family struct
    auto familyConstantStruct = dyn_cast<ConstantStruct>(familyStruct);
    auto family = familyConstantStruct->getOperand(0);
    auto familyVal = getIntValue(family);
    outs() << "family: " << familyVal << "\n";
    auto create = familyConstantStruct->getOperand(1);
    if (auto createFunction = dyn_cast<Function>(create)) {
        // process .create function
        outs() << "createFunction: " << createFunction->getName() << "\n";
        infoItem->CreateFunction = createFunction;

        auto sockArg = createFunction->getArg(1);
        
        // extract proto ops in create function
        auto sockAliasSet = GetAliasOfStructType(sockArg, "struct.socket");

        set<Value*> opsStructCandidate;
    
        for (auto sockAlias: *sockAliasSet) {
            outs() << "sock alias: " << *sockAlias << "\n";
            for (auto user : sockAlias->users()) { 
                if (auto gepInst = dyn_cast<GetElementPtrInst>(user)) {
                    outs() << "\tGEP: " << *gepInst << "\n";
                    auto offsetVal = gepInst->getOperand(2);
                    auto offsetInt = dyn_cast<ConstantInt>(offsetVal);
                    // get access of the fops field
                    if (offsetInt && offsetInt->getZExtValue() == Ctx->StructFieldIdx["socket"]["ops"]) {
                        auto opsVal = ExtractPtrAssignment(gepInst);
                        if (opsVal) {
                            if (auto selectInst = dyn_cast<SelectInst>(opsVal)) {
                                auto trueOp = selectInst->getTrueValue();
                                auto falseOp = selectInst->getFalseValue();
                                opsStructCandidate.insert(trueOp);
                                opsStructCandidate.insert(falseOp);
                            } else {
                                opsStructCandidate.insert(opsVal);
                                
                            }
                        }
                    } 
                    
                }
            }
        }

        infoItem->family = familyVal;
        infoItem->name = nameStr;

        if(isBt){
            if(Constant* protocolV=dyn_cast<Constant>(socketRegisterCall->getArgOperand(0))){
                infoItem->protocol=getIntValue(protocolV);
                OP << "BT!!get protocol" << infoItem->protocol << "\n";
            }
        }
        if (opsStructCandidate.size() > 0) {
            for (auto opsVal: opsStructCandidate) {
                auto opsStruct = getStructValue(opsVal);
                if (!opsStruct && Ctx->GlobalStructMap.count(opsVal->getName().str())) {
                    opsStruct = getStructValue(Ctx->GlobalStructMap[opsVal->getName().str()]);
                }
                if (opsStruct && opsStruct->getType()->getStructName() == "struct.proto_ops") {
                    auto newInfoItem = new NetworkInterfaceInfoItem();
                    newInfoItem->name = string(infoItem->name);
                    newInfoItem->ItemType = NETWORK;
                    newInfoItem->family = infoItem->family;
                    newInfoItem->protocol=infoItem->protocol;
                    for (auto syscall: networkSyscalls) {
                        auto opsConstStruct = dyn_cast<ConstantStruct>(opsStruct);
                        if (opsConstStruct) {
                            auto handler = opsConstStruct->getOperand(Ctx->StructFieldIdx["proto_ops"][syscall]);
                            if (auto handlerFunc = dyn_cast<Function>(handler)) {
                                newInfoItem->SyscallHandler[syscall] = handlerFunc;
                                generateNetworkSyscallsArgMapProtoOps(handlerFunc, syscall);
                            }
                        }
                    }

                    // FIXME: ad-hoc solution for socket type
                    auto structName = opsVal->getName().str();
                    outs() << "struct name:" << structName << "\n";
                    if (ProtoOpsTypeMap.count(structName)) {
                        newInfoItem->type = ProtoOpsTypeMap[structName];
                        newInfoItem->protocol = ProtoOpsProtocolMap[structName];
                    }

                    bool exist = false;
                    for (auto item : Ctx->SubsystemInfo) {
                        if (item->ItemType == NETWORK) {
                            auto networkInfoItem = static_cast<NetworkInterfaceInfoItem*>(item);
                            if (networkInfoItem->family == newInfoItem->family && newInfoItem->type == networkInfoItem->type && newInfoItem->family != 0 && newInfoItem->type != 0) {
                                exist = true;
                            }
                        }
                    }
                    if (!exist) {
                        Ctx->SubsystemInfo.push_back(newInfoItem);
                    }
                }
            }

            // finished
            return;
        }

    }

    outs() << "DEBUG!!!" << "\n";
    if(infoItem->family == AF_NETLINK)
    {
        set<Function*> visited = set<Function*>();
        ConstantStruct* protoOps = nullptr;
        getProtoOpsFromCreateFunction(infoItem->CreateFunction, &protoOps, visited, 0);
        if(protoOps)
        {
            outs() << "proto_ops: " << *protoOps << "\n";
            for (auto syscall: networkSyscalls) {
                outs() << "syscall: " << syscall << "\n";
                outs() << "op idx: " << Ctx->StructFieldIdx["proto_ops"][syscall] << "\n";
                for(auto item:Ctx->StructFieldIdx["proto_ops"])
                {
                    outs() << "name: " << item.first << " idx: " << item.second << "\n";
                }
                auto handler = protoOps->getOperand(Ctx->StructFieldIdx["proto_ops"][syscall]);
                outs() << "handler: " << *handler << "\n";
                if (auto handlerFunc = dyn_cast<Function>(handler)) {
                    infoItem->SyscallHandler[syscall] = handlerFunc;
                    generateNetworkSyscallsArgMapProtoOps(handlerFunc, syscall);
                }
            }
            
            for (auto handler : infoItem->SyscallHandler) {
                auto syscallName = handler.first;
                auto handlerName = handler.second->getName();
                outs() << "|---|--- " << syscallName << ": " << handlerName << "\n";
            }
        }
        infoItem->type = 2;
        ProcessNetlink(infoItem);
        infoItem->type = 3;
        ProcessNetlink(infoItem);
        return;
    }

    Ctx->SubsystemInfo.push_back(infoItem);
}


bool NetworkInterfaceExtractorPass::doInitialization(Module * M) {
    if (DFA == nullptr) {
        DFA = new DataFlowAnalysis(Ctx);
    }
    return false;
}

bool NetworkInterfaceExtractorPass::doModulePass(Module * M) {
    for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
        Function& func = *mi;
        if (func.hasName()) {
            if (func.getName().str() == "proto_register") {
                // possible interface init
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessProtoRegister(callInst);
                    } 
                }
            }
        }
    }
    return false;
} 

bool NetworkInterfaceExtractorPass::doFinalization(Module * M) {



    for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
        // some special cases
        Function& func = *mi;
        if (func.hasName()) {
            // inet
            if (func.getName().str() == "inet_register_protosw" || func.getName().str() == "inet6_register_protosw") {
                for (auto user : func.users()) {
                    if (auto callInst = dyn_cast<CallInst>(user)) {
                        ProcessInetRegisterProtosw(callInst);
                    } 
                }
            } 
        }
    }
    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) { 
        GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
        if (g == nullptr) {
            continue;
        }
        if (g->getName() == "inetsw_array") {
            auto inetswArray = dyn_cast<ConstantArray>(g->getInitializer());
            for (int i = 0; i < inetswArray->getNumOperands(); i++) {
                auto inetsw = dyn_cast<ConstantStruct>(inetswArray->getOperand(i));
                ProcessInetProtosw(inetsw);
            }
        }
    }
    return false;
}