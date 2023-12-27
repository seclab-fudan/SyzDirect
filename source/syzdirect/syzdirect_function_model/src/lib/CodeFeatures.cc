#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Support/FileSystem/UniqueID.h"
#include "llvm/Support/FileSystem.h"
#include <memory>
#include <iostream>
#include <map>
#include <vector>
#include <fstream>
#include <set>
#include <sstream>
#include <algorithm>
#include <string>
#include <set>
#include <queue>
#include <stack>

#include "CodeFeatures.h"
#include "Utils.h"

#include "ArgMapParser.h"

using namespace llvm;

#define MAX_ITER_COUNT 3

TraceOperand::TraceOperand(/* args */)
{
}

TraceOperand::TraceOperand(Value* value, CastOpPath castOps)
{
    this->value = value;
    this->castOps = castOps;
}

TraceOperand::TraceOperand(Value* value, CastOpPath castOps, OperandPath ops)
{
    this->value = value;
    this->castOps = castOps;
    this->opPath = ops;
    this->andOps = OperandPath();
}

TraceOperand::TraceOperand(Value* value, CastOpPath castOps, OperandPath ops, OperandPath andOps)
{
    this->value = value;
    this->castOps = castOps;
    this->opPath = ops;
    this->andOps = andOps;
}

void TraceOperand::updateCastOps(CastOp* op)
{
    this->castOps.push_back(op);
}

void TraceOperand::updateOps(Value* v)
{
    this->opPath.push_back(v);
} 

void TraceOperand::updateAndOps(Value* v)
{
    this->andOps.push_back(v);
}

TraceOperand::~TraceOperand()
{
}

CMDConst::CMDConst(/* args */)
{
    this->location = -1;
}

CMDConst::CMDConst(CMDConst& cmdConst)
{
    this->value = cmdConst.value;
    this->castOps = cmdConst.castOps;
    this->targetBlock = cmdConst.targetBlock;
    this->opPath = cmdConst.opPath;
    this->location = -1;
}

CMDConst::CMDConst(CMDConst* cmdConst)
{
    this->value = cmdConst->value;
    this->castOps = cmdConst->castOps;
    this->targetBlock = cmdConst->targetBlock;
    this->opPath = cmdConst->opPath;
    this->location = -1;
}

CMDConst::CMDConst(ConstantInt* constantInt, CastOpPath castOps, BasicBlock* bb, BasicBlock* switchBlock, string cmpStr = "")
{
    this->value = constantInt;
    this->castOps = castOps;
    this->targetBlock = bb;
    this->switchBlock = switchBlock;
    this->location = -1;
    this->compareString = cmpStr;
}

CMDConst::CMDConst(ConstantInt* constantInt, CastOpPath castOps, BasicBlock* bb, BasicBlock* switchBlock, OperandPath ops, string cmpStr = "")
{
    this->value = constantInt;
    this->castOps = castOps;
    this->targetBlock = bb;
    this->opPath = ops;
    this->switchBlock = switchBlock;
    this->location = -1;
    this->compareString = cmpStr;
}

CMDConst::CMDConst(ConstantInt* constantInt, CastOpPath castOps, BasicBlock* bb, BasicBlock* switchBlock, OperandPath ops, OperandPath andOps, string cmpStr = "")
{
    this->value = constantInt;
    this->castOps = castOps;
    this->targetBlock = bb;
    this->opPath = ops;
    this->andOps = andOps;
    this->switchBlock = switchBlock;
    this->location = -1;
    this->compareString = cmpStr;
}

void CMDConst::updateCastOps(CastOpPath castOps, bool front)
{
    if(front)
    {
        this->castOps.insert(this->castOps.begin(), castOps.begin(), castOps.end());
    }
    else{
        this->castOps.insert(this->castOps.end(), castOps.begin(), castOps.end());
    }
}

void CMDConst::updateOps(OperandPath ops, bool front)
{
    if(front)
    {
        this->opPath.insert(this->opPath.begin(), ops.begin(), ops.end());
    }
    else{
        this->opPath.insert(this->opPath.end(), ops.begin(), ops.end());
    }
}

bool CMDConst::isEnoughPaths()
{
    std::vector<BasicBlock*> path;
    std::set<BasicBlock*> blocks;
    unsigned times = 0;
    return getPathFromBlockToRet(this->targetBlock, this->paths, times, blocks, path);
}

bool CMDConst::isRetFixedNegative()
{
    if(this->paths.size() == 0)
    {
        isEnoughPaths();
    }
    vector<vector<BasicBlock*>> newPaths;
    for(vector<BasicBlock*> path:this->paths)
    {
        vector<BasicBlock*> newPath;
        newPath.push_back(this->switchBlock);
        for(BasicBlock* bb : path)
        {
            newPath.push_back(bb);
        }
        newPaths.push_back(newPath);
    }
    
    return isRetFixedNegativeInPaths(newPaths);
}

bool CMDConst::isRequestModuleInKernel()
{
    if(this->paths.size() == 0)
    {
        isEnoughPaths();
    }
    if(this->calledFunctions.size() == 0)
    {
        this->calledFunctions = getCalledFunctionInPathsInter(this->paths, true, 10);
    }
    pair<CallInst*, Function*> p = getCallInstByCalledFunctionName(this->calledFunctions, "__request_module");
    if((p.second) != nullptr)
    {
        CallInst* callInst = p.first;
        return isRequestModuleInKernelTest1(callInst);
    }
    return true;
}

bool CMDConst::shouldFuzzing()
{
    if(this->paths.size() == 0 && isEnoughPaths())
        return true;
    if(isRetFixedNegative())
        return false;
    if(!isRequestModuleInKernel())
        return false;
    return true;
}

CMDConst::~CMDConst()
{
}

BBConstraint::BBConstraint()
{    
}

BBConstraint::BBConstraint(unsigned argIdx, CMDConst* cmdConst, BasicBlock* bb)
{
    this->argIdx = argIdx;
    this->cmdConstSet = {cmdConst};
    this->bb = bb;
}

void BBConstraint::insertCMDConst(CMDConst* cmdConst)
{
    this->cmdConstSet.insert(cmdConst);
}

set<string> funcBlackList = {"__get_free_pages", "__kmalloc", "__kmalloc_track_caller",
                            "kfree", "kmem_cache_free", "__kmalloc_node_track_caller",
                            "kmem_cache_alloc", "__kmalloc_node"};

bool inBlackList(Function* F)
{
    return funcBlackList.count(F->getName().str());
}

void handleDrmIoctl(map<string, Module*> &ModuleMap, raw_fd_ostream& signatureFile) {
    for (auto item: ModuleMap) {
        if (item.first.find("drm_ioctl") == string::npos) {
        continue;
        }
        auto M = item.second;
        auto gv = M->getGlobalVariable("drm_ioctls", true);
        if (!gv) {
            outs() << "drm_ioctls not in module\n";
            break;
        } 
        map<unsigned, Function*> res;
        if (!gv->hasInitializer()) {
            outs() <<"drm_ioctls not has initializer\n";
            break;
        }
        ConstantStruct* drm_ioctls_struct = dyn_cast<ConstantStruct>(gv->getInitializer());
        if (drm_ioctls_struct == nullptr) {
            outs() << "drm_ioctls not struct\n";
            break;
        }
        for(int i = 0; i < drm_ioctls_struct->getNumOperands(); i++) {
            auto item = drm_ioctls_struct->getOperand(i);
            if (auto constantStruct = dyn_cast<ConstantStruct>(item)) {
                auto func_arg = constantStruct->getOperand(2);
                if (func_arg && isa<Function>(func_arg)) {
                auto constantInt = dyn_cast<ConstantInt>(constantStruct->getOperand(0));
                if (constantInt == nullptr) {
                    outs() << "constant cmd is null!!\n";
                } else {
                    uint32_t cmd = uint32_t(constantInt->getZExtValue() & 0xFFFFFFFF); 
                    res[cmd] = dyn_cast<Function>(func_arg);
                }
                } else {
                    outs() << "no function arg\n";
                }
            }
        }
        
        vector<string> signatures;
        for(auto item:res)
        {
            string s = "ioctl|D[/dev/dri/controlD#]|C[" + to_string(item.first) + "]|C[]";
            s += " ";
            s += "0";
            s += " ";
            if (item.second->getName() != "")
                s += item.second->getName().str();
            else
                s += "none";
            signatures.push_back(s);
        }
        for(string s : signatures)
        {
            signatureFile << s << "\n";
        }
        break;
    }
}

void handleSpecial(ModuleList &MList, raw_fd_ostream& signatureFile) {
    vector<string> signatures;
    for (auto Mitem: MList) {
        Module *M = Mitem.first;
        for (auto fit = M->begin(), fend = M->end(); fit != fend; fit++) {
            Function *F = &*fit;
            // fuse notify
            if (F && F->getName() == "fuse_dev_do_write") {
                for (auto bit = F->begin(), bend = F->end(); bit != bend; bit++) {
                    BasicBlock *BB = &*bit;
                    for (auto iit = BB->begin(), iend = BB->end(); iit != iend; iit++) {
                        Instruction *I = &*iit;
                        if (SwitchInst *switchInst = dyn_cast<SwitchInst>(I)) {
                            for (auto c: switchInst->cases()) {
                                uint64_t caseNum = c.getCaseValue()->getZExtValue();
                                BasicBlock *caseBlock = c.getCaseSuccessor();
                                int caseBlockIndex = getBasicBlockIndex(caseBlock);
                                string s = "write|D[/dev/fuse]|C[" + to_string(caseNum) + "]|C[]|C[]" + " " + "1" + " " + "fuse_dev_do_write" + " " + to_string(caseBlockIndex) + " " + "fuse_dev_do_write";
                                signatures.push_back(s);
                            }
                        }
                    }
                }
            } 
            // vt ioctl
            else if (F && F->getName() == "vt_ioctl") {
                Argument *cmdArg = F->getArg(1);
                for (User *U: cmdArg->users()) {
                    Instruction *Inst = dyn_cast<Instruction>(U);
                    if (!Inst) continue;
                    SwitchInst *switchInst = dyn_cast<SwitchInst>(Inst);
                    if (!switchInst) continue;
                    for (auto c: switchInst->cases()) {
                        uint64_t caseNum = c.getCaseValue()->getZExtValue();
                        BasicBlock *caseBlock = c.getCaseSuccessor();
                        int caseBlockIndex = getBasicBlockIndex(caseBlock);
                        string s = "ioctl|D[/dev/tty]|C[" + to_string(caseNum) + "]|C[]" + " " + "1" + " " + "vt_ioctl" + " " + to_string(caseBlockIndex) + " " + "vt_ioctl";
                        signatures.push_back(s);
                    }
                }
            }
        }
    }
    for (string s: signatures) {
        signatureFile << s << "\n";
    }
    return;
}

// void getPathFromBlockToRet(BasicBlock* BB, std::vector<std::vector<BasicBlock*>>& paths, std::vector<BasicBlock*> path)
bool getPathFromBlockToRet(BasicBlock* BB, std::vector<std::vector<BasicBlock*>>& paths, unsigned& times, std::set<BasicBlock*>& blocks, 
                            std::vector<BasicBlock*> path, unsigned max_path_num, unsigned max_bb_num, unsigned total_block)
{
    if(times >= 100000)
    {
        return true;
    }
    if(std::find(path.begin(), path.end(), BB) != path.end())
    {
        times += 1;
        return false;
    }
    path.push_back(BB);
    if(blocks.count(BB) == 0)
        blocks.insert(BB);
    if(blocks.size() >= total_block)
    {
        return true;
    }
    if(path.size() >= max_bb_num)
    {
        return true;
    }
    if(succ_empty(BB))
    {
        paths.push_back(path);
        times += 1;
        if(paths.size() >= max_path_num)
        {
            return true;
        }
        else
            return false;
    }
    for (BasicBlock* bb : successors(BB))
    {
        if(getPathFromBlockToRet(bb, paths, times, blocks, path))
            return true;
    }
    return false;
}

void output_paths(std::vector<std::vector<BasicBlock*>>& paths)
{
    int num = 0;
    for(std::vector<BasicBlock*> path: paths)
    {
        outs() << "path" << num << "\n";
        num ++;
        for(BasicBlock* BB : path)
        {
            outs() << "block:" << BB->getName() << "\n";
            outs() << *BB << "\n";
        }
        BasicBlock* endBB = path[path.size() - 1];
        bool res;
    }
}

vector<pair<CallInst*, Function*>> getCalledFunctionInBlock(BasicBlock* BB)
{

    vector<pair<CallInst*, Function*>> calledFunctions;
    for(BasicBlock::iterator iter = BB->begin(); iter != BB->end(); iter++)
    {
        Instruction *instr = &(*iter);
        if(instr->getOpcode() == Instruction::Call)
        {
            CallInst *callinstr = dyn_cast<CallInst>(instr);
            Function *callee = callinstr->getCalledFunction();
            if(callee == nullptr)
            {
                callee = dyn_cast<Function>(callinstr->getCalledOperand()->stripPointerCasts());
            }
            if(callee != nullptr)
            {
                if(callee->isIntrinsic())
                    continue;
                // calledFunctions
                calledFunctions.push_back(make_pair(callinstr, callee));
            }
        }
        
    }
    return calledFunctions;
}

vector<pair<CallInst*, Function*>> getCalledFunctionInPaths(vector<vector<BasicBlock*>>& paths)
{
    set<BasicBlock*> visited;
    vector<pair<CallInst*, Function*>> res;
    for(vector<BasicBlock*> path:paths)
    {
        for(BasicBlock* bb:path)
        {
            if(visited.count(bb))
                continue;
            visited.insert(bb);
            for(pair<CallInst*, Function*> p:getCalledFunctionInBlock(bb))
            {
                bool flag = false;
                for(pair<CallInst*, Function*> r : res)
                {
                    if(r.second == p.second)
                    {
                        flag = true;
                        break;
                    }

                }
                if(flag)
                    continue;
                res.push_back(p);
            }
        }
    }
    return res;
}

bool functionInPaths(vector<vector<BasicBlock*>>& paths, string funcName)
{
    vector<pair<CallInst*, Function*>> calledFunctions = getCalledFunctionInPaths(paths);
    for(pair<CallInst*, Function*> p:calledFunctions) 
    {
        if((p.second)->getName().str() == funcName)
            return true;
    }
    return false;
}

pair<CallInst*, Function*> getCallInstByCalledFunctionName(vector<pair<CallInst*, Function*>> res, string funcName)
{
    for(pair<CallInst*, Function*> p:res) 
    {
        if((p.second)->getName().str() == funcName)
            return p;
    }
    return make_pair(nullptr, nullptr);
}

// void getCalledFuncitonInter(Function* func, vector<Function*>& calledFunction, unsigned depth, bool ignoreIndirectCall, unsigned maxDepth)
void getCalledFuncitonInter(Function* func, vector<pair<CallInst*, Function*>>& calledFunction, unsigned depth, bool ignoreIndirectCall, unsigned maxDepth)
{
    if(depth > maxDepth)
        return;
    for(inst_iterator iter = inst_begin(func); iter != inst_end(func); iter++)
    {
        Instruction* I = &*iter;
        if(I->getOpcode() == Instruction::Call)
        {
            CallInst* callInst = dyn_cast<CallInst>(I);
            if(ignoreIndirectCall)
            {
                if(callInst->isIndirectCall())
                    continue;
                if(GlobalCtx.Callees[callInst].size() > 1)
                {
                    outs() << "direct call not one target call!!!" << "\n";
                    outs() << "call instruction: " << *callInst << "\n";
                    outs() << "in function: " << callInst->getFunction()->getName() << "\n";
                }
            }
            
            for(Function* callee : GlobalCtx.Callees[callInst])
            {
                if(callee->isIntrinsic())
                    continue;
                bool flag = false;
                for(pair<CallInst*, Function*> r : calledFunction)
                {
                    if(r.second == callee)
                    {
                        flag = true;
                        break;
                    }

                }
                if(flag)
                    continue;

                calledFunction.push_back(make_pair(callInst, callee));
                getCalledFuncitonInter(func, calledFunction, depth+1, ignoreIndirectCall, maxDepth);
            }
        }
    }
}
GlobalVariable* getGlobalVariable(Value* toFind)
{
    queue<Value*> q;
    q.push(toFind);
    while(!q.empty())
    {
        Value* v = q.front();
        if(!v->hasOneUse())
            return nullptr;
        q.pop();
        if(Instruction* I = dyn_cast<Instruction>(v))
        {
            if(I->getOpcode() == Instruction::Load)
            {
                LoadInst* loadInst = dyn_cast<LoadInst>(I);
                Value* var = loadInst->getOperand(0);
                if(GlobalVariable* globalVar = dyn_cast<GlobalVariable>(var))
                    return globalVar;
                else
                    return nullptr;
            }
            else
            {
                for(Use& U:I->operands())
                {
                    q.push(U.get());
                }
            }
        }
    }
    return nullptr;
}

Function* getSetGlobalVariableFunc(GlobalVariable* globalVar)
{
    for(User* user: globalVar->users())
    {
        if(StoreInst* storeInst = dyn_cast<StoreInst>(user))
        {
            return storeInst->getFunction();
        }
    }
    return nullptr;
}

bool isRequestModuleInKernelTest1(CallInst* requestModuleCall)
{
    BasicBlock* bb = requestModuleCall->getParent();
    if(bb->getFirstNonPHIOrDbgOrLifetime() != requestModuleCall)
        return true;
    if(pred_size(bb) != 1)
        return true;
    BasicBlock* pred = *pred_begin(bb);
    Instruction* I = pred->getTerminator();
    if(I->getOpcode() != Instruction::Br)
        return true;
    BranchInst* brInst = dyn_cast<BranchInst>(I);
    if(brInst->isUnconditional())
        return true;
    Value* cond = brInst->getCondition();
    if(ICmpInst* icmpInst = dyn_cast<ICmpInst>(cond))
    {
        if(!icmpInst->isEquality())
            return true;
        
        Value* op0 = icmpInst->getOperand(0);
        Value* op1 = icmpInst->getOperand(1);
        if(!op0->getType()->isPointerTy())
            return true;
        Value* toFind;
        if(ConstantPointerNull* nul = dyn_cast<ConstantPointerNull>(op0))
        {
            toFind = op1;
        }
        else if(ConstantPointerNull* nul = dyn_cast<ConstantPointerNull>(op1))
        {
            toFind = op0;
        }
        else{
            return true;
        }
        GlobalVariable* globalVar = getGlobalVariable(toFind);
        if(globalVar == nullptr)
            return true;
        Function* F = getSetGlobalVariableFunc(globalVar);
        if(F == nullptr)
            return true;
        if(GlobalCtx.Callers[F].size() == 0)
            return false;
        else
            return true;
    }
    return true;
}

unsigned getNotIntrinsicFuncNum(FuncSet s)
{
    unsigned res;
    for(Function* func:s)
    {
        if(func->isIntrinsic())
            continue;
        res ++;
    }
    return res;
}


vector<pair<CallInst*, Function*>> getCalledFunctionInPathsInter(vector<vector<BasicBlock*>>& paths, bool ignoreIndirectCall, unsigned maxDepth)
{
    set<BasicBlock*> visited;
    vector<pair<CallInst*, Function*>> res;
    for(vector<BasicBlock*> path:paths)
    {
        for(BasicBlock* bb:path)
        {
            if(visited.count(bb))
                continue;
            visited.insert(bb);
            for(BasicBlock::iterator iter = bb->begin(); iter != bb->end(); iter++)
            {
                Instruction *instr = &(*iter);
                if(instr->getOpcode() == Instruction::Call)
                {
                    CallInst *callinstr = dyn_cast<CallInst>(instr);
                    if(ignoreIndirectCall)
                    {
                        if(callinstr->isIndirectCall())
                            continue;
                        if(GlobalCtx.Callees[callinstr].size() > 1)
                        {
                            outs() << "direct call not one target call!!!" << "\n";
                            outs() << "call instruction: " << *callinstr << "\n";
                            outs() << "in function: " << callinstr->getFunction()->getName() << "\n";
                        }
                    }
                    for(Function* callee: GlobalCtx.Callees[callinstr])
                    {
                        if(callee->isIntrinsic())
                            continue;
                        bool flag = false;
                        for(pair<CallInst*, Function*> r : res)
                        {
                            if(r.second == callee)
                            {
                                flag = true;
                                break;
                            }

                        }
                        if(flag)
                            continue;
                        res.push_back(make_pair(callinstr, callee));
                        getCalledFuncitonInter(callee, res, 1, ignoreIndirectCall, maxDepth);
                    }
                }
                
            }
        }
    }
    return res;
}


std::vector<CMDConst*> getTargetBlockByArg(Function* F, unsigned argIdx, std::map<Function*, set<unsigned>>& visited, int depth)
{
    Argument* arg = F->getArg(argIdx);
    bool traceAnd = false;
    if(arg->getType()->isIntegerTy())
    {
        traceAnd = true;
    }
    std::vector<CMDConst*> res;
    if(GlobalCtx.FoundFunctionCache.count(F) > 0)
    {
        return res;
    }

    if(visited.find(F) == visited.end())
    {
        visited[F] = set<unsigned>();
    }
    else
    {
        if(visited[F].count(argIdx) > 0)
        {
            return res;
        }
    }
    visited[F].insert(argIdx);

    TraceOperand* traceOp = new TraceOperand(arg, CastOpPath(), OperandPath());
    traceOp->updateOps(arg);

    std::set<Value*> visitedNode;

    std::queue<TraceOperand*> q;
    q.push(traceOp);
    visitedNode.insert(arg);
    while(!q.empty())
    {
        TraceOperand* traceOp = q.front();
        Value* toFind = traceOp->value;
        q.pop();
        for (User *U: toFind->users())
        {
            if(visitedNode.count(U))
            {
                CallInst* tmp = dyn_cast<CallInst>(U);
                if(!tmp)
                    continue;
            }
            visitedNode.insert(U);
            if(Instruction* I = dyn_cast<Instruction>(U))
            {
                if (I->getOpcode() == Instruction::Switch)
                {
                    SwitchInst* swInstr = dyn_cast<SwitchInst>(I);
                    for(SwitchInst::CaseIt iter = swInstr->case_begin(); iter != swInstr->case_end(); iter++)
                    {
                        if(iter == swInstr->case_default())
                            continue;
                        ConstantInt* value = iter->getCaseValue();
                        BasicBlock* bb = iter->getCaseSuccessor();
                        CMDConst* cmdConst = new CMDConst(value, traceOp->castOps, bb, swInstr->getParent(), traceOp->opPath, traceOp->andOps);
                        cmdConst->opPath.push_back(U);
                        res.push_back(cmdConst);
                    }
                }
                else if (I->getOpcode() == Instruction::ICmp) {
                    auto icmpInst = dyn_cast<ICmpInst>(I);
                    if(icmpInst->getPredicate() == CmpInst::ICMP_EQ)
                    {
                        ConstantInt* value = dyn_cast<ConstantInt>(icmpInst->getOperand(1));
                        if (value != nullptr) {
                            BasicBlock* bb = nullptr;
                            for (auto cmpResUser: icmpInst->users()) {
                                if (auto brInst = dyn_cast<BranchInst>(cmpResUser)) {
                                    bb = brInst->getSuccessor(0);
                                    break;
                                }
                            }
                            CMDConst* cmdConst = new CMDConst(value, traceOp->castOps, bb, icmpInst->getParent(), traceOp->opPath, traceOp->andOps);
                            cmdConst->opPath.push_back(U);
                            res.push_back(cmdConst);
                        }
                    }

                }
                else if(I->getOpcode() == Instruction::Call)
                {
                    CallInst* callInst = dyn_cast<CallInst>(I);
                    if(traceAnd && traceOp->andOps.size() > 0)
                        continue;
                    int targetIdx = -1;
                    for(int i = 0; i < callInst->getNumArgOperands(); i++)
                    {
                        if(callInst->getArgOperand(i) == toFind)
                        {
                            targetIdx = i;
                            break;
                        }
                    }
                    if(targetIdx < 0)
                    {
                        // toFind is a function pointer and is called by an indirect call
                        continue;
                    }
                    auto calledFunc = callInst->getCalledFunction();
                    if (calledFunc && calledFunc->hasName() && calledFunc->getName() == "strcmp") {
                    } else {
                        for(Function* callee :GlobalCtx.Callees[callInst])
                        {
                            if(callee->isVarArg())
                                continue;
                            if(callee->isIntrinsic() || (callee->getInstructionCount() == 0))
                                continue;
                            if(inBlackList(callee))
                                continue;
                            
                            if(GlobalCtx.FoundFunctionCache.count(callee) > 0)
                            {
                                continue;
                            }
                            if (depth < MAX_ITER_COUNT) {
                                std::vector<CMDConst*> calleeTargetBlocks = getTargetBlockByArg(callee, targetIdx, visited, depth+1);
                                for(CMDConst* cmdConst: calleeTargetBlocks)
                                {
                                    cmdConst->updateCastOps(traceOp->castOps, true);
                                    cmdConst->opPath.insert(cmdConst->opPath.begin(), callee);
                                    cmdConst->opPath.insert(cmdConst->opPath.begin(), callInst);
                                    cmdConst->updateOps(traceOp->opPath, true);
                                }
                                res.insert(res.end(), calleeTargetBlocks.begin(), calleeTargetBlocks.end());
                            }
                        }
                    }
                }
                else if(CastInst* castInst = dyn_cast<CastInst>(I))
                {
                    Instruction::CastOps op = castInst->getOpcode();
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    CastOp* castOp = new CastOp();
                    castOp->op = op;
                    castOp->srcTy = castInst->getSrcTy();
                    castOp->dstTy = castInst->getDestTy();
                    newOp->updateCastOps(castOp);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::GetElementPtr)
                {
                    
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::And)
                {
                    if(traceAnd)
                    {
                        TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                        newOp->updateAndOps(U);
                        newOp->updateOps(U);
                        q.push(newOp);
                    }
                }
                else if(I->getOpcode() == Instruction::Shl)
                {
                    if(F->getName() == "io_uring_mmap")
                    {
                        TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                        newOp->updateOps(U);
                        q.push(newOp);   
                    }
                }
                else if(I->getOpcode() == Instruction::Load)
                {
                    
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::PHI)
                {
                    
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::Store)
                {
                    StoreInst* storeInst = dyn_cast<StoreInst>(I);
                    if(storeInst->getValueOperand() == toFind)
                    {
                        Value* v = storeInst->getPointerOperand();
                        
                        TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                        newOp->updateOps(U);
                        q.push(newOp);
                    }
                }
                // TODO: handle icmp instructions
            }
        }
        delete traceOp;
    }
    return res;
}

vector<CMDConst*> getValueInSwitchCase(Function* F)
{
    vector<CMDConst*> res;
    for(inst_iterator iter = inst_begin(F); iter != inst_end(F); iter++)
    {
        Instruction* I = &*iter;
        if(I->getOpcode() == Instruction::Switch)
        {
            SwitchInst* switchInst = dyn_cast<SwitchInst>(I);
            for(SwitchInst::CaseIt iter = switchInst->case_begin(); iter != switchInst->case_end(); iter++)
            {
                if(iter == switchInst->case_default())
                    continue;
                ConstantInt* value = iter->getCaseValue();
                BasicBlock* bb = iter->getCaseSuccessor();
                CMDConst* cmdConst = new CMDConst();
                cmdConst->value = value;
                cmdConst->targetBlock = bb;
                cmdConst->switchBlock = switchInst->getParent();
                res.push_back(cmdConst);
                
            }
        }
    }
    return res;
}


std::vector<CMDConst*> getTargetBlockByValuePtr(Function* F, Value* value, std::map<Function*, set<unsigned>>& visited)
{
    Value* arg = value;
    std::vector<CMDConst*> res;
    if(GlobalCtx.FoundFunctionCache.count(F) > 0)
    {
        return res;
    }
    
    TraceOperand* traceOp = new TraceOperand(arg, CastOpPath(), OperandPath());
    traceOp->updateOps(arg);

    std::set<Value*> visitedNode;

    std::queue<TraceOperand*> q;
    q.push(traceOp);
    visitedNode.insert(arg);
    while(!q.empty())
    {
        TraceOperand* traceOp = q.front();
        Value* toFind = traceOp->value;
        q.pop();
        for (User *U: toFind->users())
        {
            if(visitedNode.count(U))
            {
                CallInst* tmp = dyn_cast<CallInst>(U);
                if(!tmp)
                    continue;
            }
            visitedNode.insert(U);
            if(Instruction* I = dyn_cast<Instruction>(U))
            {
                if (I->getOpcode() == Instruction::Switch)
                {
                    SwitchInst* swInstr = dyn_cast<SwitchInst>(I);
                    for(SwitchInst::CaseIt iter = swInstr->case_begin(); iter != swInstr->case_end(); iter++)
                    {
                        if(iter == swInstr->case_default())
                            continue;
                        ConstantInt* value = iter->getCaseValue();
                        BasicBlock* bb = iter->getCaseSuccessor();
                        CMDConst* cmdConst = new CMDConst(value, traceOp->castOps, bb, swInstr->getParent(), traceOp->opPath);
                        cmdConst->opPath.push_back(U);
                        res.push_back(cmdConst);
                    }
                }
                else if (I->getOpcode() == Instruction::ICmp) {
                    auto icmpInst = dyn_cast<ICmpInst>(I);
                    if(icmpInst->getPredicate() == CmpInst::ICMP_EQ)
                    {
                        ConstantInt* value = dyn_cast<ConstantInt>(icmpInst->getOperand(1));
                        if (value != nullptr) {
                            BasicBlock* bb = nullptr;
                            CMDConst* cmdConst = new CMDConst(value, traceOp->castOps, bb, icmpInst->getParent(), traceOp->opPath);
                            cmdConst->opPath.push_back(U);
                            res.push_back(cmdConst);
                        }
                                            }

                }
                else if(I->getOpcode() == Instruction::Call)
                {
                    CallInst* callInst = dyn_cast<CallInst>(I);
                    int targetIdx = -1;
                    for(int i = 0; i < callInst->getNumArgOperands(); i++)
                    {
                        if(callInst->getArgOperand(i) == toFind)
                        {
                            targetIdx = i;
                            break;
                        }
                    }
                    if(targetIdx < 0)
                    {
                        // toFind is a function pointer and is called by an indirect call
                                                continue;
                    }
                    auto calledFunc = callInst->getCalledFunction();
                    if (calledFunc && calledFunc->hasName() && calledFunc->getName() == "strcmp") {
                        ;
                    } else {
                        for(Function* callee :GlobalCtx.Callees[callInst])
                        {
                                                        if(callee->isVarArg())
                                continue;
                            if(callee->isIntrinsic() || (callee->getInstructionCount() == 0))
                                continue;
                            if(inBlackList(callee))
                                continue;
                            if(GlobalCtx.FoundFunctionCache.count(callee) > 0)
                            {
                                continue;
                            }
                            std::vector<CMDConst*> calleeTargetBlocks = getTargetBlockByArg(callee, targetIdx, visited, 0);
                            for(CMDConst* cmdConst: calleeTargetBlocks)
                            {
                                cmdConst->updateCastOps(traceOp->castOps, true);
                                cmdConst->opPath.insert(cmdConst->opPath.begin(), callee);
                                cmdConst->opPath.insert(cmdConst->opPath.begin(), callInst);
                                cmdConst->updateOps(traceOp->opPath, true);
                            }
                            res.insert(res.end(), calleeTargetBlocks.begin(), calleeTargetBlocks.end());
                        }
                    }
                }
                else if(CastInst* castInst = dyn_cast<CastInst>(I))
                {
                    Instruction::CastOps op = castInst->getOpcode();
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath);
                    CastOp* castOp = new CastOp();
                    castOp->op = op;
                    castOp->srcTy = castInst->getSrcTy();
                    castOp->dstTy = castInst->getDestTy();
                    newOp->updateCastOps(castOp);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::GetElementPtr)
                {
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::Load)
                {
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::PHI)
                {
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::Store)
                {
                    StoreInst* storeInst = dyn_cast<StoreInst>(I);
                    if(storeInst->getValueOperand() == toFind)
                    {
                        Value* v = storeInst->getPointerOperand();
                        TraceOperand* newOp = new TraceOperand(v, traceOp->castOps, traceOp->opPath);
                        newOp->updateOps(U);
                        q.push(newOp);
                    }
                }
            }
        }
        delete traceOp;
    }
    return res;
}

std::vector<CMDConst*> getTargetBlockByArg(Function* F, unsigned argIdx, std::map<Function*, set<unsigned>>& visited, map<BasicBlock*, CMDConst*> &bbConstraints, int depth)
{
    Argument* arg = F->getArg(argIdx);
    bool traceAnd = false;
    if(arg->getType()->isIntegerTy())
    {
        traceAnd = true;
    }
    std::vector<CMDConst*> res;
    if(GlobalCtx.FoundFunctionCache.count(F) > 0)
    {
        return res;
    }
    if(visited.find(F) == visited.end())
    {
        visited[F] = set<unsigned>();
    }
    else
    {
        if(visited[F].count(argIdx) > 0)
        {
            return res;
        }
    }
    visited[F].insert(argIdx);
    
    TraceOperand* traceOp = new TraceOperand(arg, CastOpPath(), OperandPath());
    traceOp->updateOps(arg);

    std::set<Value*> visitedNode;
    std::queue<TraceOperand*> q;
    q.push(traceOp);
    visitedNode.insert(arg);
    while(!q.empty())
    {
        TraceOperand* traceOp = q.front();
        Value* toFind = traceOp->value;
        q.pop();
        for (User *U: toFind->users())
        {
            if(visitedNode.count(U))
            {
                CallInst* tmp = dyn_cast<CallInst>(U);
                if(!tmp)
                    continue;
            }
            visitedNode.insert(U);
            if(Instruction* I = dyn_cast<Instruction>(U))
            {
                if (I->getOpcode() == Instruction::Switch)
                {
                    SwitchInst* swInstr = dyn_cast<SwitchInst>(I);
                    for(SwitchInst::CaseIt iter = swInstr->case_begin(); iter != swInstr->case_end(); iter++)
                    {
                        if(iter == swInstr->case_default())
                            continue;
                        ConstantInt* value = iter->getCaseValue();
                        BasicBlock* bb = iter->getCaseSuccessor();
                        CMDConst* cmdConst = new CMDConst(value, traceOp->castOps, bb, swInstr->getParent(), traceOp->opPath, traceOp->andOps);
                        cmdConst->opPath.push_back(U);
                        res.push_back(cmdConst);
                    }
                }
                else if (I->getOpcode() == Instruction::ICmp) {
                    auto icmpInst = dyn_cast<ICmpInst>(I);
                    if(icmpInst->getPredicate() == CmpInst::ICMP_EQ)
                    {
                        ConstantInt* value = dyn_cast<ConstantInt>(icmpInst->getOperand(1));
                        if (value != nullptr) {
                            BasicBlock* bb = nullptr;
                            CMDConst* cmdConst = new CMDConst(value, traceOp->castOps, bb, icmpInst->getParent(), traceOp->opPath, traceOp->andOps);
                            cmdConst->opPath.push_back(U);
                            res.push_back(cmdConst);
                        }
                    }

                }
                else if(I->getOpcode() == Instruction::Call)
                {
                    CallInst* callInst = dyn_cast<CallInst>(I);
                    if(traceAnd && traceOp->andOps.size() > 0)
                        continue;
                    int targetIdx = -1;
                    for(int i = 0; i < callInst->getNumArgOperands(); i++)
                    {
                        if(callInst->getArgOperand(i) == toFind)
                        {
                            targetIdx = i;
                            break;
                        }
                    }
                    if(targetIdx < 0)
                    {
                        continue;
                    }
                    auto calledFunc = callInst->getCalledFunction();
                    if (calledFunc && calledFunc->hasName() && calledFunc->getName() == "strcmp") {
                    } else {
                        for(Function* callee :GlobalCtx.Callees[callInst])
                        {
                            if(callee->isVarArg())
                                continue;
                            if(callee->isIntrinsic() || (callee->getInstructionCount() == 0))
                                continue;
                            if(GlobalCtx.FoundFunctionCache.count(callee) > 0)
                            {
                                continue;
                            }
                            if (depth < MAX_ITER_COUNT) {
                                std::vector<CMDConst*> calleeTargetBlocks = getTargetBlockByArg(callee, targetIdx, visited, bbConstraints, depth+1);
                                for(CMDConst* cmdConst: calleeTargetBlocks)
                                {
                                    cmdConst->updateCastOps(traceOp->castOps, true);
                                    cmdConst->opPath.insert(cmdConst->opPath.begin(), callee);
                                    cmdConst->opPath.insert(cmdConst->opPath.begin(), callInst);
                                    cmdConst->updateOps(traceOp->opPath, true);
                                }
                                res.insert(res.end(), calleeTargetBlocks.begin(), calleeTargetBlocks.end());
                            }
                        }
                    }
                }
                else if(CastInst* castInst = dyn_cast<CastInst>(I))
                {
                    Instruction::CastOps op = castInst->getOpcode();
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    CastOp* castOp = new CastOp();
                    castOp->op = op;
                    castOp->srcTy = castInst->getSrcTy();
                    castOp->dstTy = castInst->getDestTy();
                    newOp->updateCastOps(castOp);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::GetElementPtr)
                {
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::And)
                {
                    if(traceAnd)
                    {
                        TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                        newOp->updateAndOps(U);
                        newOp->updateOps(U);
                        q.push(newOp);
                    }
                }
                else if(I->getOpcode() == Instruction::Shl)
                {
                    if(F->getName() == "io_uring_mmap")
                    {
                        TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                        newOp->updateOps(U);
                        q.push(newOp);   
                    }
                }
                else if(I->getOpcode() == Instruction::Load)
                {
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::PHI)
                {
                    TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                    newOp->updateOps(U);
                    q.push(newOp);
                }
                else if(I->getOpcode() == Instruction::Store)
                {
                    StoreInst* storeInst = dyn_cast<StoreInst>(I);
                    if(storeInst->getValueOperand() == toFind)
                    {
                        Value* v = storeInst->getPointerOperand();
                        TraceOperand* newOp = new TraceOperand(U, traceOp->castOps, traceOp->opPath, traceOp->andOps);
                        newOp->updateOps(U);
                        q.push(newOp);
                    }
                }
            }
        }
        delete traceOp;
    }
    return res;
}

map<BasicBlock*, BBConstraint*> labeledBlocks;
set<Function*> relatedFuncs;
set<BasicBlock*> visitedLabeledBlocks;
map<Function*, set<vector<BBConstraint*>>> funcResCache;
map<BasicBlock*, set<vector<BBConstraint*>>> blockResCache;

map<BasicBlock*, BBConstraint*> labelBasicBlocks(map<unsigned, ConstBlockMap>& argConstMap)
{
    map<BasicBlock*, BBConstraint*> res;
    for(auto item: argConstMap)
    {
        unsigned argIdx = item.first;
        ConstBlockMap constBlockMap = item.second;
        for(CMDConst* cmdConst : constBlockMap)
        {
            BasicBlock* bb = cmdConst->targetBlock;
            if(bb != nullptr)
            {
                int num = 0;
                for(Value* v : cmdConst->opPath)
                {
                    if(Function* F = dyn_cast<Function>(v))
                    {
                        num ++;
                        if(num > 10)
                            break;
                        if(F->getName() == "netlink_sendmsg")
                            break;
                        relatedFuncs.insert(F);
                    }
                }
                if(res.count(bb))
                {
                    res[bb]->insertCMDConst(cmdConst);
                }
                else
                {
                    res[bb] = new BBConstraint(argIdx, cmdConst, bb);
                }
            }
        }
    }
    return res;
}

bool haveLabeledBlock(Function* func)
{
    for(auto iter = func->begin(); iter != func->end(); iter++)
    {
        BasicBlock* bb = &*iter;
        if(labeledBlocks.count(bb) > 0)
            return true;
    }
    return false;
}

void getConstraintsDFSInter(BasicBlock* BB, vector<BBConstraint*> path, vector<vector<BBConstraint*>>& paths, set<BasicBlock*> visited, set<Function*>& visitedFunc)
{
    if(visited.count(BB) > 0)
        return;
    visited.insert(BB);
    if(labeledBlocks.count(BB) > 0)
    {
        path.push_back(labeledBlocks[BB]);
        if(visitedLabeledBlocks.count(BB) == 0)
            visitedLabeledBlocks.insert(BB);
    }
    if(pred_empty(BB))
    {
        Function* F = BB->getParent();
        if(GlobalCtx.Callers[F].size() == 0)
        {
            if(path.size() > 0)
                paths.push_back(path);
        }
        else
        {
            bool haveCallerFunc = false;
            for(auto I : GlobalCtx.Callers[F])
            {
                Function* callerFunc = I->getParent()->getParent();
                if(visitedFunc.count(callerFunc))
                {
                    haveCallerFunc = true;
                    getConstraintsDFSInter(I->getParent(), path, paths, visited, visitedFunc);
                }
            }
            if(!haveCallerFunc)
            {
                if(path.size() > 0)
                    paths.push_back(path);
            }
        }
    }
    else
    {
        for(BasicBlock* bb:predecessors(BB))
        {
            if(visited.count(bb))
                continue;
            getConstraintsDFSInter(bb, path, paths, visited, visitedFunc);
        }
    }
}

bool haveNoPredecessor(BasicBlock* BB, set<BasicBlock*>& visited)
{
    if(pred_empty(BB))
        return true;
    for(BasicBlock* bb : predecessors(BB))
    {
        if(visited.count(bb) == 0)
            return false;
    }
    return true;
}


void getConstraintsDFSIntra(BasicBlock* BB, vector<BBConstraint*> path, set<vector<BBConstraint*>>& paths, set<BasicBlock*> visited, unsigned& times)
{
    if(times > 100000)
        return;
    times ++;
    if(visited.count(BB) > 0)
        return;
    visited.insert(BB);
    if(labeledBlocks.count(BB) > 0)
    {
        path.push_back(labeledBlocks[BB]);
        if(visitedLabeledBlocks.count(BB) == 0)
            visitedLabeledBlocks.insert(BB);
    }
    if(haveNoPredecessor(BB, visited))
    {
        if(pred_empty(BB))
        {
            if(path.size() > 0)
            {
                paths.insert(path);
            }
        }
        else
        {
            return;
        }
    }
    else
    {
        for(BasicBlock* bb:predecessors(BB))
        {
            if(visited.count(bb))
                continue;
            getConstraintsDFSIntra(bb, path, paths, visited, times);
        }
    }
}

vector<vector<BBConstraint*>> getConstraintsPathsFromLabeledBBInter(BasicBlock* BB, set<Function*> visitedFunc)
{
    set<BasicBlock*> visited = set<BasicBlock*>();
    vector<BBConstraint*> bbConstraintInPath = vector<BBConstraint*>();
    vector<vector<BBConstraint*>> res; 
    getConstraintsDFSInter(BB, bbConstraintInPath, res, visited, visitedFunc);
    return res;
} 


set<vector<BBConstraint*>> getConstraintsPathsFromLabeledBBIntra(BasicBlock* BB)
{
    outs() << "start DFS find path from " << BB->getName() << "\n";
    set<BasicBlock*> visited = set<BasicBlock*>();
    vector<BBConstraint*> bbConstraintInPath = vector<BBConstraint*>();
    // vector<vector<BBConstraint*>> res; 
    set<vector<BBConstraint*>> res;
    unsigned times = 0;
    getConstraintsDFSIntra(BB, bbConstraintInPath, res, visited, times);
    outs() << "finish DFS find path from " << BB->getName() << "\n";
    return res;
} 

map<unsigned, ConstBlockMap> processBBConstraintVec(vector<BBConstraint*> bbConstraints)
{
    map<unsigned, ConstBlockMap> res;
    for(BBConstraint* bbConstraint: bbConstraints)
    {
        unsigned argIdx = bbConstraint->argIdx;
        if(res.count(argIdx) == 0)
        {
            res[argIdx] = ConstBlockMap();
        }
        for(auto cmdConst : bbConstraint->cmdConstSet)
        {
            res[argIdx].push_back(cmdConst);
        }
    }
    return res;
}

vector<BasicBlock*> getStartBasicBlocksInFunc(Function* F)
{
    vector<BasicBlock*> res = vector<BasicBlock*>();
    for(auto iter = inst_begin(F); iter != inst_end(F); iter++)
    {
        Instruction* I = &*iter;
        if(I->getOpcode() == Instruction::Ret)
        {
            res.push_back(I->getParent());
        }
    }
    return res;
}

set<vector<BBConstraint*>> findLabeledBlockBFS(BasicBlock* startBB, set<BasicBlock*>& visited, set<Function*> visitedFunctions)
{
    set<vector<BBConstraint*>> res = set<vector<BBConstraint*>>();
    queue<BasicBlock*> q;
    q.push(startBB);

    while(!q.empty())
    {
        BasicBlock* bb = q.front();
        q.pop();
        if(visited.count(bb) > 0)
            continue;
        visited.insert(bb);
        vector<Function*> calledFunctions = vector<Function*>();
        for(auto iter = bb->begin(); iter != bb->end(); iter++)
        {
            Instruction* I = &*iter;
            if(CallInst* callInst = dyn_cast<CallInst>(I))
            {
                for(Function* F : GlobalCtx.Callees[callInst])
                {
                    if(relatedFuncs.count(F) && find(calledFunctions.begin(), calledFunctions.end(), F) == calledFunctions.end())
                        calledFunctions.push_back(F);
                }
            }
        }
        if(calledFunctions.size() == 0)
        {
            if(labeledBlocks.count(bb) > 0 && visitedLabeledBlocks.count(bb) == 0)
            {
                outs() << "get a labeled basic block\n";
                outs() << *bb << "\n";
                set<vector<BBConstraint*>> constraintsPaths = getConstraintsPathsFromLabeledBBIntra(bb);
                res.insert(constraintsPaths.begin(), constraintsPaths.end());
            }
        }
        else
        {
            outs() << "called function in this block\n";
            outs() << *bb << "\n";
            set<vector<BBConstraint*>> constraintsInFunc = getConstraintsPathsFromLabeledBBIntra(bb);
            for(Function* F: calledFunctions)
            {
                if(visitedFunctions.count(F) > 0)
                    continue;
                set<vector<BBConstraint*>> subFuncConstraints = getBBConstraintsPathsInFunc(F, visitedFunctions);
                if(subFuncConstraints.size() == 0)
                    continue;
                if(constraintsInFunc.size() == 0)
                {
                    res.insert(subFuncConstraints.begin(), subFuncConstraints.end());
                    continue;
                }
                outs() << "constraints in this function: " << constraintsInFunc.size() << "\n";
                outs() << "constraints in sub function: " << subFuncConstraints.size() << "\n";
                for(auto p1: constraintsInFunc)
                {
                    for(auto p2: subFuncConstraints)
                    {
                        vector<BBConstraint*> vec;
                        vec.insert(vec.end(), p2.begin(), p2.end());
                        vec.insert(vec.end(), p1.begin(), p1.end());
                        res.insert(vec);
                    }
                }
            }
        }
        for(BasicBlock* predBB: predecessors(bb))
        {
            if(visited.count(predBB))
                continue;
            q.push(predBB);
        }
    }
    outs() << "finish BFS\n";
    return res;
}

// vector<vector<BBConstraint*>> getBBConstraintsPathsInFunc(Function* F)
set<vector<BBConstraint*>> getBBConstraintsPathsInFunc(Function* F, set<Function*> visitedFunctions)
{
    outs() << "In function: " << F->getName() << "\n";
    if(visitedFunctions.count(F) > 0)
    {
        outs() << "visited function, return!!!\n";
        return set<vector<BBConstraint*>>();
    }
    visitedFunctions.insert(F);
    if(funcResCache.count(F))
    {
        outs() << "found in cache, return\n";
        return funcResCache[F];
    }
    vector<BasicBlock*> startBBs = getStartBasicBlocksInFunc(F);
    outs() << "total found " << startBBs.size() << " start blocks\n";
    set<vector<BBConstraint*>> res;
    set<BasicBlock*> visited = set<BasicBlock*>();
    for(BasicBlock* startBB : startBBs)
    {
        outs() << "BFS from block: " << startBB->getName() << "\n";
        set<vector<BBConstraint*>> constraints = findLabeledBlockBFS(startBB, visited, visitedFunctions);
        res.insert(constraints.begin(), constraints.end());
    }
    funcResCache[F] = res;
    outs() << "finish analyze function " << F->getName() << "\n";
    return res;
}

vector<map<unsigned, ConstBlockMap>> getConstraintsWrapper(Function* F, map<unsigned, ConstBlockMap>& argConstMap, raw_fd_ostream& outfile)
{
    outs() << "process argument const map\n";
    vector<map<unsigned, ConstBlockMap>> r;
    labeledBlocks.clear();
    relatedFuncs.clear();
    labeledBlocks = labelBasicBlocks(argConstMap);
    visitedLabeledBlocks.clear();
    set<Function*> visitedFunctions = set<Function*>();
    funcResCache.clear();
    outs() << "labeled all target blocks\n";
    if(labeledBlocks.size() == 0)
        return r;
    outfile << "func name: " << F->getName() << "; " << "arg num: " << F->arg_size() << "\n";
    set<vector<BBConstraint*>> constraintPaths = getBBConstraintsPathsInFunc(F, visitedFunctions);
    for(auto constraintPath : constraintPaths)
    {
        outfile << "==============\n";
        map<unsigned, ConstBlockMap> res = processBBConstraintVec(constraintPath);
        r.push_back(res);
        for(auto item : res)
        {
            unsigned argIdx = item.first;
            outfile << argIdx << ":";
            ConstBlockMap c = item.second;
            for(CMDConst* cmdConst : c)
            {
                outfile << " ";
                if(cmdConst->compareString != "")
                {
                    outfile << cmdConst->compareString;
                }
                else
                {
                    outfile << cmdConst->value->getZExtValue();
                }
            }
            outfile << "\n";
        }
    }
    return r;
}

void getDFSStartBBsBFSFromBasicBlock(BasicBlock* BB, vector<DFSStartBB*>& res, vector<CallInst*> callList, set<BasicBlock*>& visitedBlocks, set<Function*>& visitedFuncs)
{
    queue<BasicBlock*> q;
    q.push(BB);
    while(!q.empty())
    {
        BasicBlock* bb = q.front();
        q.pop();
        if(visitedBlocks.count(bb))
            continue;
        visitedBlocks.insert(bb);
        vector<pair<CallInst*, Function*>> calledFunctions = vector<pair<CallInst*, Function*>>();
        for(auto iter = bb->begin(); iter != bb->end(); iter++)
        {
            Instruction* I = &*iter;
            if(CallInst* callInst = dyn_cast<CallInst>(I))
            {
                for(Function* F : GlobalCtx.Callees[callInst])
                {
                    pair<CallInst*, Function*> calledFunction = pair<CallInst*, Function*>(callInst, F);
                    if(relatedFuncs.count(F) && visitedFuncs.count(F) == 0 && !inBlackList(F) &&
                        find(calledFunctions.begin(), calledFunctions.end(), calledFunction) == calledFunctions.end())
                        calledFunctions.push_back(calledFunction);
                }
            }
        }
        if(calledFunctions.size() > 0)
        {
            for(auto item : calledFunctions)
            {
                vector<CallInst*> newCallList = callList;
                newCallList.push_back(item.first);
                if(visitedFuncs.count(item.second))
                    continue;
                visitedFuncs.insert(item.second);
                vector<BasicBlock*> bfsStartBBs = getStartBasicBlocksInFunc(item.second);
                set<BasicBlock*> visited = set<BasicBlock*>();
                for(BasicBlock* bfsStartBB : bfsStartBBs)
                {
                    getDFSStartBBsBFSFromBasicBlock(bfsStartBB, res, newCallList, visited, visitedFuncs);
                }
            }
        }
        if(labeledBlocks.count(bb))
        {
            DFSStartBB* startBB = new DFSStartBB();
            startBB->BB = bb;
            startBB->callList = callList;
            res.push_back(startBB);
        }
        else
        {
            for(BasicBlock* predBB : predecessors(bb))
            {
                if(visitedBlocks.count(predBB))
                    continue;
                q.push(predBB);
            }
        }
    }
}

vector<DFSStartBB*> getDFSStartBBsBFSInFunc(Function* F)
{
    vector<BasicBlock*> startBBs = getStartBasicBlocksInFunc(F);
    vector<DFSStartBB*> res = vector<DFSStartBB*>();
    set<BasicBlock*> visitedBlocks = set<BasicBlock*>();
    set<Function*> visitedFuncs = set<Function*>();
    vector<CallInst*> callList = vector<CallInst*>();
    outs() << "start bb num: " << startBBs.size() << "\n";
    for(auto startBB : startBBs)
    {
        getDFSStartBBsBFSFromBasicBlock(startBB, res, callList, visitedBlocks, visitedFuncs);
    }
    return res;
}

void findLabeledBlocksFromFunc(Function* F, set<vector<BBConstraint*>>& res, set<Function*>& visitedFuncs)
{
    if(visitedFuncs.count(F))
        return;
    visitedFuncs.insert(F);
    for(auto iter = F->begin(); iter != F->end(); iter++)
    {
        BasicBlock* BB = &*iter;
        if(labeledBlocks.count(BB))
        {
            res.insert(vector<BBConstraint*>({labeledBlocks[BB]}));
        }
        else
        {
            for(auto i = BB->begin(); i != BB->end(); i++)
            {
                Instruction* I = &*i;
                if(CallInst* callInst = dyn_cast<CallInst>(I))
                {
                    for(Function* func : GlobalCtx.Callees[callInst])
                    {
                        if(visitedFuncs.count(func) == 0 && relatedFuncs.count(func))
                        {
                            findLabeledBlocksFromFunc(func, res, visitedFuncs);
                        }
                    }
                }
            }
        }
    }
}

set<vector<BBConstraint*>> getBBConstraintsInSubFunc(Function* F)
{
    set<vector<BBConstraint*>> constraintsInFunc;
    if(funcResCache.count(F))
    {
        constraintsInFunc = funcResCache[F];
    }
    else
    {
        set<Function*> visited;
        findLabeledBlocksFromFunc(F, constraintsInFunc, visited);
    }
    return constraintsInFunc;
}

map<BasicBlock*, set<vector<BBConstraint*>>> callBlockSubpaths;
map<BasicBlock*, set<vector<BBConstraint*>>> nopredBlokcSubpaths;

void getPathFromBasicBlockDFS(BasicBlock* BB, vector<CallInst*> callList, vector<BBConstraint*> path, set<vector<BBConstraint*>>& paths, set<BasicBlock*> visited, set<Function*> visitedFuncs, bool flag)
{
    if(visited.count(BB) > 0)
        return;
    visited.insert(BB);
    if(labeledBlocks.count(BB) > 0)
    {
        path.push_back(labeledBlocks[BB]);
        if(visitedLabeledBlocks.count(BB) == 0)
            visitedLabeledBlocks.insert(BB);
    }
    else
    {
        if(!flag)
        {   
            if(callBlockSubpaths.count(BB) && callBlockSubpaths[BB].count(path))
                return; 
            vector<pair<CallInst*, Function*>> calledFunctions = vector<pair<CallInst*, Function*>>();
            for(auto iter = BB->begin(); iter != BB->end(); iter++)
            {
                Instruction* I = &*iter;
                if(CallInst* callInst = dyn_cast<CallInst>(I))
                {
                    for(Function* F : GlobalCtx.Callees[callInst])
                    {
                        pair<CallInst*, Function*> calledFunction = pair<CallInst*, Function*>(callInst, F);
                        if(relatedFuncs.count(F) && visitedFuncs.count(F) == 0 &&
                            find(calledFunctions.begin(), calledFunctions.end(), calledFunction) == calledFunctions.end())
                            calledFunctions.push_back(calledFunction);
                    }
                }
            }
            if(calledFunctions.size() > 0)
            {
                set<vector<BBConstraint*>> subFuncConstraints;
                for(auto item : calledFunctions)
                {
                    Function* F = item.second;
                    if(visitedFuncs.count(F))
                        continue;
                    visitedFuncs.insert(F);
                    set<vector<BBConstraint*>> constraintsInFunc;
                    if(funcResCache.count(F))
                    {
                        constraintsInFunc = funcResCache[F];
                    }
                    else
                    {
                        constraintsInFunc = getBBConstraintsInSubFunc(F);
                        funcResCache[F] = constraintsInFunc;
                    }
                    subFuncConstraints.insert(constraintsInFunc.begin(), constraintsInFunc.end());
                }
                set<vector<BBConstraint*>> pathsFromCallBlock;
                if(blockResCache.count(BB))
                {
                    pathsFromCallBlock = blockResCache[BB];
                }
                else
                {
                    vector<BBConstraint*> pathFromCallBlock;
                    outs() << "analyze a call block in the path in function " << BB->getParent()->getName() << "\n";
                    outs() << *BB << "\n";
                    getPathFromBasicBlockDFS(BB, callList, pathFromCallBlock, pathsFromCallBlock, visited, visitedFuncs, true);
                    outs() << "finish analyze call block in the path\n";
                    outs() << "path length: " << path.size() << "\n";
                    outs() << "paths num in sub functions: " << subFuncConstraints.size() << "\n";
                    outs() << "paths num from call block: " << pathsFromCallBlock.size() << "\n";
                    blockResCache[BB] = pathsFromCallBlock;
                }
                if(subFuncConstraints.size() != 0)
                {
                    for(auto item : subFuncConstraints)
                    {
                        vector<BBConstraint*> tmp = path;
                        tmp.insert(tmp.end(), item.begin(), item.end());
                        if(pathsFromCallBlock.size() != 0)
                        {
                            for(auto p : pathsFromCallBlock)
                            {
                                p.insert(p.begin(), tmp.begin(), tmp.end());
                                if(p.size() != 0)
                                    paths.insert(p);
                            }
                        }
                        else
                        {
                            if(tmp.size() != 0)
                                paths.insert(tmp);
                        }
                    }
                }
                else
                {
                    if(pathsFromCallBlock.size() != 0)
                    {
                        for(auto p : pathsFromCallBlock)
                        {
                            p.insert(p.begin(), path.begin(), path.end());
                            if(p.size() != 0)
                                paths.insert(p);
                        }
                    }
                    else
                    {
                        if(path.size() != 0)
                            paths.insert(path);
                    }
                }
                if(callBlockSubpaths.count(BB) == 0)
                    callBlockSubpaths[BB] = set<vector<BBConstraint*>>();
                callBlockSubpaths[BB].insert(path);
                return;
            }
        }
    }
    if(pred_empty(BB))
    {
        if(callList.size() == 0)
        {
            if(path.size() > 0)
                paths.insert(path);
        }
        else
        {
            /*CallInst* callInst = callList[callList.size() - 1];
            vector<CallInst*> newCallList(callList.begin(), callList.end() - 1);
            outs() << "inter function analyze in function " << BB->getParent()->getName() << " parent function " << callInst->getFunction()->getName() << "\n";
            outs() << *(callInst->getParent()) << "\n";
            // getPathFromBasicBlockDFS(callInst->getParent(), newCallList, path, paths, visited, visitedFuncs, true);*/
            if(nopredBlokcSubpaths.count(BB) && nopredBlokcSubpaths[BB].count(path))
                return;
            set<vector<BBConstraint*>> pathsInCaller;
            if(blockResCache.count(BB))
            {
                pathsInCaller = blockResCache[BB];
            }
            else
            {
                CallInst* callInst = callList[callList.size() - 1];
                vector<CallInst*> newCallList(callList.begin(), callList.end() - 1);
                outs() << "inter function analyze in function " << BB->getParent()->getName() << " parent function " << callInst->getFunction()->getName() << "\n";
                vector<BBConstraint*> pathInCaller;
                getPathFromBasicBlockDFS(callInst->getParent(), newCallList, pathInCaller, pathsInCaller, visited, visitedFuncs, true);
                blockResCache[BB] = pathsInCaller;
            }
            if(pathsInCaller.size() != 0)
            {
                for(auto p : pathsInCaller)
                {
                    p.insert(p.begin(), path.begin(), path.end());
                    if(p.size() != 0)
                        paths.insert(p);
                }
            }
            else
            {
                if(path.size() != 0)
                    paths.insert(path);
            }
            if(nopredBlokcSubpaths.count(BB) == 0)
                nopredBlokcSubpaths[BB] = set<vector<BBConstraint*>>();
            nopredBlokcSubpaths[BB].insert(path);
            return;
            
        }
    }
    else
    {
        for(BasicBlock* bb:predecessors(BB))
        {
            if(visited.count(bb))
                continue;
            getPathFromBasicBlockDFS(bb, callList, path, paths, visited, visitedFuncs);
        }
    }
}

set<vector<BBConstraint*>> getBBConstraintsInSubFuncNew(Function* F, set<Function*> visitedFuncs)
{
    set<vector<BBConstraint*>> res;
    if(visitedFuncs.count(F) || inBlackList(F))
        return res;
    visitedFuncs.insert(F);
    if(funcResCache.count(F))
        return funcResCache[F];
    outs() << "sub function: " << F->getName() << "\n";
    vector<DFSStartBB*> dfsStartBBs = getDFSStartBBsBFSInFunc(F);
    outs() << "sub function found dfs start bb num: " << dfsStartBBs.size() << "\n";
    for(DFSStartBB* dfsStartBB : dfsStartBBs)
    {
        BasicBlock* BB = dfsStartBB->BB;
        vector<CallInst*> callList = dfsStartBB->callList;
        vector<BBConstraint*> path;
        set<vector<BBConstraint*>> paths;
        set<BasicBlock*> visited;
        set<Function*> visitedFunctions = visitedFuncs;
        visitedFunctions.insert(BB->getParent());
        getPathFromBasicBlockDFSNew(BB, callList, path, paths, visited, visitedFunctions, 0);
        res.insert(paths.begin(), paths.end());
    }
    outs() << "found paths num: " << res.size() << " in " << F->getName() << "\n";
    funcResCache[F] = res;
    return res;
}

map<BasicBlock*, set<vector<BBConstraint*>>> upPaths;
map<BasicBlock*, set<vector<BBConstraint*>>> downPaths;
map<BasicBlock*, set<vector<BBConstraint*>>> callBlockPaths;

void getPathFromBasicBlockDFSNew(BasicBlock* BB, vector<CallInst*> callList, vector<BBConstraint*> path, set<vector<BBConstraint*>>& paths, set<BasicBlock*> visited, set<Function*> visitedFuncs, bool flag, int loop)
{
    if (loop > 100) return;

    if(visited.count(BB) > 0)
        return;
    visited.insert(BB);
    
    if(labeledBlocks.count(BB) > 0)
    {
        path.push_back(labeledBlocks[BB]);
        vector<BBConstraint*> newPath = path;
        if(visitedLabeledBlocks.count(BB) == 0)
            visitedLabeledBlocks.insert(BB);
    }
    else
    {
        if(!flag)
        {
            vector<pair<CallInst*, Function*>> calledFunctions = vector<pair<CallInst*, Function*>>();
            for(auto iter = BB->begin(); iter != BB->end(); iter++)
            {
                Instruction* I = &*iter;
                if(CallInst* callInst = dyn_cast<CallInst>(I))
                {
                    for(Function* F : GlobalCtx.Callees[callInst])
                    {
                        pair<CallInst*, Function*> calledFunction = pair<CallInst*, Function*>(callInst, F);
                        if(relatedFuncs.count(F) && visitedFuncs.count(F) == 0 && !inBlackList(F) &&
                            find(calledFunctions.begin(), calledFunctions.end(), calledFunction) == calledFunctions.end())
                            calledFunctions.push_back(calledFunction);
                    }
                }
            }
            if(calledFunctions.size() > 0)
            {
                set<vector<BBConstraint*>> subFuncConstraints;
                if(callBlockPaths.count(BB))
                {
                    subFuncConstraints = callBlockPaths[BB];
                }
                else
                {
                    for(auto item : calledFunctions)
                    {
                        Function* F = item.second;
                        if(visitedFuncs.count(F))
                            continue;
                        outs() << "function name: " << F->getName() << "\n";
                        set<vector<BBConstraint*>> constraintsInFunc;
                        if(funcResCache.count(F))
                        {
                            constraintsInFunc = funcResCache[F];
                        }
                        else
                        {
                            set<Function*> visitedFunctions = visitedFuncs;
                            visitedFunctions.insert(BB->getParent());
                            constraintsInFunc = getBBConstraintsInSubFuncNew(F, visitedFunctions);
                            funcResCache[F] = constraintsInFunc;
                        }
                        subFuncConstraints.insert(constraintsInFunc.begin(), constraintsInFunc.end());
                    }
                    callBlockPaths[BB] = subFuncConstraints;
                }
                set<vector<BBConstraint*>> pathsFromCallBlock;
                if(upPaths.count(BB))
                {
                    pathsFromCallBlock = upPaths[BB];
                }
                else
                {
                    vector<BBConstraint*> pathFromCallBlock;
                    getPathFromBasicBlockDFSNew(BB, callList, pathFromCallBlock, pathsFromCallBlock, visited, visitedFuncs, true, loop + 1);
                    upPaths[BB] = pathsFromCallBlock;
                }
                if(subFuncConstraints.size() != 0)
                {
                    for(auto item : subFuncConstraints)
                    {
                        vector<BBConstraint*> tmp = path;
                        tmp.insert(tmp.end(), item.begin(), item.end());
                        if(pathsFromCallBlock.size() != 0)
                        {
                            for(auto p : pathsFromCallBlock)
                            {
                                p.insert(p.begin(), tmp.begin(), tmp.end());
                                if(p.size() != 0)
                                    paths.insert(p);
                            }
                        }
                        else
                        {
                            if(tmp.size() != 0)
                                paths.insert(tmp);
                        }
                    }
                }
                else
                {
                    if(pathsFromCallBlock.size() != 0)
                    {
                        for(auto p : pathsFromCallBlock)
                        {
                            p.insert(p.begin(), path.begin(), path.end());
                            if(p.size() != 0)
                                paths.insert(p);
                        }
                    }
                    else
                    {
                        if(path.size() != 0)
                            paths.insert(path);
                    }
                }
                return;
            }
        }
    }
    if(pred_empty(BB))
    {
        if(callList.size() == 0)
        {
            if(path.size() > 0)
                paths.insert(path);
        }
        else
        {
            set<vector<BBConstraint*>> pathsInCaller;
            if(upPaths.count(BB))
            {
                pathsInCaller = upPaths[BB];
            }
            else
            {
                CallInst* callInst = callList[callList.size() - 1];
                vector<CallInst*> newCallList(callList.begin(), callList.end() - 1);
                outs() << "inter function analyze in function " << BB->getParent()->getName() << " parent function " << callInst->getFunction()->getName() << "\n";
                vector<BBConstraint*> pathInCaller;
                getPathFromBasicBlockDFSNew(callInst->getParent(), newCallList, pathInCaller, pathsInCaller, visited, visitedFuncs, true, loop+1);
                upPaths[BB] = pathsInCaller;
            }
            if(pathsInCaller.size() != 0)
            {
                for(auto p : pathsInCaller)
                {
                    p.insert(p.begin(), path.begin(), path.end());
                    if(p.size() != 0)
                        paths.insert(p);
                }
            }
            else
            {
                if(path.size() != 0)
                    paths.insert(path);
            }
            return;
        }
    }
    else
    {
        set<vector<BBConstraint*>> pathsFromBB;
        if(upPaths.count(BB))
        {
            pathsFromBB = upPaths[BB];
        }
        else
        {
            for(BasicBlock* bb : predecessors(BB))
            {
                if(visited.count(bb))
                    continue;
                vector<BBConstraint*> pathFromBB;
                getPathFromBasicBlockDFSNew(bb, callList, pathFromBB, pathsFromBB, visited, visitedFuncs, loop+1);
            }
            upPaths[BB] = pathsFromBB;
        }

        if(pathsFromBB.size() != 0)
        {
            for(auto p : pathsFromBB)
            {
                
                p.insert(p.begin(), path.begin(), path.end());
                if(p.size() != 0)
                    paths.insert(p);
            }
        }
        else
        {
            if(path.size() != 0)
                paths.insert(path);
        }

    }
}

map<BasicBlock*, vector<map<unsigned, ConstBlockMap>>> getConstraintsWrapperNew(Function* F, map<unsigned, ConstBlockMap>& argConstMap, raw_fd_ostream& outfile)
{
    outs() << "process argument const map\n";
    labeledBlocks.clear();
    relatedFuncs.clear();
    labeledBlocks = labelBasicBlocks(argConstMap);
    visitedLabeledBlocks.clear();
    funcResCache.clear();
    blockResCache.clear();
    upPaths.clear();
    downPaths.clear();
    callBlockPaths.clear();
    map<BasicBlock*, vector<map<unsigned, ConstBlockMap>>> res;
    if(labeledBlocks.size() == 0)
        return res;
    vector<DFSStartBB*> dfsStartBBs = getDFSStartBBsBFSInFunc(F);
    for(DFSStartBB* dfsStartBB : dfsStartBBs)
    {
        BasicBlock* BB = dfsStartBB->BB;
        vector<CallInst*> callList = dfsStartBB->callList;
        vector<BBConstraint*> path;
        set<vector<BBConstraint*>> paths;
        set<BasicBlock*> visited;
        set<Function*> visitedFuncs;
        visitedFuncs.insert(BB->getParent());
        getPathFromBasicBlockDFSNew(BB, callList, path, paths, visited, visitedFuncs, 0);
        vector<map<unsigned, ConstBlockMap>> r = vector<map<unsigned, ConstBlockMap>>();
        for(auto p : paths)
        {
            BBConstraint* RootConstraint=NULL;
            for(auto bbcst:p){
                if (bbcst->bb==BB){
                    RootConstraint=bbcst;
                    break;
                }
            }
            if(RootConstraint){
                vector<BBConstraint*> newConstSet;
                set<Value*> RootConditions;
                set<int> RootValues;
                for(auto cmd:RootConstraint->cmdConstSet){
                    if(cmd->switchBlock && isa<SwitchInst>(cmd->switchBlock->getTerminator())){
                        SwitchInst* swi=dyn_cast<SwitchInst>(cmd->switchBlock->getTerminator());
                        RootConditions.insert(swi->getCondition());
                        RootValues.insert(cmd->value->getZExtValue());
                    }
                }
                if(RootConditions.size()!=0){
                    for(auto bbcst:p){
                        bool shouldRemove=false;
                        if(bbcst!=RootConstraint && RootConstraint->argIdx == bbcst->argIdx){
                            for(auto cmd: bbcst->cmdConstSet){
                                if(cmd->switchBlock && isa<SwitchInst>(cmd->switchBlock->getTerminator())){
                                    /* from switch */
                                    SwitchInst* swi=dyn_cast<SwitchInst>(cmd->switchBlock->getTerminator());
                                    Value* ConditionV=swi->getCondition();
                                    if (RootConditions.find(ConditionV)!=RootConditions.end()) { // TODO: use alias set
                                        
                                        if(RootValues.find(cmd->value->getZExtValue())==RootValues.end()){
                                            shouldRemove=true;
                                            break;
                                        }

                                    }
                                }
                            }
                            if(shouldRemove)
                                continue;
                        }
                        newConstSet.push_back(bbcst);
                    }
                    p=newConstSet;
                }
            }
            r.push_back(processBBConstraintVec(p));
        }
        if(r.size() != 0)
        {
            res[BB] = r;
        }
    }
    return res;
}

map<unsigned, Function*> handleIoctlHandlersGlobalVar(GlobalVariable* ioctlHandlers)
{
    map<unsigned, Function*> res;
    outs() << "ioctl_handlers:\n";
    outs() << *ioctlHandlers << "\n";
    ConstantArray* ioctlHandlersArray = dyn_cast<ConstantArray>(ioctlHandlers->getInitializer());
    if(ioctlHandlersArray == nullptr)
        return res;
    outs() << "constant array:\n";
    outs() << *ioctlHandlersArray << "\n";
    for(int i = 0; i < ioctlHandlersArray->getNumOperands(); i++)
    {
        ConstantStruct* ioctlHandler = dyn_cast<ConstantStruct>(ioctlHandlersArray->getOperand(i));
        if(ioctlHandler == nullptr)
            continue;
        ConstantInt* cmd = dyn_cast<ConstantInt>(ioctlHandler->getOperand(GlobalCtx.StructFieldIdx["ioctl_handler"]["cmd"]));
        if(cmd == nullptr)
            continue;
        Function* handler = dyn_cast<Function>(ioctlHandler->getOperand(GlobalCtx.StructFieldIdx["ioctl_handler"]["func"]));
        res[cmd->getZExtValue()] = handler;
    }
    return  res;
}

void handleSndSeqIoctl(Function* targetFunction, InfoItem* info, raw_fd_ostream& outfile)
{
    Module* M = targetFunction->getParent();
    GlobalVariable* ioctlHandlers = nullptr;
    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) { 
        GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
        if (g == nullptr) {
            continue;
        }
        outs() << "global name: " << g->getName() << "\n";
        if(g->getName() == "ioctl_handlers")
        {
            ioctlHandlers = g;
            break;
        }
    }
    map<unsigned, Function*> res = handleIoctlHandlersGlobalVar(ioctlHandlers);
    string str = "ioctl|D[" + info->name + "]";
    vector<string> signatures;
    for(auto item:res)
    {
        string s = str + "|C[" + to_string(item.first) + "]|C[]";
        s += " ";
        s += "0";
        s += " ";
        if (item.second->getName() != "")
            s += item.second->getName().str();
        else
            s += "none";
        signatures.push_back(s);
    }
    
    for(string s : signatures)
    {
        outfile << s << "\n";
    }
}

#define AUTOFS_DEV_IOCTL_IOC_FIRST 3222836081

map<unsigned, Function*> handleArrayHandlers(GlobalVariable* ioctls, long bias)
{
    map<unsigned, Function*> res;
    ConstantArray* ioctlsArray = dyn_cast<ConstantArray>(ioctls->getInitializer());
    if(ioctlsArray == nullptr)
        return res;
    for(int i = 0; i < ioctlsArray->getNumOperands(); i++)
    {
        Function* ioctlFunc = dyn_cast<Function>(ioctlsArray->getOperand(i));
        if(ioctlFunc == nullptr)
            continue;
        res[i + bias] = ioctlFunc;
    }
    return res;
}

void handleAutofsDevIoctl(Function* targetFunction, InfoItem* info, raw_fd_ostream& outfile)
{
    GlobalVariable* targetGlobalVar = nullptr;
    for(inst_iterator iter = inst_begin(targetFunction); iter != inst_end(targetFunction); iter++)
    {
        Instruction* I = &*iter;
        if(GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(I))
        {
            if(!gepInst->getResultElementType()->isPointerTy())
                continue;
            if(gepInst->getResultElementType()->getPointerElementType()->isFunctionTy())
            {
                Value* src = gepInst->getOperand(0);
                if(GlobalVariable* g = dyn_cast<GlobalVariable>(src))
                {
                    targetGlobalVar = g;
                    break;
                }
            }
        }
    }
    if(targetGlobalVar == nullptr)
        return;
    map<unsigned, Function*> res = handleArrayHandlers(targetGlobalVar, AUTOFS_DEV_IOCTL_IOC_FIRST);
    string str = "ioctl|D[" + info->name + "]";
    vector<string> signatures;
    for(auto item:res)
    {
        string s = str + "|C[" + to_string(item.first) + "]|C[]";
        s += " ";
        s += "0";
        s += " ";
        if (item.second->getName() != "")
            s += item.second->getName().str();
        else
            s += "none";
        signatures.push_back(s);
    }
    
    for(string s : signatures)
    {
        outfile << s << "\n";
    }
}


void handleUcmaWrite(Function* targetFunction, InfoItem* info, raw_fd_ostream& outfile)
{
    Module* M = targetFunction->getParent();
    GlobalVariable* ucma_cmd_table = M->getGlobalVariable("ucma_cmd_table", true);
    if(ucma_cmd_table == nullptr)
        return;
    map<unsigned, Function*> res = handleArrayHandlers(ucma_cmd_table, 0);
    // write|D[rdma_cm] 0 ucma_write
    string str = "write|D[" + info->name + "]";
    vector<string> signatures;
    for (auto &item: res)
    {
        outs() << "idx: " << item.first << " func: " << item.second->getName().str() << "\n";
        string s = str + "|C[" + to_string(item.first) + "]|C[]";
        s += " ";
        s += "0";
        s += " ";
        if (item.second->getName() != "") {
            s += item.second->getName().str();
            signatures.push_back(s);
        }
    }
    for(string s : signatures)
    {
        outfile << s << "\n";
    }
}

std::map<unsigned, ConstBlockMap> getTargetBlocksInFunc(Function* F)
{
    std::map<unsigned, ConstBlockMap> res;
    if(F->getInstructionCount() == 0)
    {
        F = getFunctionFromModules(F->getName());
    }
    if(GlobalCtx.FoundFunctionCache.count(F)> 0)
    {
        return GlobalCtx.FoundFunctionCache[F];
    }
    for(Function::arg_iterator iter = F->arg_begin(); iter != F->arg_end(); iter++)
    {
        unsigned argNo = iter->getArgNo();
        map<Function*, set<unsigned>> visited;
        res[argNo] = getTargetBlockByArg(F, argNo, visited, 0);
    }
    GlobalCtx.FoundFunctionCache[F] = res;
    return res;
}

bool needToAnalyzeArg(Function* F, vector<int> mappedArgs, Function* entryFunc)
{
    if(entryFunc == nullptr)
        return true;
    vector<string> funcs = {
        "__se_sys_ioctl",
        "do_dentry_open",
        "vfs_read",
        "vfs_write",
        "__sys_setsockopt",
        "__sys_getsockopt",
        "____sys_sendmsg",
        "____sys_recvmsg",
        "__sys_listen"
    };
    if(find(funcs.begin(), funcs.end(), entryFunc->getName().str()) != funcs.end() &&
        find(mappedArgs.begin(), mappedArgs.end(), 0) != mappedArgs.end())
        return false;

    return true;
}

bool needToAnalyzeArg(Function* F, vector<int> mappedArgs, string syscall)
{
    if(syscall == "")
        return true;
    vector<string> funcs = {
        "ioctl",
        "open",
        "read",
        "write",
        "mmap",
        "setsockopt",
        "getsockopt",
        "sendmsg",
        "recvmsg",
        "listen",
        "accept",
        "connect",
        "bind",
        "getname"
    };
    if(find(funcs.begin(), funcs.end(), syscall) != funcs.end() &&
        find(mappedArgs.begin(), mappedArgs.end(), 0) != mappedArgs.end())
        return false;

    return true;
}

map<unsigned, ConstBlockMap> getTargetBlocksInFuncByArgMap(Function* F, vector<vector<int>>& argMap, Function* entryFunc)
{
    map<unsigned, ConstBlockMap> res;
    if(F->getInstructionCount() == 0)
    {
        F = getFunctionFromModules(F->getName());
    }
    if(GlobalCtx.FoundFunctionCache.count(F)> 0)
    {
        return GlobalCtx.FoundFunctionCache[F];
    }
    for(Function::arg_iterator iter = F->arg_begin(); iter != F->arg_end(); iter++)
    {
        unsigned argNo = iter->getArgNo();
        map<Function*, set<unsigned>> visited;
        vector<int> mappedArgs = argMap[argNo];
        if(mappedArgs.size() == 0 || !needToAnalyzeArg(F, mappedArgs, entryFunc))
        {
            res[argNo] = ConstBlockMap();
            continue;
        }
        outs() << "find related constant of argIdx " << argNo << "\n";
        res[argNo] = getTargetBlockByArg(F, argNo, visited, 0);
    }
    GlobalCtx.FoundFunctionCache[F] = res;
    return res;
}

map<unsigned, ConstBlockMap> getTargetBlocksInFuncByArgMap(Function* F, vector<vector<int>>& argMap, string syscall)
{
    map<unsigned, ConstBlockMap> res;
    if(F->getInstructionCount() == 0)
    {
        F = getFunctionFromModules(F->getName());
    }
    if(GlobalCtx.FoundFunctionCache.count(F)> 0)
    {
        return GlobalCtx.FoundFunctionCache[F];
    }
    for(Function::arg_iterator iter = F->arg_begin(); iter != F->arg_end(); iter++)
    {
        unsigned argNo = iter->getArgNo();
        map<Function*, set<unsigned>> visited;
        vector<int> mappedArgs = argMap[argNo];
        if(mappedArgs.size() == 0 || !needToAnalyzeArg(F, mappedArgs, syscall))
        {
            res[argNo] = ConstBlockMap();
            continue;
        }
        outs() << "find related constant of argIdx " << argNo << " of " << F->getName() << "\n";
        res[argNo] = getTargetBlockByArg(F, argNo, visited, 0);
    }
    GlobalCtx.FoundFunctionCache[F] = res;
    return res;
}

void outputBlocks(std::map<unsigned, ConstBlockMap> map, raw_fd_ostream& outfile)
{
    unsigned totalBlocks = 0;
    for(std::map<unsigned, ConstBlockMap>::iterator iter = map.begin(); iter != map.end(); iter++)
    {
        unsigned argIdx = iter->first;
        ConstBlockMap constBlockMap = iter->second;
        for(ConstBlockMap::iterator it = constBlockMap.begin(); it != constBlockMap.end(); it++)
        {
            ConstantInt* value = (*it)->value;
            BasicBlock* bb = (*it)->targetBlock;
            outfile << "cmd idx: " << argIdx << " value: " << value->getZExtValue() << " block: " << bb->getName() << " at " << bb->getParent()->getName() <<"\n";
            CastOpPath castPath = (*it)->castOps;
            if(castPath.size() > 0)
            {
                outfile << "cast path: ";
                for(CastOp* castop: castPath)
                {
                    outfile << castop->op << ": " << *(castop->srcTy) << " -> " << *(castop->dstTy) << " ";
                }
                outfile << "\n";
            }
            /*
            OperandPath opPath = (*it)->opPath;
            if(opPath.size() > 0)
            {
                outfile << "operand path:" << "\n";
                for(Value* v: opPath)
                {
                    if(Instruction* I = dyn_cast<Instruction>(v))
                    {
                        outfile << *I << " " << I->getFunction()->getName().str() << "\n";
                    }
                    else if(Function* F = dyn_cast<Function>(v))
                    {
                        outfile << "function: " << F->getName() << "\n";
                    }
                    else
                    {
                        outfile << *v << "\n";
                    }
                }
            }*/
            totalBlocks++;
        }

    }
    outfile << "total found blocks: " << totalBlocks << "\n";
}

void testFindBlocks(Function* F)
{
    std::error_code OutErrorInfo;
    std::string funcName = F->getName().str();
    raw_fd_ostream blocksFile(StringRef("./" + funcName + "_target_blocks.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);
    outs() << "Function: " << funcName << "\n";
    outputBlocks(getTargetBlocksInFunc(F), blocksFile);
}

bool isRetFixedValueInPath(ReturnInst* retInst, std::vector<BasicBlock*> path, int64_t* value)
{
    Instruction* inst = retInst;
    while(!inst->operands().empty())
    {
        if(PHINode* phiNode = dyn_cast<PHINode>(inst))
        {
            BasicBlock* relatedBB = phiNode->getParent();
            std::vector<BasicBlock*>::iterator it = std::find(path.begin(), path.end(), relatedBB);
            if(it == path.begin() || it == path.end())
            {
                return false;
            }
            BasicBlock* srcBB = *(it - 1);
            Value* v = phiNode->getIncomingValueForBlock(srcBB);
            if(Instruction* instDef = dyn_cast<Instruction>(v))
            {
                if(instDef->getParent() == inst->getParent())
                {
                    inst = instDef;
                }
                else if(std::find(path.begin(), path.end(), instDef->getParent())!= path.end())
                {
                    inst = instDef;
                }
                else
                {
                    // the pre block of ret inst is not in the path
                    return false;
                }
            }
            else if(ConstantInt* c = dyn_cast<ConstantInt>(v))
            {
                *value = c->getSExtValue();
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            if(inst->getNumOperands() > 1)
                return false;
            for(Use &U: inst->operands())
            {
                
                if(Instruction* instDef = dyn_cast<Instruction>(U.get()))
                {
                    if(instDef->getParent() == inst->getParent())
                    {
                        inst = instDef;
                        break;
                    }
                    else if(std::find(path.begin(), path.end(), instDef->getParent())!= path.end())
                    {
                        inst = instDef;
                        break;
                    }
                    else
                    {
                        // the pre block of ret inst is not in the path
                        return false;
                    }
                }
                else if (ConstantInt *c = dyn_cast<ConstantInt>(U.get()))
                {
                    *value = c->getSExtValue();
                    return true;
                }
                else{
                    outs() << *(U.get()) << "\n";
                    return false;
                }
            }
        }
    }
    return true;
}

ReturnInst* getRetInstInPath(vector<BasicBlock*> path)
{
    BasicBlock* endBB = path[path.size() - 1];
    ReturnInst* retInst = nullptr;
    for(Instruction& I: *endBB)
    {
        Instruction* inst = &I;
        if(inst->getOpcode() == Instruction::Ret)
        {
            retInst = dyn_cast<ReturnInst>(inst);
            return retInst;
        }
    }
    outs() << "in function: " << endBB->getParent()->getName() << "\n"; 
    return retInst;
}

bool isRetFixedNegativeInPaths(vector<vector<BasicBlock*>>& paths)
{
    int64_t curr = 0;
    for(vector<BasicBlock*> path : paths)
    {
        ReturnInst* retInst = getRetInstInPath(path);
        if(retInst == nullptr)
        {
            outs() << "can't find return instruction, something wrong!!!" << "\n";
            return  false;
        }
        int64_t value = 0;
        bool res = isRetFixedValueInPath(retInst, path, &value);
        if(!res || value >= 0)
            return false;
        if(curr != 0)
        {
            if (value != curr)
                return false;
        }
        else
        {
            curr = value;
        }
    }
    return true;
}

vector<string> getNetDeviceNameByAllocNetdev()
{
    vector<string> res;
    for(auto item: GlobalCtx.Modules)
    {
        Module* M = item.first;
        for(Module::iterator mi = M->begin(); mi != M->end(); mi++)
        {
            Function* F = &*mi;
            if(F->hasName())
            {
                if(F->getName().str() == "alloc_netdev_mqs")
                {
                    for(User* user : F->users())
                    {
                        if(CallInst* callInst = dyn_cast<CallInst>(user))
                        {
                            outs() << "in function: " << callInst->getFunction()->getName() << "\n";
                            outs() << "alloc_netdev_mqs: " << *callInst << "\n";
                            Value* op = callInst->getArgOperand(1);
                            if(op->getValueID() == Value::ConstantExprVal)
                            {
                                ConstantExpr* expr = dyn_cast<ConstantExpr>(op);
                                if(expr->getOpcode() == Instruction::GetElementPtr)
                                {
                                    string str = getDeviceString(op);
                                    outs() << "str: " << str << "\n";
                                    res.push_back(str);
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