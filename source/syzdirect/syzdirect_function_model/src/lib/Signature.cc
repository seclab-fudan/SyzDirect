#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Path.h"


#include "Signature.h"

#include "CodeFeatures.h"

Signature::Signature(Function* handlerFunction, const string& syscallType, GlobalVariable* operationStruct, vector<int> FunctionSyscallArgMapItem) : handlerFunction(handlerFunction), syscallType(syscallType), operationStruct(operationStruct) {
    auto functionArgConstMap = getTargetBlocksInFunc(handlerFunction);
    for (auto argConstItem: functionArgConstMap) {
        int affectedSyscallArg = FunctionSyscallArgMapItem[argConstItem.first];
        if(handlerFunction->getArg(argConstItem.first)->getType()->isIntegerTy()) {
            for (int i = 1; i <= affectedSyscallArg; i <<= 1) {
                if (i & affectedSyscallArg) {
                    this->argConstBlockMap[i].insert(argConstBlockMap[i].end(), argConstItem.second.begin(), argConstItem.second.end());
                }
            }
        }
    }
}

Signature::Signature(Function* handlerFunction, const string& syscallType, const string& subsystemName, map<unsigned, ConstBlockMap> argConstBlockMap) : handlerFunction(handlerFunction), syscallType(syscallType), subsystemName(subsystemName), argConstBlockMap(argConstBlockMap) {}

map<unsigned, ConstBlockMap> Signature::getArgConstBlockMap()
{
    return this->argConstBlockMap;
}

Function* Signature::getHandlerFunction()
{
    return this->handlerFunction;
}

string Signature::getName()
{
    return this->subsystemName;
}

string Signature::getSyscallType()
{
    return this->syscallType;
}