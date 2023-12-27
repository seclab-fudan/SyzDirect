#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <string>
#include "Analyzer.h"
#include "CodeFeatures.h"

class Signature {
    private:
        Function* handlerFunction;
        GlobalVariable* operationStruct;
        string subsystemName;
        string syscallType;
        map<unsigned, ConstBlockMap> argConstBlockMap;
        int additionalFlags; // return fixed value? need other module? 

    public:
        Signature(Function* handlerFunction, const string& syscallType, GlobalVariable* operationStruct, vector<int> FunctionSyscallArgMapItem);
        Signature(Function* handlerFunction, const string& syscallType, const string& subsystemName, map<unsigned, ConstBlockMap> argConstBlockMap);
        map<unsigned, ConstBlockMap> getArgConstBlockMap();
        Function* getHandlerFunction();
        string getName();
        std::string serialize();
        string getSyscallType();
};

#endif