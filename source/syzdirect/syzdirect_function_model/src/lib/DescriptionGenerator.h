#ifndef DESCRIPTION_GENERATOR_H
#define DESCRIPTION_GENERATOR_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>

#include "Analyzer.h"

#include "CodeFeatures.h"

#include "DeviceExtractor.h"
#include "FilesystemExtractor.h"
#include "NetworkInterfaceExtractor.h"

class SyscallInstance;
class Generator;

class Arg {
    public:
        string name;
        string type;
        bool isDev = false;
        Arg(string name, string type, bool isDev = false) : name(name), type(type), isDev(isDev) { };
        Arg(const Arg& arg);
};

class Constraint {
    public:
        int argIdx;
        virtual void SetConstraintToSyscall(SyscallInstance*) = 0;
};

class ConstantConstraint : public Constraint {
    public:
        int value;
        // string constName;
        ConstantConstraint(int argIdx, int value);
        void SetConstraintToSyscall(SyscallInstance*);
};

class BasicBlockConstraint : public Constraint {
    public:
        BasicBlock* block;
        Value* value;
        set<BasicBlock*> visitedBB;
        BasicBlockConstraint(int argIdx, BasicBlock* BB, Value* value);
        void SetConstraintToSyscall(SyscallInstance*);
        set<Value*> CollectReachableCFU(BasicBlock* BB, set<Value*>& current);
};

class StringConstraint : public Constraint {
    public:
        string cmpStr;
        StringConstraint(int argIdx, string cmpStr);
        void SetConstraintToSyscall(SyscallInstance*);
};


class Syscall {
    protected:
        string name;
        vector<Arg*> *args;
        Generator* generator;
        // Arg* ret;
    public:
        Syscall(string name, vector<Arg*>* args);
        Syscall(const Syscall &syscall);
        vector<Arg*>* getArgs() { return args; }
        virtual string serialize();
        Generator* getGenerator();
        void setGenerator(Generator*);
        // SyscallInstance* instantiateSyscall(string devStr);
};

class SyscallInstance: public Syscall {
    private:
        string devStr;
        // map<int, Constraint> constraints;
    public:
        SyscallInstance(Syscall syscall, string devStr) : Syscall(syscall), devStr(devStr) {};
        string serialize();
        // void setConstraint(int argIdx, Constraint* constraint);
        // void setConstraint(ConstantConstraint);
        // void setConstraint(BasicBlockConstraint);
};

string GenerateRandomString(string prefix, int randLength, string suffix);


class Generator {
    private:
        GlobalContext* Ctx;
    public:
    // map<string, string> ResourceOnlySyscallTemplate = {
    //     {"read", "read$%s(fd fd_%s, buf buffer[out], count len[buf])\n"},
    //     {"write", "write$%s(fd fd_%s, buf buffer[in], count len[buf])\n"},
        
    // };

    map<string, int> ConstMap;
    map<string, vector<pair<string, string>>* > StructMap;
    set<string> devs;

    vector<SyscallInstance*> Syscalls;

    // string IoctlTemplate = "ioctl$%s(fd fd_%s, cmd const[%s], arg ptr[in, %s])";

    map<string, Syscall*> SyscallMap;

        Generator(GlobalContext* Ctx);
        SyscallInstance* AddSyscall(string name, string devName);
        SyscallInstance* AddSyscall(string name, string devName, int family, int type, int protocol);
        void ExtractStructure(string structName, StructType* structType);
        string ExtractType(Type* Ty);
        string serialize();
};

#endif