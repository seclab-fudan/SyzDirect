#include <boost/format.hpp>

#include "DescriptionGenerator.h"

#include "CodeFeatures.h"

#include "DeviceExtractor.h"
#include "FilesystemExtractor.h"
#include "NetworkInterfaceExtractor.h"

using boost::format;

Arg::Arg(const Arg& arg) {
    this->name = arg.name;
    this->type = arg.type;
    this->isDev = arg.isDev;
}

Syscall::Syscall(const Syscall &syscall) {
    this->name = syscall.name;
    this->args = new vector<Arg*>();
    for (auto item : *syscall.args) {
        this->args->push_back(new Arg(*item));
    }
}

Syscall::Syscall(string name, vector<Arg*>* args) {
    this->name = name;
    this->args = new vector<Arg*>();
    for (auto item : *args) {
        this->args->push_back(new Arg(*item));
    }
}


map<string, vector<tuple<string, string, bool>>> SyscallArgsMap = {
        {"openat", {
            {"fd", "const[AT_FDCWD]", false}, 
            {"file", "ptr[in, string[\"/dev/%s\"]]", true}, 
            {"flags", "flags[open_flags]", false}, 
            {"mode", "const[0]", false},
        }}, 
        {"add_key", {
            {"type", "ptr[in, string]", false},
            {"desc", "ptr[in, key_desc]", false},
            {"payload", "buffer[in]", false},
            {"paylen", "len[payload]", false},
            {"keyring", "keyring[opt]", false},
        }},
        {"read", {
            {"fd", "fd_%s", true},
            {"buf", "buffer[out]", false}, 
            {"count", "len[buf]", false},
        }},
        {"write", {
            {"fd", "fd_%s", true},
            {"buf", "buffer[in]", false}, 
            {"count", "len[buf]", false},
        }},
        {"ioctl", {
            {"fd", "fd_%s", true},
            {"cmd", "int32", false},
            {"arg", "buffer[inout]", false}
        }}, 
        {"fsetxattr", {
            {"fd", "fd", false},
            {"name", "ptr[in, string]", false},
            {"val", "ptr[in, string]", false},
            {"size", "len[val]", false},
            {"flags", "flags[setxattr_flags]", false},
        }}, 
        {"setxattr", {
            {"path", "ptr[in, filename]", false},
            {"name", "ptr[in, string]", false},
            {"val", "ptr[in, string]", false},
            {"size", "len[val]", false},
            {"flags", "flags[setxattr_flags]", false},
        }},
        {"lsetxattr", {
            {"path", "ptr[in, filename]", false},
            {"name", "ptr[in, string]", false},
            {"val", "ptr[in, string]", false},
            {"size", "len[val]", false},
            {"flags", "flags[setxattr_flags]", false},
        }},
        {"socket", {
            {"family", "int32", false},
            {"type", "int32", false},
            {"protocol", "int32", false},
        }},
        {"setsockopt", {
            {"fd", "fd_%s", true},
            {"level", "int", false},
            {"optname", "int", false},
            {"optval", "buffer[in]", false},
            {"optlen", "len[optval]", false},
        }}, 
        {"getsockopt", {
            {"fd", "fd_%s", true},
            {"level", "int32", false},
            {"optname", "int32", false},
            {"optval", "buffer[out]", false},
            {"optlen", "ptr[inout, len[optval, int32]]", false},
        }}, 
};

map<string, bool> SyscallRetMap = {
        {"openat", true},
        {"socket", true}
};


string GenerateRandomString(string prefix, int randLength, string suffix = "") {
    string res = prefix;
    string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < randLength; i++) {
        res += charset[rand() % charset.length()];
    }
    res += suffix;
    return res;
}

// init syscall args
Generator::Generator(GlobalContext* Ctx) {
    this->Ctx = Ctx;
    srand(time(0));
    for (auto item: SyscallArgsMap) {
        auto syscall = item.first;
        vector<Arg*>* argsVec = new vector<Arg*>();
        auto args = item.second;
        for (auto arg: args) {
            auto name = get<0>(arg);
            auto type = get<1>(arg);
            auto isDev = get<2>(arg);
            argsVec->push_back(new Arg(name, type, isDev));
        }
        SyscallMap[syscall] = new Syscall(syscall, argsVec);
    }

    

}

Generator* Syscall::getGenerator() {
    return this->generator;
}

void Syscall::setGenerator(Generator* generator_t) {
    this->generator = generator_t;
}

SyscallInstance* Generator::AddSyscall(string name, string devName) {
    if (devName != "" && this->devs.count(devName) == 0 && devName != "fd") {
        this->devs.insert(devName);
        AddSyscall("openat", devName);
    }
    SyscallInstance* instance = new SyscallInstance(*(SyscallMap[name]), devName);
    for (auto arg: *(instance->getArgs())) {
        if (arg->isDev) {
            if (devName == "fd" || devName == "sock") {
                arg->type = devName;
            } else {
                arg->type = str(boost::format(arg->type) % devName);
            }
        }
    }
    this->Syscalls.push_back(instance);
    instance->setGenerator(this);
    return instance;
}

SyscallInstance* Generator::AddSyscall(string name, string devName, int family, int type, int protocol) {
    if (devName != "" && this->devs.count(devName) == 0 && devName != "sock") {
        this->devs.insert(devName);
        auto socketSyscall = AddSyscall("socket", devName);
        auto familyConstraint = new ConstantConstraint(0, family);
        familyConstraint->SetConstraintToSyscall(socketSyscall);
        auto typeConstraint = new ConstantConstraint(1, type);
        typeConstraint->SetConstraintToSyscall(socketSyscall);
        auto protocolConstraint = new ConstantConstraint(2, protocol);
        protocolConstraint->SetConstraintToSyscall(socketSyscall);
    }
    SyscallInstance* instance = new SyscallInstance(*(SyscallMap[name]), devName);
    for (auto arg: *(instance->getArgs())) {
        if (arg->isDev) {
            if (devName == "fd" || devName == "sock") {
                arg->type = devName;
            } else {
                arg->type = str(boost::format(arg->type) % devName);
            }
        }
    }
    this->Syscalls.push_back(instance);
    instance->setGenerator(this);
    return instance;
}

ConstantConstraint::ConstantConstraint(int argIdx, int value) {
    this->argIdx = argIdx;
    this->value = value;
}

StringConstraint::StringConstraint(int argIdx, string cmpStr) {
    this->argIdx = argIdx;
    this->cmpStr = cmpStr;
}

BasicBlockConstraint::BasicBlockConstraint(int argIdx, BasicBlock* BB, Value* value) {
    this->argIdx = argIdx;
    this->block = BB;
    this->value = value;
}

void ConstantConstraint::SetConstraintToSyscall(SyscallInstance* instance) {
    auto arg = instance->getArgs()->at(argIdx);
    auto name = arg->name;
    if (arg->type != "int32") {
        return;
    }
    auto constName = GenerateRandomString("CONST_", 5);
    auto val = this->value;
    instance->getArgs()->at(argIdx) = new Arg(name, str(boost::format("const[%s]") % constName));
    instance->getGenerator()->ConstMap[constName] = val;
    return;
}

void StringConstraint::SetConstraintToSyscall(SyscallInstance* instance) {
    auto arg = instance->getArgs()->at(argIdx);
    auto val = this->cmpStr;
    if (arg->type != "ptr[in, string]") {
        return;
    }
    instance->getArgs()->at(argIdx) = new Arg(arg->name, str(boost::format("ptr[in, string[\"%s\"]]") % cmpStr));
    return;
    
}

set<Value*> BasicBlockConstraint::CollectReachableCFU(BasicBlock* BB, set<Value*>& current) {
    for (auto succ: successors(BB)) {
        if (this->visitedBB.count(succ) != 0) {
            continue;
        }
        this->visitedBB.insert(succ);
        for (auto &I: *succ) {
            if (auto callInst = dyn_cast<CallInst>(&I)) {
                if (auto calledFunc = callInst->getCalledFunction()) {
                    if (calledFunc->hasName() && calledFunc->getName() == "_copy_from_user") {
                        current.insert(callInst);
                    }
                }
            }
        }
        CollectReachableCFU(succ, current);
    }
    return current;
}

string Generator::ExtractType(Type* Ty) {
    if (Ty->isIntegerTy()) {
        auto width = Ty->getIntegerBitWidth();
        return str(boost::format("int%d") % width);
    } else if (Ty->isFloatTy()) {
        return "float32";
    } else if (Ty->isPointerTy()) {
        return str(boost::format("ptr[inout, %s]") % ExtractType(Ty->getPointerElementType()));
    } else if (Ty->isArrayTy()) {
        auto elemType = ExtractType(Ty->getArrayElementType());
        auto elemNum = Ty->getArrayNumElements();
        return str(boost::format("array[%s, %d]") % elemType % elemNum);
    } else if (Ty->isStructTy()) {
        auto structName = Ty->getStructName().substr(7).str();
        return structName;
    } else {
        string typeName;
        llvm::raw_string_ostream rso(typeName);
        Ty->print(rso);
        return rso.str();
    }
}

void Generator::ExtractStructure(string structName, StructType* structType) {
    auto structure = new vector<pair<string, string>>;

    for (int i = 0; i < structType->getStructNumElements(); i++) {
        auto Ty = structType->getStructElementType(i);
        if (Ty->isPointerTy()) {
            auto ptrTy = cast<PointerType>(Ty);
            auto pointedTy = ptrTy->getPointerElementType();
            if (pointedTy->isStructTy()) {
                auto structTy = cast<StructType>(pointedTy);
                auto pointedStructName = structTy->getStructName().substr(7).str(); 
                if (pointedStructName != structName) {
                    ExtractStructure(pointedStructName, structTy);
                }
            }
        }
        auto structFieldMap = Ctx->StructFieldIdx[structName];
        for (auto item: structFieldMap) {
            auto fieldName = item.first;
            auto fieldIdx = item.second;
            if (fieldIdx == i) {
                structure->push_back(make_pair(fieldName, ExtractType(Ty)));
                break;
            }
        }
    }

    this->StructMap[structName] = structure;
}

void BasicBlockConstraint::SetConstraintToSyscall(SyscallInstance* instance) {
    auto arg = instance->getArgs()->at(argIdx);
    auto name = arg->name;
    

    // get value alias 
    set<Value*> srcValueSet;
    srcValueSet.insert(this->value);
    auto func = this->block->getParent();
    for (auto &BB: *func) {
        for (auto &I: BB) {
            if (auto castInst = dyn_cast<CastInst>(&I)) {
                auto src = castInst->getOperand(0);
                if (srcValueSet.count(src)) {
                    srcValueSet.insert(castInst);
                }
            }
        }
    }

    // collect reachable copy_from_users
    this->visitedBB.clear();
    set<Value*> CFUSet;
    CFUSet = CollectReachableCFU(this->block, CFUSet);

    set<Value*> dstValueSet;
    // check if the CFU src is in the CFUSet
    for (auto item: CFUSet) {
        outs() << "CFU: " << *item << "\n";
        auto callInst = dyn_cast<CallInst>(item);
        auto src = callInst->getArgOperand(1);
        if (srcValueSet.count(src)) {
            dstValueSet.insert(callInst->getArgOperand(0));
        }
    }

    // get alias of the copy_from_user dest
    // prev
    for (auto iter = func->getBasicBlockList().rbegin(); iter != func->getBasicBlockList().rend(); iter++) {
        auto &BB = *iter;
        for (auto instIter = BB.rbegin(); instIter != BB.rend(); instIter++) {
            auto &I = *instIter;
            if (auto castInst = dyn_cast<CastInst>(&I)) {
                auto src = castInst->getOperand(0);
                if (dstValueSet.count(castInst)) {
                    dstValueSet.insert(src);
                }
            }
        }
    }
    // next
    for (auto &BB: *func) {
        for (auto &I: BB) {
            if (auto castInst = dyn_cast<CastInst>(&I)) {
                auto src = castInst->getOperand(0);
                if (dstValueSet.count(src)) {
                    dstValueSet.insert(castInst);
                }
            }
        }
    }
    
    set<Type*> structTys;

    // get type of the dest ptr
    for (auto item: dstValueSet) {
        outs() << *item << "\n";    
        if (item->getType()->isPointerTy()) {
            auto PETy = item->getType()->getPointerElementType();
            if (PETy->isStructTy()) {
                structTys.insert(PETy);
            }
            // outs() << "structTy: " << *structTy << "\n";  
        }
    }

    // extract the struct type
    if (structTys.empty()) {
        instance->getArgs()->at(argIdx) = new Arg(name, "intptr");
    } else {
        for (auto structTy: structTys) {
            auto structName = structTy->getStructName().substr(7).str(); // remove "struct."
            outs() << "structName: " << structName;
            if (auto structType = dyn_cast<StructType>(structTy)) {
                instance->getArgs()->at(argIdx) = new Arg(name, str(boost::format("ptr[inout, %s]") % structName));
                instance->getGenerator()->ExtractStructure(structName, structType);
            }
        }
    }


    

}

string SyscallInstance::serialize() {
    string result = "";
    result += this->name + "$";
    result += GenerateRandomString(this->devStr + "_", 5) + "(";
    bool flag = false;
    for (auto arg: *(this->args)) {
        if (flag) {
            result += ", ";
        }
        auto name = arg->name;
        auto type = arg->type;
        result += str(boost::format("%s %s") % name % type);
        flag = true;
    }
    result += ")";
    if (SyscallRetMap.count(this->name)) {
        result += " fd_" + this->devStr; 
    }
    return result;
}

string Syscall::serialize() {
    string result = "";
    result += this->name;
    result += "(";
    bool flag = false;
    for (auto arg: *(this->args)) {
        if (flag) {
            result += ", ";
        }
        auto name = arg->name;
        auto type = arg->type;
        result += str(boost::format("%s %s") % name % type);
        flag = true;
    }
    result += ")";
    if (SyscallRetMap.count(this->name)) {
        result += " fd";
    }
    return result;
}

string Generator::serialize() {
    // print all the constants
    string result = "";
    for (auto item: this->ConstMap) {
        auto key = item.first;
        auto val = item.second;
        result += str(boost::format("%s = 0x%x\n") % key % val);
    }
    result += "\n\n";

    // print all the resources
    for (auto item: this->devs) {
        result += str(boost::format("resource fd_%s[fd]\n") % item);
    }
    result += "\n\n";

    // print all the structures 
    for (auto item: this->StructMap) {
        auto structName = item.first;
        auto structVec = item.second;
        result += str(boost::format("%s {\n") % structName);
        for (auto field: *structVec) {
            auto fieldName = field.first;
            auto fieldType = field.second;
            result += str(boost::format("\t%s\t%s\n") % fieldName % fieldType);
        }
        result += "}\n\n";
    }

    result += "\n\n";

    // print all the syscalls
    for (auto syscall: this->Syscalls) {
        result += syscall->serialize() + "\n";
    }
    
    return result;
}
