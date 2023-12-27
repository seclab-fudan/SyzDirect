import Levenshtein
from tqdm import tqdm
import time

class Argument:
    def __init__(self, type, value, and_value = 0):
        self.type = type
        self.value = tuple(value)
        self.and_value = and_value

    def __hash__(self):
        return hash((self.type, self.value, self.and_value))

    def __eq__(self, other):
        return (self.type, self.value, self.and_value) == (other.type, other.value, other.and_value)

class Device:
    def __init__(self, type, value):
        self.type = type # 'device', 'socket'
        self.value = value

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value
    
    def __hash__(self):
        return hash((self.type, self.value))

    def __str__(self) -> str:
        s = "<" + self.type + " " 
        for v in self.value:
            s += str(v) + " "
        s += ">"
        return s

class Packet:
    def __init__(self, type, name, value):
        self.type = type
        self.name = name
        self.value = tuple(value)

    def __hash__(self):
        return hash((self.type, self.name, self.value))

    def __eq__(self, other):
        return (self.type, self.name, self.value) == (other.type, other.name, other.value)

class Syscall:
    def __init__(self, syscall, variant):
        self.syscall = syscall
        self.variant = variant
        self.args = []

    def __hash__(self):
        return hash((self.syscall, self.variant, self.args))

    def __eq__(self, other):
        if (self.syscall, self.variant, len(self.args)) == (other.syscall, other.variant, len(other.args)):
            for a1, b1 in zip(self.args, other.args):
                if a1 != b1:
                    return False 
            return True 
        return False

def parse_syzkaller_signature(filename):
    res = []
    with open(filename, 'r') as f:
        for line in f.readlines():
            data = line.strip().split("|")
            syscall_name = data[0]
            if ('$' in syscall_name):
                syscall, variant = syscall_name.split('$')
            else:
                syscall = syscall_name
                variant = None
            syscall_obj = Syscall(syscall, variant)
            for arg in data[1:]:
                if (arg != ''):
                    arg_type = arg[0]
                    arg_val = arg[2:-1].split(" ")
                    if (arg_type == 'C'):
                        if ('&' in arg[2:-1]): 
                            # print(arg)
                            val, and_val = arg[2:-1].split('&')
                            val = int(val)
                            and_val = int(and_val)
                            syscall_obj.args.append(Argument(arg_type, [val], and_val))
                        else:
                            for i in range(len(arg_val)):
                                if (arg_val[i] != ''):
                                    arg_val[i] = int(arg_val[i])
                                else:
                                    arg_val = []
                            syscall_obj.args.append(Argument(arg_type, arg_val))
                    elif (arg_type == 'S'):
                        for i in range(len(arg_val)):
                            if (arg_val[i] != ''):
                                arg_val[i] = arg_val[i]
                            else:
                                arg_val = []
                        syscall_obj.args.append(Argument(arg_type, arg_val))
                    elif (arg_type == 'P'):
                        packet_type, packet_val = arg[2:-2].split("]")
                        packet_type = packet_type[2:]
                        packet_val = packet_val[2:]
                        vals = []
                        if packet_val != "" :
                            for x in packet_val.split(" "):
                                if x != "":
                                    vals.append(int(x))
                        syscall_obj.args.append(Packet("P", packet_type, vals))
                    else:
                        arg_res_val = []
                        #if 'socket-' in arg[2:-1]: # socket
                        for argx in arg_val:
                            if 'socket-' in argx:
                                _, family, typ, proto = argx.split('-')
                                family = family[1:-1].split(",")
                                typ = typ[1:-1].split(",")
                                proto = proto[1:-1].split(",")
                                for x in family:
                                    for y in typ:
                                        for z in proto:
                                            if (x == ''):
                                                x = 0
                                            if (y == ''):
                                                y = 0
                                            if (z == ''):
                                                z = 0
                                            tmp = Device('socket', (int(x), int(y), int(z)))
                                            if tmp not in arg_res_val:
                                                arg_res_val.append(tmp)
                            else: 
                                x = argx
                                if (x != ''):
                                    if (x.startswith("/dev/bus/usb/")):
                                        x = "usb_device"
                                    elif (x.startswith("/selinux/")):
                                        x = "securityfs"
                                    else:
                                        if ('/' in x):
                                            x = x.split('/')[-1]
                                        if ('%d' in x):
                                            x = x.replace('%d', '0')
                                    tmp = Device('device', x)
                                    if tmp not in arg_res_val:
                                        arg_res_val.append(tmp)
                        syscall_obj.args.append(Argument(arg_type, arg_res_val))
                        
            syscall_obj.args = tuple(syscall_obj.args)
            res.append(syscall_obj)
    return res

def parse_kernel_signature(filename):
    res = []
    with open(filename, 'r') as f:
        for line in f:
            mp = {}
            line_split = line.strip().split(" ")
            sig_split = []
            bbidx = -1
            for i, item in enumerate(line_split):
                if item.isdigit() and line_split[i-1][-1] == "]":
                    bbidx = i
                    break
                sig_split.append(item)
            sig_str = " ".join(sig_split)
            if bbidx == -1:
                continue 

            bb_num = int(line_split[bbidx])
            mp["target block info"] = []
            for i in range(bb_num): # bbidx+1/bbidx+2 bbidx+3/bbidx+4 bbidx+5/bbidx+6
                target_function = line_split[1 + 2*i + bbidx]
                target_block_idx = int(line_split[2 + 2*i + bbidx])
                block_sig = target_function + " " + str(target_block_idx)
                mp["target block info"].append(block_sig)
            mp["handler function"] = line_split[-1]
            data = sig_str.strip().split("|")
            syscall_name = data[0]
            if ('$' in syscall_name):
                syscall, variant = syscall_name.split('$')
            else:
                syscall = syscall_name
                variant = None
            syscall_obj = Syscall(syscall, variant)
            for arg in data[1:]:
                if (arg != ''):
                    arg_type = arg[0]
                    arg_val = arg[2:-1].split(" ")
                    if (arg_type == 'C'):
                        for i in range(len(arg_val)):
                            if (arg_val[i] != '' and arg_val[i].isdigit()):
                                arg_val[i] = int(arg_val[i])
                            else:
                                arg_val = []
                        syscall_obj.args.append(Argument(arg_type, arg_val))
                    elif (arg_type == 'S'):
                        for i in range(len(arg_val)):
                            if (arg_val[i] != ''):
                                arg_val[i] = arg_val[i]
                            else:
                                arg_val = []
                        syscall_obj.args.append(Argument(arg_type, arg_val))
                    elif (arg_type == 'P'):
                        packet_type, packet_val = arg[2:-2].split("]")
                        packet_type = packet_type[2:]
                        packet_val = packet_val[2:]
                        vals = []
                        if packet_val != "" :
                            for x in packet_val.split(" "):
                                if x != "":
                                    vals.append(int(x))
                        syscall_obj.args.append(Packet("P", packet_type, vals))
                    else:
                        arg_res_val = []
                        #if 'socket-' in arg[2:-1]: # socket
                        for argx in arg_val:
                            if 'socket-' in argx:
                                _, family, typ, proto = argx.split('-')
                                family = family[1:-1].split(",")
                                typ = typ[1:-1].split(",")
                                proto = proto[1:-1].split(",")
                                for x in family:
                                    for y in typ:
                                        for z in proto:
                                            if (x == ''):
                                                x = 0
                                            if (y == ''):
                                                y = 0
                                            if (z == ''):
                                                z = 0
                                            tmp = Device('socket', (int(x), int(y), int(z)))
                                            if tmp not in arg_res_val:
                                                arg_res_val.append(tmp)
                            else: 
                                x = argx
                                if (x != ''):
                                    if ('/' in x):
                                        x = x.split('/')[-1]
                                    if ('%d' in x):
                                        x = x.replace('%d', '0')
                                    tmp = Device('device', x)
                                    if tmp not in arg_res_val:
                                        arg_res_val.append(tmp)
                        syscall_obj.args.append(Argument(arg_type, arg_res_val))
            syscall_obj.args = tuple(syscall_obj.args)
            mp["syscall obj"] = syscall_obj 
            res.append(mp)
    return res

def cmp_device(kernel_device, syz_device):
    score = 0
    if (kernel_device.type == syz_device.type):
        if (kernel_device.type == 'device'):
            # strict cmp
            # if (device1.value == 'fd' or device2.value == 'fd'):
            #     return 1
            score = Levenshtein.ratio(kernel_device.value, syz_device.value)
            if score < 0.8:
                score = 0
        else:
            if syz_device.value[0] == syz_device.value[1] == syz_device.value[2] == 0:
                return 0.69
            if kernel_device.value[0] ==  syz_device.value[0]: # family 
                score += 0.4
            if kernel_device.value[1] ==  syz_device.value[1]: # type 
                score += 0.3
            if kernel_device.value[2] ==  syz_device.value[2]:
                score += 0.3
    return score

def cmp2(kern_syscall, fuzz_syscall):
    if (kern_syscall.syscall != fuzz_syscall.syscall):
        # print('g 1')
        return 0
    # kern one, fuzz multiple
    score = 0
    all_continue_flag = True
    for (kern_arg, fuzz_arg) in zip(kern_syscall.args, fuzz_syscall.args):
        if (fuzz_arg.type == 'D' and fuzz_arg.value[0].value == 'fd'):
            continue
        if (fuzz_arg.type == 'C' and len(fuzz_arg.value) == 0):
            continue
        all_continue_flag = False
        if (kern_arg.type != fuzz_arg.type):
            return 0
        if (kern_arg.type == 'C'):
            if (len(fuzz_arg.value) == 0):
                continue
            if (len(kern_arg.value) == 0 and len(fuzz_arg.value) != 0):
                # print('g 3')
                return 0
            kern_val = kern_arg.value[0]
            if kern_arg.and_value != 0:
                flag = False
                for x in fuzz_arg.value:
                    if kern_arg.and_value & x == kern_val:
                        flag = True
                        break
                if not flag:
                    return 0
            else:
                if kern_val not in fuzz_arg.value:
                    # print('g 4')
                    return 0
            score += 1
            
        elif (kern_arg.type == 'S'):
            if (len(fuzz_arg.value) == 0):
                continue
            if (len(kern_arg.value) == 0 and len(fuzz_arg.value) != 0):
                # print('g 3')
                return 0
            kern_val = kern_arg.value[0]
            # print(kern_val, fuzz_arg.value)
            if "*" in kern_val:
                assert "*" == kern_val[-1], "just support prefix"
                kern_val = kern_val[:-1]
                found = False
                for v in fuzz_arg.value:
                    if v.startswith(kern_val):
                        found = True 
                        break
                if found == False:
                    return 0
            else:
                if kern_val not in fuzz_arg.value:
                    # print('g 4')
                    return 0
            score += 1

        elif (kern_arg.type == 'P'):
            if (len(fuzz_arg.value) == 0):
                continue
            if (len(kern_arg.value) == 0 and len(fuzz_arg.value) != 0):
                # print('g 3')
                return 0
            if kern_arg.name != fuzz_arg.name:
                # print('g 2')
                return 0
            kern_val = kern_arg.value[0]
            if kern_val not in fuzz_arg.value:
                # print('g 1')
                return 0
            score += 1
        else:
            max_device_score = 0         
            for kern_device in kern_arg.value:
                for fuzz_device in fuzz_arg.value:
                    max_device_score = max(cmp_device(kern_device, fuzz_device), max_device_score)
            if max_device_score < 0.69:
                return 0
            score += max_device_score
            if (len(fuzz_arg.value) > 1):
                score -= 0.01
    if all_continue_flag:
        return 0
    else:
        return score

def MatchSig(syzkaller_signature_file, kernel_signature_file):
    syzkaller_signatures = parse_syzkaller_signature(syzkaller_signature_file)
    kernel_signatures = parse_kernel_signature(kernel_signature_file)

    start_time = time.time()

    kernel_signature_map = {} # kernel syscall: [(kernel_target, kernel_handler) ]
    for kern_syscall_mp in kernel_signatures:
        kern_syscall = kern_syscall_mp["syscall obj"]
        kern_target = kern_syscall_mp["target block info"]
        kern_handler = kern_syscall_mp["handler function"]
        if kern_syscall not in kernel_signature_map:
            kernel_signature_map[kern_syscall] = []
        kernel_signature_map[kern_syscall].append((kern_target, kern_handler))

    exist_syscalls = {}
    kernelCode2syscall = {}

    print(f"kernel sig num: {len(kernel_signatures)}, syzkaller sig num: {len(syzkaller_signatures)}")

    for kern_syscall, kern_items in tqdm(kernel_signature_map.items()):
        shouldAdd = set()
        noneAdd = set()
        for fuzz_syscall in syzkaller_signatures:
            cmp_val = cmp2(kern_syscall, fuzz_syscall)
            if cmp_val != 0:
                last_name = f'{fuzz_syscall.syscall}${fuzz_syscall.variant}'
                shouldAdd.add((last_name, cmp_val))
            else:
                noneAdd.add((kern_syscall.syscall, cmp_val))

        for kern_target, kern_handler in kern_items:
            if kern_handler not in kernelCode2syscall:
                kernelCode2syscall[kern_handler] = {}
            tmpMap = kernelCode2syscall[kern_handler]
            if len(shouldAdd) > 0:
                if "none" not in kern_target:
                    kern_target.append("none")
                for block_sig in kern_target:
                    if block_sig not in tmpMap:
                        tmpMap[block_sig] = set()
                    tmpMap[block_sig].update(shouldAdd)
            if len(noneAdd) > 0:
                if "none" not in tmpMap:
                    tmpMap["none"] = set()
                tmpMap["none"].update(noneAdd)

    newKernelCode2syscall = {}
    for kern_handler, block_sigs in kernelCode2syscall.items():
        if kern_handler not in newKernelCode2syscall:
            newKernelCode2syscall[kern_handler] = {}
        newBlockSigs = newKernelCode2syscall[kern_handler]
        for block_sig, syscall_item_list in block_sigs.items():
            if block_sig == "none":
                newBlockSigs["none"] = syscall_item_list
            else:
                handler2, block_idx = block_sig.split(" ")
                if handler2 == kern_handler:
                    assert block_idx.isdigit(), f"what {block_sig}"
                    if block_idx in newBlockSigs:
                        newBlockSigs[block_idx].update(syscall_item_list)
                    else:
                        newBlockSigs[block_idx] = syscall_item_list
                else:
                    if handler2 not in newKernelCode2syscall: 
                        newKernelCode2syscall[handler2] = {}
                    if block_idx in newKernelCode2syscall[handler2]:
                        newKernelCode2syscall[handler2][block_idx].update(syscall_item_list)
                    else:
                        newKernelCode2syscall[handler2][block_idx] = syscall_item_list
                    
    for kern_handler, block_sigs in newKernelCode2syscall.items():        
        for block_sig, syscall_item_list in block_sigs.items():
            sorted_syscall_item_list = sorted(syscall_item_list, key=lambda x: x[1], reverse=True)
            # pick the highest score syscall
            highest_score = sorted_syscall_item_list[0][1]
            highest_score_syscall_list = []
            for syscall_item in sorted_syscall_item_list:
                if syscall_item[1] == highest_score:
                    highest_score_syscall_list.append(syscall_item[0])
                else:
                    break
            newKernelCode2syscall[kern_handler][block_sig] = highest_score_syscall_list

        # print(kernelCode2syscall)
    end_time = time.time()
    print("time: ", end_time - start_time)
    return newKernelCode2syscall
