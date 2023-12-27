// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// mutates mutates a given program and prints result.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
)

type ArgCtx struct {
	traversedTypes map[prog.Type]bool
	Stop           bool
}

func ForeachField(syscall *prog.Syscall, f func(prog.Type, *ArgCtx)) {
	ctx := &ArgCtx{}
	ctx.Stop = false
	ctx.traversedTypes = make(map[prog.Type]bool, 0)
	if syscall.Ret != nil {
		foreachFieldImpl(syscall.Ret, ctx, f)
	}
	for _, arg := range syscall.Args {
		foreachFieldImpl(arg.Type, ctx, f)
	}
}

var trivialValues map[uint64]bool = map[uint64]bool{
	0:                    true,
	1:                    true,
	0xffffffffffffffff:   true,
	0xffffffff:           true,
	0x10:                 true,
	0x20:                 true,
	0x40:                 true,
	0x80:                 true,
	0x100:                true,
	0x200:                true,
	0x400:                true,
	0x800:                true,
	0x1000:               true,
	0x2000:               true,
	0x4000:               true,
	0x8000:               true,
	0x10000:              true,
	0x20000:              true,
	0x40000:              true,
	0x80000:              true,
	0x100000:             true,
	0x200000:             true,
	0x400000:             true,
	0x800000:             true,
	0x1000000:            true,
	0x2000000:            true,
	0x4000000:            true,
	0x8000000:            true,
	0x10000000:           true,
	0x20000000:           true,
	0x40000000:           true,
	0x80000000:           true,
	18446744073709551516: true, // AT_FDCWD
}

func nonTrivial(val uint64) bool {
	_, ok := trivialValues[val]
	return !ok
}

func foreachFieldImpl(arg prog.Type, ctx *ArgCtx, f func(prog.Type, *ArgCtx)) {
	ctx0 := *ctx
	defer func() { *ctx = ctx0 }()
	// fmt.Printf("%s\n", arg.Name())
	_, ok := ctx.traversedTypes[arg]
	if ok {
		return
	} else {
		ctx.traversedTypes[arg] = true
	}
	f(arg, ctx)
	if ctx.Stop {
		return
	}
	switch arg.(type) {
	// fmt.Printf("\t%v\n", val)
	case *prog.StructType:
		for _, field := range arg.(*prog.StructType).Fields {
			foreachFieldImpl(field.Type, ctx, f)
		}
	case *prog.UnionType:
		for _, field := range arg.(*prog.UnionType).Fields {
			foreachFieldImpl(field.Type, ctx, f)
		}
	case *prog.PtrType:
		foreachFieldImpl(arg.(*prog.PtrType).Elem, ctx, f)
	}
}

func initConstMap(target *prog.Target) {
	target.ConstMap = make(map[string]uint64, len(target.Consts))
	for _, item := range target.Consts {
		target.ConstMap[item.Name] = item.Value
	}
}

var ResourceCtorMap map[*prog.Syscall][]string = make(map[*prog.Syscall][]string, 0)
var ResourceDeviceMap map[*prog.ResourceType][]string = make(map[*prog.ResourceType][]string, 0)

func isCompatibleResource(dst, src []string) bool {
	if len(dst) > len(src) {
		// Destination resource is more specialized, e.g dst=socket, src=fd.
		return false
	}
	if len(src) > len(dst) {
		// Source resource is more specialized, e.g dst=fd, src=socket.
		src = src[:len(dst)]
	}
	for i, k := range dst {
		if k != src[i] {
			return false
		}
	}
	return true
}

func extractResourceDevice(resourceArg *prog.ResourceType, target *prog.Target) []string {
	res, ok := ResourceDeviceMap[resourceArg]
	if ok {
		return res
	}
	res = make([]string, 0)
	if resourceArg.Desc.Name == "fd" {
		// universal resource
		return []string{"fd"}
	}
	if resourceArg.Desc.Name == "sock" {
		return []string{"socket-[0]-[0]-[0]"}
	}

	// fmt.Println(resourceArg.Desc.Kind)
	//resourceArg.
	ctors := resourceArg.Desc.Ctors

	for _, subResource := range target.Resources {
		if isCompatibleResource(resourceArg.Desc.Kind, subResource.Kind) {
			// fmt.Printf("%v %v\n", resourceArg.Desc.Kind, subResource.Kind)
			ctors = append(ctors, subResource.Ctors...)
		}
	}

	for idx := range ctors {
		ctorIdx := ctors[idx].Call
		ctorCall := target.Syscalls[ctorIdx]
		// if ctorCall.Ret == resourceArg {
		if ctorCall.Ret != nil {
			if isCompatibleResource(resourceArg.Desc.Kind, ctorCall.Ret.(*prog.ResourceType).Desc.Kind) {
				// fmt.Printf("\t%v\n", ctorCall.Name)
				resourceFilename := processResourceCtor(ctorCall, target)
				// fmt.Printf("\t%v\n", resourceFilename)
				res = append(res, resourceFilename...)
			}
		}
	}
	if len(res) == 0 {
		return []string{resourceArg.TypeName}
	}
	return res
}

func processIntValue(arg prog.Field) []uint64 {
	switch arg.Type.(type) {
	case *prog.FlagsType:
		return arg.Type.(*prog.FlagsType).Vals
	case *prog.ConstType:
		return []uint64{arg.Type.(*prog.ConstType).Val}
	default:
		return []uint64{0}
		// panic("unknown type")
	}
}

func processResourceCtor(ctorCall *prog.Syscall, target *prog.Target) []string {
	res, ok := ResourceCtorMap[ctorCall]
	if ok {
		return res
	}
	res = nil
	if strings.HasPrefix(ctorCall.Name, "openat") {
		// openat
		filenameArg := ctorCall.Args[1]
		filenameStringType := filenameArg.Type.(*prog.PtrType).Elem.(*prog.BufferType)
		res = make([]string, 0)
		for _, val := range filenameStringType.Values {
			if strings.HasSuffix(val, "\x00") {
				res = append(res, val[:len(val)-1])
			} else {
				res = append(res, val)
			}
		}
	} else if strings.HasPrefix(ctorCall.Name, "syz_open_dev$") {
		// syz_open_dev

		filenameArg := ctorCall.Args[0]
		switch filenameArg.Type.(type) {
		case *prog.PtrType:
			filenameStringType := filenameArg.Type.(*prog.PtrType).Elem.(*prog.BufferType)
			// fmt.Printf("%v %v\n", ctorCall.Name, filenameStringType.Values)
			res = make([]string, 0)
			for _, val := range filenameStringType.Values {
				if strings.HasSuffix(val, "\x00") {
					res = append(res, val[:len(val)-1])
				} else {
					res = append(res, val)
				}
			}
		case *prog.ConstType:
			// block or char device
			deviceType := ctorCall.Args[0].Type.(*prog.ConstType).Val
			deviceTypeStr := ""
			if deviceType == 0xc {
				deviceTypeStr = "char"
			} else if deviceType == 0xb {
				deviceTypeStr = "block"
			}
			major := ctorCall.Args[1].Type.(*prog.ConstType).Val
			return []string{fmt.Sprintf("/dev/%s/%d", deviceTypeStr, major)}
		default:
			fmt.Printf("?? %v %v\n", ctorCall.Name, filenameArg.Type)
			return nil
		}
	} else if strings.HasPrefix(ctorCall.Name, "ioctl$") {
		// generated by other ioctl
		ioctlResArg := ctorCall.Args[0].Type.(*prog.ResourceType)
		if ioctlResArg != ctorCall.Ret.(*prog.ResourceType) {
			return extractResourceDevice(ioctlResArg, target)
		}
	} else if strings.HasPrefix(ctorCall.Name, "socket$") || strings.HasPrefix(ctorCall.Name, "syz_init_net_socket$") || strings.HasPrefix(ctorCall.Name, "socketpair$") {
		// socket
		// family
		familyVal := processIntValue(ctorCall.Args[0])
		familyjson, err := json.Marshal(familyVal)
		if err != nil {
			panic(err)
		}
		familyStr := string(familyjson)
		// type
		typeVal := processIntValue(ctorCall.Args[1])
		typejson, err := json.Marshal(typeVal)
		if err != nil {
			panic(err)
		}
		typeStr := string(typejson)
		// protocol
		protocolVal := processIntValue(ctorCall.Args[2])
		protocoljson, err := json.Marshal(protocolVal)
		if err != nil {
			panic(err)
		}
		protocolStr := string(protocoljson)
		res = []string{fmt.Sprintf("socket-%s-%s-%s", familyStr, typeStr, protocolStr)}
	} else {
		// fmt.Printf("G!\t%s\n", ctorCall.Name)
		return nil
	}
	ResourceCtorMap[ctorCall] = res
	return res
}

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	initConstMap(target)
	// typeMap := make(map[string][]*prog.Syscall, 0)
	for idx := range target.Syscalls {
		syscall := target.Syscalls[idx]
		name := syscall.Name

		// if syscall.Ret != nil {
		// 	switch syscall.Ret.(type) {
		// 	case *prog.ResourceType:
		// 		// fmt.Printf("%v\n", syscall.Name)
		// 		if strings.Contains(name, "openat") || strings.Contains(name, "syz_open_dev") || strings.Contains(name, "ioctl") {
		// 			typeMap["device"] = append(typeMap["device"], syscall)
		// 		} else if strings.Contains(name, "socket") || strings.Contains(name, "accept") || strings.Contains(name, "syz_genetlink_get_family_id") {
		// 			typeMap["socket"] = append(typeMap["socket"], syscall)
		// 		} else if strings.Contains(name, "syz_mount_image") {
		// 			typeMap["fs_image"] = append(typeMap["fs_image"], syscall)
		// 		} else if strings.Contains(name, "bpf$") {
		// 			typeMap["bpf"] = append(typeMap["bpf"], syscall)
		// 		} else if strings.Contains(name, "usb") {
		// 			typeMap["usb"] = append(typeMap["usb"], syscall)
		// 		} else {
		// 			typeMap["misc"] = append(typeMap["misc"], syscall)
		// 		}
		// 	}
		// }

		// continue

		if strings.Contains(name, "syz_") || strings.Contains(name, "openat") || strings.Contains(name, "socket") || strings.Contains(name, "mount") {
			continue
		}
		if strings.Contains(name, "$") {
			fmt.Printf("%s", name)
			strs := make([]string, 0)
			constants := make([]uint64, 0)
			resourceStrs := make([]string, 0)

			for _, arg := range syscall.Args {
				// fmt.Printf("\tArgument %d:\n", idx)
				switch arg.Type.(type) {
				case *prog.ResourceType:
					resourceStrs = extractResourceDevice(arg.Type.(*prog.ResourceType), target)
					fmt.Printf("|D%v", resourceStrs)
					// strs = append(strs, resourceArg.Name())
				case *prog.ConstType:
					constantVal := arg.Type.(*prog.ConstType).Val
					fmt.Printf("|C[%v]", constantVal)
				case *prog.FlagsType:
					flagsVal := arg.Type.(*prog.FlagsType).Vals
					fmt.Printf("|C%v", flagsVal)
				// case *prog.PtrType:
				// goto
				default:
					argStr := arg.String()
					argStr = strings.Replace(argStr, "[", " ", -1)
					argStr = strings.Replace(argStr, "]", " ", -1)
					argStr = strings.Replace(argStr, ",", " ", -1)
					argStr = strings.Replace(argStr, ".", " ", -1)
					argStr = strings.Replace(argStr, "  ", " ", -1)
					argStrList := strings.Split(argStr, " ")
					// fmt.Printf("\t\t%v\n", argStrList)
					constants = make([]uint64, 0)
					for _, str := range argStrList {
						val, ok := target.ConstMap[str]
						if ok {
							constants = append(constants, val)
						}
					}
					// constantsjson, err := json.Marshal(constants)
					// if err != nil {
					// 	panic(err)
					// }
					// constantsStr := string(constantsjson)
					fmt.Printf("|C%v", constants)
				}
			}
			fmt.Printf("\n")
			// ForeachField(syscall, func(arg prog.Type, ctx *ArgCtx) {
			// 	// fmt.Printf("\t%v\n", arg.Name())
			// 	switch arg.(type) {
			// 	case *prog.ResourceType:
			// 		resourceArg := arg.(*prog.ResourceType)
			// 		ctors := resourceArg.Desc.Ctors
			// 		for idx := range ctors {
			// 			ctorIdx := ctors[idx].Call
			// 			ctorCall := target.Syscalls[ctorIdx]
			// 			if ctorCall.Ret == arg {
			// 				// fmt.Printf("\t%v\n", ctorCall.Name)
			// 				ForeachField(ctorCall, func(innerArg prog.Type, innerCtx *ArgCtx) {
			// 					// fmt.Printf("\t\t%v\n", innerArg.Name())
			// 					switch innerArg.(type) {
			// 					case *prog.BufferType:
			// 						bufferArg := innerArg.(*prog.BufferType)
			// 						if bufferArg.Kind == prog.BufferString {
			// 							resourceStrs = append(resourceStrs, bufferArg.Values...)
			// 						}
			// 					}
			// 				})
			// 			}
			// 		}
			// 		strs = append(strs, resourceArg.Name())
			// 		// fmt.Printf("\t%s\n", resourceArg.Name())
			// 	case *prog.ConstType:
			// 		constArg := arg.(*prog.ConstType)
			// 		val := constArg.Val
			// 		if nonTrivial(val) {
			// 			// fmt.Printf("%s\n", arg.String())
			// 			constants = append(constants, val)
			// 		}
			// 	case *prog.FlagsType:
			// 		for _, val := range arg.(*prog.FlagsType).Vals {
			// 			if nonTrivial(val) {
			// 				constants = append(constants, val)
			// 			}
			// 		}
			// 	}
			// })
			// for _, resourceStr := range resourceStrs {
			// 	fmt.Printf("\t%s\n", resourceStr)
			// }
			// for _, str := range strs {
			// 	fmt.Printf("\t%s\n", str)
			// }
			// for _, val := range constants {
			// 	fmt.Printf("\t%v\n", val)
			// }

			signature := name + ":"
			for _, str := range strs {
				signature += "str|" + str + ":"
			}
			for _, val := range constants {
				signature += "const|" + fmt.Sprintf("%d", val) + ":"
			}
			// fmt.Println(signature)
			// fmt.Printf("%v\n", target.ConstMap["ABS_CNT"])

		}

	}
	// for idx, item := range typeMap {
	// 	fmt.Printf("%v: \n", idx)
	// 	for _, val := range item {
	// 		fmt.Printf("\t%v,", val.Name)
	// 		for idx := 1; idx < 6; idx++ {
	// 			if idx < len(val.Args) {
	// 				arg := val.Args[idx]
	// 				switch arg.Type.(type) {
	// 				case *prog.PtrType:
	// 					switch arg.Type.(*prog.PtrType).Elem.(type) {
	// 					case *prog.BufferType:
	// 						filenameStringType := arg.Type.(*prog.PtrType).Elem.(*prog.BufferType)
	// 						fmt.Printf("\"")
	// 						for _, val := range filenameStringType.Values {
	// 							if strings.HasSuffix(val, "\x00") {
	// 								fmt.Printf("%s,", val[:len(val)-1])
	// 							} else {
	// 								fmt.Printf("%s,", val)
	// 							}
	// 						}
	// 						fmt.Printf("\",")
	// 					default:
	// 						fmt.Printf("\"%s\",", arg.String())
	// 					}
	// 				case *prog.ConstType:
	// 					fmt.Printf("\"0x%x\",", arg.Type.(*prog.ConstType).Val)
	// 				default:
	// 					fmt.Printf("\"%s\",", arg.String())
	// 				}

	// 			} else {
	// 				fmt.Printf("-,")
	// 			}
	// 		}
	// 		fmt.Printf("\"%s\",", val.Ret.String())
	// 		fmt.Printf("\n")
	// 	}
	// }
}
