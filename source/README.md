# Syzdirect

## Directory structure

```
├── llvm-project-new	// Customized llvm
│   ├── ......
├── README.md
└── syzdirect
    ├── bigconfig	// Default config
    ├── kcov.diff	// Kcov patch for source code 
    ├── Runner		// Runner scripts
    ├── syzdirect_function_model
    ├── syzdirect_fuzzer
    ├── syzdirect_kernel_analysis
    └── template_config		// template fuzzing config
```

Directory structure is presented as above. Syzdirect has customized llvm for instrumentation, based on version 13.0.1(commit 75e33f71c2dae584b13a7d1186ae0a038ba98838). All main tools are located at `syzdirect/syzdirect_*`:

- `syzdirect_function_model` analyzes the kernel interfaces.
- `syzdirect_kernel_analysis` analyzes the target points.
- `syzdirect_fuzzer ` is the customized fuzzer, based on syzkaller commit a371c43c33b6f901421f93b655442363c072d251.

```
Since our script will automatically compile all tools (i.e., static analyzer, fuzzer and customized llvm), we recommend that users do not change the directory structure to ensure correct compilation.

If users want to change the directory structure, they need to modify the paths defined in syzdirect/Runner/Config.py
```

## Quick Start

Here are steps for quick usage:

1. [Prepare fileimage](#prepare-fileimage)
2. [Dataset construction](#dataset-construction)
3. `cd syzdirect/Runner && python Main.py prepare_for_manual_instrument`
4. [Manual instrument](#manual-instrument)
5. Perform stages in [Other stages](#other-stages): `cd syzdirect/Runner && python Main.py prepare_kernel_bitcode analyze_kernel_syscall extract_syscall_entry instrument_kernel_with_distance fuzz`

## Usage

Runner scripts are placed under `syzdirect/Runner/`:

```
syzdirect/Runner/
├── Compilation.py	// Everything about compiling the kernel
├── Config.py		// Global variables, helpers and preparations
├── dataset.xlsx	// Dataset input file
├── Fuzz.py		// Launch fuzzer
├── Main.py		// Main script
└── SyscallAnalyze	// Analyze the kernel and target point
    ├── InterfaceGenerate.py
    ├── SyscallAnalyze.py
    └── TargetPointAnalyze.py
```

The main functions of the script is shown in the comment above. To simplify, users are expected to perform following steps.

### Prepare fileimage

Users must prepare a fileimage template for fuzzing. It's recommended to [create-image.sh](syzdirect/syzdirect_fuzzer/tools/create-image.sh) provided by syzkaller.

When fileimage is ready, please fill out the path of the fileimage and public key of the fileimage into the variable `CleanImageTemplatePath,KeyPath`  at the end of `syzdirect/Runner/Config.py -> PreparePathVariables() `.

```
############### SET BY USER
    global CleanImageTemplatePath,KeyPath
    CleanImageTemplatePath=""
    KeyPath=""
    assert os.path.exists(CleanImageTemplatePath), "Please offer clean image path"
    assert os.path.exists(KeyPath), "Please offer key path"
```

### Dataset construction

Syzdirect accepts dataset in the form of excel, please refer to the [template](syzdirect/Runner/dataset.xlsx) for detailed information.

For every case with `idx`, multiple intrumentation points with distinctive `xidx` are supported, both `idx` and `xidx` should be integer. The case index `idx `and designated testing kernel commit `kernel commit` is necessary. Other optional information includes:

- `repro bug title`: If not left blank, the fuzzer would stop as soon as the kernel crashes with the same title
- `recommend syscall`: If not left blank, Syzdirect would takes it into account during entry extraction for better improvement. Note that the recommend syscall *should not* include `$`
- `config path`: If not left blank, compile the kernel using the config in the path specified. Default set to the [bigconfig given](syzdirect/bigconfig).

### General usage of runner scripts

Before any other concrete steps, let's first take a look at the usage of runner scripts. Users are expected to **read the below usage information carefully** before running.

```bash
$ python Main.py -h
usage: Main.py [-h] [-WorkdirPrefix WORKDIRPREFIX] [-dataset DATASET_FILE] [-j J] [-fuzz-rounds RUN_ROUNDS] [-uptime UPTIME]
               [-linux-repo-template LINUX_TEMPLATE]
		[prepare_for_manual_instrument/prepare_kernel_bitcode/analyze_kernel_syscall/extract_syscall_entry/instrument_kernel_with_distance/fuzz]
...... 

This is the runner script for Syzdirect.

positional arguments:
  prepare_for_manual_instrument/prepare_kernel_bitcode/analyze_kernel_syscall/extract_syscall_entry/instrument_kernel_with_distance/fuzz
                        actions to be chose from

optional arguments:
  -h, --help            show this help message and exit
  -WorkdirPrefix WORKDIRPREFIX
                        working directory root, default set to cwd/workdir
  -dataset DATASET_FILE
                        input dataset for datapoints, default set to ${WorkdirPrefix}/dataset.xlsx
  -j J                  cpu num to use
  -fuzz-rounds RUN_ROUNDS
                        run rounds for every case
  -uptime UPTIME        fuzzing timeout(hours) for every case, default set to 24
  -linux-repo-template LINUX_TEMPLATE
                        linux repository template can also be given to save time cloning Linux repository
```

*Note that, multiple actions performed in one command is supported.*

Here's an example:

 `python Main.py instrument_kernel_distance fuzz -j 10 -uptime 48 -fuzz-rounds 5 -WorkdirPrefix -dataset /path/to/some_dataset.xlsx`  means running two stage of  `instrument_kernel_distance` and `fuzz` over cases specified in `path/to/some_dataset.xlsx` , adding   `-j10` during every compilation, fuzzing 5 rounds every case with fuzzing timeout as 48 hours.

### Executing stages

Syzdirect normally goes through six stages.

#### Manual instrumentation

- Stage 1  `prepare_for_manual_instrument`  clones linux repositories for every case `idx` and try to apply [kcov patch](syzdirect/kcov.diff).
- Users are expected to

  - apply kcov patch manually if fails.
  - instrument the kernel
    - Insert `kcov_mark_block(xidx);` adjacent to the target point of your choice, it is expected to be in the same basicblock with the target point.  `xidx` is expected to be a distinctive integer in arbitrary Linux repository, meaning there **should not** be two `kcov_mark_block(x)` of arbitrary `x` in one repository.
    - Insert `#include <linux/kcov.h>` at the beginning of the file.

#### Other Stages

- Stage 2:  `prepare_kernel_bitcode`

  - compile source code into bitcode for later analyzes per case `idx`
- Stage 3: `analyze_kernel_syscall`

  - analyze the kernel interfaces per case `idx`
- Stage 4:  `extract_syscall_entry`

  - analyze target points, entract syscall entry and calculate distance per case `idx` per `xidx`
  - troubleshooting
    - When this stage fails and the function target point resides in is inlined, manual inspection is expected. Please fill out multi-points file correctly according to the instruction given by the runner scripts, then rerun from this stage.
    - Manual inspection of `workdir/fuzzinps/*` is also recommended to filter some FP.
- Stage 5: `instrument_kernel_with_distance`

  - instrument kernel with distance calculated in the previous stage per case `idx` per `xidx`
- Stage 6:  `fuzz`

  - fuzzing the instrumented kernel with extracted syscall entry per case `idx` per `xidx`
