# fuse-fuzzer
A simple libprotobuf-mutator based fuzzing grammar for a FUSE target

## Structure

You'll want to define two libraries: 
- fuzzing target (we call ours `example-fuse-lib`)
- coverage report target (we call ours `example-fuse-lib-cov`)

These libraries are linked against `harness` and `harness-cov`. In the harness you can provide boilerplate code
to set up the target via the `SetupFS` and `TeardownFS` functions. You'll also need to declare a 
`struct fuse_operations ops`.

The harnesses are then linked to `fuzzer` and `fuzzer-cov`, which contain the actual libfuzzer `main` to execute.

See `CMakelists.txt` and the rest of the source code for more details.

## Usage

This repo is mostly a reference. You'll want to copy/modify it for your own project. It certainly won't build as-is.

If you're having trouble building or linking, I suggest starting with
[a bare-bones setup](https://github.com/n-wach/fuzzing-with-cmake).

### Fuzzing

You run the `fuzzer` executable to fuzz your target. Pass a corpus directory as the first argument. I also
suggest passing `-workers=8 -jobs=8` (replacing 8 with what makes sense for your system) to speed things up.

### Debugging

The fuzzer will crash when it encounters a bug (ASAN violation or otherwise). This will produce a crash report
containing the raw protobuf input. To view it in a human-readable format, or to run it in a debugger, you can
run `fuzzer` with the `TESTCASE` environment variable set to the path to the crash report.

### Coverage

Once you have a corpus of inputs that exercise your target, you can run `fuzzer-cov` to generate a coverage report.
Pass the corpus directory as the first argument, and pass `-runs=0` to only run the corpus tests. The coverage report
will be saved to `default.profdata`, which you can convert to a nice HTML report using the following commands:

```bash
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov show --format=html -output-dir=report -instr-profile=default.profdata ./build/fuzz/fuzzer-cov
```

## Other points

There are some missing syscalls, and a few limitations to what is passed to various syscalls. You can still get 
high coverage, just beware. 

Of course PRs with fixes/improvements are welcome. An easy improvement would be to add enums for various flags,
which are OR'd together in the fuzzer. This would improve readability and may reduce search space.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
