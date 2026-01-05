# iometa

Extracts C++ class runtime information from an arm64 Darwin kernel.  
Class names, inheritance, vtables, methods, etc.

### Building

Besides the main `iometa` binary, the helper tools `mangle` and `pac` can be built.  
On macOS, everything should build out of the box:

    make        # Builds iometa
    make all    # Same as above
    make aux    # Builds mangle and pac

Linux is now supported via the `IOCFBootleg` submodule, but you will need to build with `clang` and you need to have `libc++abi` from LLVM installed.

    git submodule update --init
    CC=clang make

### Usage

Run with no arguments for exhaustive help.

Examples:

    iometa kernel                                   # List all classes
    iometa -a kernel                                # List all classes with more info
    iometa -A kernel                                # List all classes and print all virtual methods
    iometa -AC IOSurfaceRoot kernel                 # Print info and methods of class IOSurfaceRoot
    iometa -Ae IOSurfaceRoot kernel                 # Print info and methods of all classes extending IOSurfaceRoot
    iometa -Ap IOSurfaceRoot kernel                 # Print info and methods of all classes from which IOSurfaceRoot inherits
    iometa -AB com.apple.iokit.IOSurface kernel     # Print info and methods of classes from kext com.apple.iokit.IOSurface
    iometa -M kernel >map.txt                       # Create symbol map
    iometa -A kernel map.txt                        # List all classes with virtual methods, and resymbolicate them
    iometa -R kernel map.txt                        # Generate a radare2 script file with all symbols

For more info on symbol maps and resymbolication, see [`/sym`](https://github.com/Siguza/iometa/tree/master/sym).

The helper tools `mangle` and `pac` each take a single command line argument.  
`mangle` turns a source-level C++ function signature into a mangled symbol (the opposite of `c++filt`).  
`pac` computes the 16-bit PAC for a mangled symbol name.

### License

[MPL2](https://github.com/Siguza/iometa/blob/master/LICENSE) with Exhibit B.
