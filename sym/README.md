# IOKit resymbolication

### What is this?

These are symbol maps. `iometa` by itself can find the names of classes, but the ones of methods are simply not preserved in release kernels. So these symbol maps are essentially huge lookup tables for virtual method names, which can be passed to `iometa` as last argument to recover most symbols.  
Symbol maps take the following form:

    OSObject                    # This is a comment
    - ~OSObject()
    - ~OSObject()
    - release(int) const
    - getRetainCount() const
    - retain() const
    - release() const
    - serialize(OSSerialize*) const
    - getMetaClass() const
    - OSMetaClassBase::isEqualTo(OSMetaClassBase const*) const
    - taggedRetain(void const*) const
    - taggedRelease(void const*) const
    - taggedRelease(void const*, int) const
    - init()
    - free()
    OSString
    - initWithString(OSString const*)
    - initWithCString(char const*)
    - initWithCStringNoCopy(char const*)
    - getLength() const
    - getChar(unsigned int) const
    - setChar(char, unsigned int)
    - getCStringNoCopy() const
    - isEqualTo(OSString const*) const
    - isEqualTo(char const*) const
    - isEqualTo(OSData const*) const
    OSSymbol
    - isEqualTo(OSSymbol const*) const

Basic class and method names should be fairly obvious, but a few things should be noted:

1.  Comments can be started with `#` and extend to the end of the line. These are entirely ignored by parsing, so `iometa -M` will also strip them out.
2.  The class inheritance is _not_ reflected in symbol maps, and is only parsed from kernels. However, inherited methods are not listed in child classes (e.g. see how `OSString` does not list `init()`, `free()`, etc., because they are inherited from `OSObject`).
3.  Destructors:

        - ~OSObject()
        - ~OSObject()

    Destructors of the form `~ClassName()` (and in theory constructors of the form `ClassName()`, but iOS doesn't have them in vtabs) are detected, and will have their name replaced by the class name in child classes.
4.  Class inaccuracy:

        - OSMetaClassBase::isEqualTo(OSMetaClassBase const*) const

    The recorded class name for a method can be overridden by prepending `ClassName::` in front of the method name. This is sometimes necessary in cases where XNU's OSMetaClass RTTI system doesn't accurately reflect the actual C++ inheritance structures.
5.  Empty placeholders. Those are not shown above, but if a line contains nothing but a dash, it denoted that there exists a virtual method in that place, but its name and arguments are unknown. Example would be:

        OSString
        - initWithString(OSString const*)
        -
        - initWithCStringNoCopy(char const*)

### Where did these symbols come from?

With the iOS 12.0 beta 1, Apple introduced a new kernelcache format for some devices where kexts were no longer just prelinked like before, but effectively directly compiled in. This new format allows for many optimisations, and had as a consequence the complete removal of _all_ symbols (previously we had some 4000-and-something symbols left). However, on the very first beta, Apple accidentally shipped kernels for A7 iPads and A8 iPhones with **all symbols left in, more than 90'000 in total!** Out of all of those, about 25'000 are symbols corresponding to virtual methods, and the original symbol maps were generated from that with `iometa -M`.  
Those are the [`A7-dense.txt`](https://github.com/Siguza/iometa/blob/master/sym/12.0b1/A7-dense.txt) and [`A8-dense.txt`](https://github.com/Siguza/iometa/blob/master/sym/12.0b1/A8-dense.txt) files you'll find in the [`12.0b1`](https://github.com/Siguza/iometa/tree/master/sym/12.0b1) folder, but you'll notice that those aren't the only symbol maps in there. I've tried my best to match those symbols against the kernelcaches of all other devices, and for those methods that got no match, to recover their names and argument list from panic strings or debugging information left in the kernels - with not overwhelming, but I think reasonable results. At the time of writing, I've also ported these symbol maps forward in time to the iOS 12 beta 2 (which additionally switched the iPhone 5s and iPod touch 6G to the new kernelcache format) and iOS 12.0 Golden Master (which was the first version to include A12 devices).

### Where are we going from here?

I'm obviously gonna continue to ports these symbols onto newer versions, because that's the entire point of keeping these maps. Now, since I don't have any of the highly sophisticated binary matching algorithms I wish I did, chances are I'm gonna miss a ton of stuff like:

- Methods getting swapped around or replaced by others, but with the number of methods per class staying the same
- Methods changing the amount and types of arguments
- New methods whose names are mentioned somewhere in the binary where I happen to not look for it

So I would greatly appreciate if you could [point out](https://github.com/Siguza/iometa/issues/new) any kind of error you detect in these maps, as well as any symbol name or argument list that you believe I missed or messed up. In that spirit, I'm also going to document how these lists are organised, how I try and update them to new versions/devices, as well as noteworthy things I've come across while doing so.

Ok, first of all, the symbol maps are organised by device class - A7, A8, etc. Originally I wanted to put all symbols for all devices into a single file, but in attempting to do that my own tool greeted me with warnings like:

> \[WRN\] Symmap entry for AppleBCMWLANBusInterface has 60 methods, vtab has 88.  
> \[WRN\] Symmap entry for AppleBCMWLANCore has 84 methods, vtab has 136.  
> \[WRN\] Symmap entry for AppleBCMWLANBSSBeacon has 61 methods, vtab has 66.  
> \[WRN\] Symmap entry for AppleBCMWLANIO80211APSTAInterface has 88 methods, vtab has 83.  
> \[WRN\] Symmap entry for AppleBCMWLANProximityInterface has 88 methods, vtab has 83.

You can reproduce that by attempting to use an A7 symbol map on an A8 cache or vice versa. Basically different device generations have, under the same name, different classes implementing different methods. So in order to work around that, I gave each generation its own map, since within generations there's at best very little difference. With maps provided on this repo, you should only ever see two kinds of warnings:

> \[WRN\] Symmap entry for \<Class\> has X methods, vtab has 0.  
> \[WRN\] Symmap entry for \<Class\> has X methods, but class has no vtab.

Both are symptoms of the same condition, namely the symbol map holding information on a class when the kernel effectively optimised that class out of existence for that device. And I can live with that.

Then the next split is by kernelcache format. This is `A8-dense.txt` vs `A8-legacy.txt`. The reason these need a split is optimisation, namely abstract classes having been optimised out. The problem arises that when you have a class hierarchy like so:

- Class `A` is a non-abstract base class declaring virtual method `x()`.
- Class `B` is an abstract class inheriting from class `A` and declaring virtual method `y()`.
- Class `C` is a non-abstract class inheriting from class `A` and declaring virtual method `z()`.

Now in the "legacy" kernelcache format, class `B` usually gets its own vtable and everything, and a symbol map would look as following:

    A
    - x()
    B
    - y()
    C
    - z()

In the "dense" kernelcache format however, class `B` will have been mostly optimised out and not get a vtable, which means that no methods for `B` will be recorded, which in turn will make it look like all of `B`'s methods were in fact introduced by `C`:

    A
    - x()
    B
    C
    - y()
    - z()

For one, this makes the two symbol maps inherently incompatible, and for two this is also the reason for the "class override" feature, so that `y()` can be accurately attributed to `B` if we have that knowledge:

    A
    - x()
    B
    C
    - B::y()
    - z()

If you ever end up porting a symbol map for a device class that just switched from legacy to dense kernelcache format, you'll no doubt notice that this is the biggest change you'll have to make: moving methods of abstract classes into their child classes. The second biggest will probably be deleting all the stuff that has been optimised out now. ;P

With that sorted out, here's how I actually go at updating symbol maps:

1.  I simply run `iometa -M kernel old.txt >/tmp/new.txt` against a kernel, using the symbol map from the last version (or in the case of a new device, the closest existing device I have a map for). Usually that will throw a bunch of warnings and turn between a few hundred and a few thousand functions into `fn_0x...`, but the vast majority will go through just fine, and I blindly assume those to still be accurate.  
    I do this for each device belonging to a generation, collect all newly generated symbol maps, and then merge them back into one with [my ugly script](https://github.com/Siguza/iometa/blob/master/sym/symmerge) (this is necessary in order to keep classes that only e.g. either iPads _or_ iPhones have, but yet get rid of classes that were actually removed).
2.  I go through all classes with `fn_0x...` methods and, before even looking at assembly, compare a bunch of vtables between this and the last generation. Of particular interest are "pure virtual" methods (i.e. those showing up red in `iometa` output) as well as those overridden in child classes:  
    <table>
        <tr>
            <td>![vtab-1a](https://user-images.githubusercontent.com/1659374/56452914-19e16b80-6339-11e9-9eaa-276ba67880be.png)</td>
            <td>![vtab-1b](https://user-images.githubusercontent.com/1659374/56452918-367da380-6339-11e9-9583-f8c960fc9368.png)</td>
        </tr>
        <tr>
            <td>![vtab-2a](https://user-images.githubusercontent.com/1659374/56452933-662cab80-6339-11e9-8886-47cfa2df908c.png)</td>
            <td>![vtab-2b](https://user-images.githubusercontent.com/1659374/56452934-6e84e680-6339-11e9-9ca2-a5114caa8871.png)</td>
        </tr>
        <tr>
            <td>![vtab-3a](https://user-images.githubusercontent.com/1659374/56452937-76dd2180-6339-11e9-8631-d20272be61a6.png)</td>
            <td>![vtab-3b](https://user-images.githubusercontent.com/1659374/56452939-7e9cc600-6339-11e9-81ae-cb1db510ea06.png)</td>
        </tr>
    </table>
    You can tell a damn lot from just those patterns.
3.  When you've finally exhausted pattern matching, it's time to dive into assembly and find out which of those methods in between were added or removed. And if methods were added and we're somewhat lucky, it will also pass its own name and/or signature to some logging function. Now if it's just the name without signature, recovering the argument list can be challenge, so here are a few tricks:
    -   When arguments are either stored to memory or passed to printf-like functions, that usually gives away their exact size. Otherwise you only get the information whether they're 32- or 64bit.
    -   For 32bit values I usually assume `unsigned int` unless a comparison instruction suggests signed-ness, or if it's only tested for zero vs non-zero, in which case I assume `bool`.
    -   For 64bit values my base assumption is `void*` unless something clearly indicates a size, magic constant, bitmask, or similar, in which case I go for `unsigned long long`.
    -   For pointer types it should be fairly obvious what types they have, with probably the most complicated case being C++ objects. This is an area where A12 devices with PAC come in _really_ handy. A virtual method call with PAC looks something like this:

            0xfffffff00809f4e8      080040f9       ldr x8, [x0]
            0xfffffff00809f4ec      e83bc1da       autdza x8
            0xfffffff00809f4f0      09e11691       add x9, x8, 0x5b8
            0xfffffff00809f4f4      08dd42f9       ldr x8, [x8, #1464]
            0xfffffff00809f4f8      6944fdf2       movk x9, 0xea23, lsl #48
            0xfffffff00809f4fc      e10302aa       mov x1, x2
            0xfffffff00809f500      09093fd7       blraa x8, x9

        And this neat little value `0xea23` is the same thing that `iometa -A` displays for each method with `pac=0xNNNN`. In most cases that alone should be unique to a single method, but even when it isn't, that together with the vtable offset (`0x5b8` here) should _definitely_ allow you to uniquely identify the method, and with that the minimum type that C++ object is expected to conform to.  
    -   For the absolute hardest cases, which are arguments that are either blindly passed through to other functions or simply ignored, the same PAC trick as above can help again, just in reverse this time. By looking up the PAC tag of the current method and searching the kernelcache for all instructions of the form `movk x.*, 0xNNNN, lsl #48`, you should be able to find any last invocation of that method, and thus can look at how the arguments are loaded.

And that's about it. Every now and then you'll come across methods whose names are simply lost (like when the function consists of a single `ret`) or whose arguments are passed around way too long before their type becomes obvious. Just put those down as `void*` and if someone ever goes on to reverse that method/class/kext, they can hit me up once they've figured it out. ;)

### Device/Version Overview

<table>
    <tr>
        <th>Generation</th>
        <th>Devices</th>
        <th>Identifiers</th>
        <th>Models</th>
        <th align="center">New kernelcache format since</th>
    </tr>
    <tr>
        <td rowspan="11" align="center">A7</td>
        <td rowspan="3">iPad Air</td>
        <td>iPad4,1</td>
        <td>J71AP</td>
        <td rowspan="9" align="center">12.0 beta 1</td>
    </tr>
    <tr>
        <td>iPad4,2</td>
        <td>J72AP</td>
    </tr>
    <tr>
        <td>iPad4,3</td>
        <td>J73AP</td>
    </tr>
    <tr>
        <td rowspan="3">iPad mini 2</td>
        <td>iPad4,4</td>
        <td>J85AP</td>
    </tr>
    <tr>
        <td>iPad4,5</td>
        <td>J86AP</td>
    </tr>
    <tr>
        <td>iPad4,6</td>
        <td>J87AP</td>
    </tr>
    <tr>
        <td rowspan="3">iPad mini 3</td>
        <td>iPad4,7</td>
        <td>J85mAP</td>
    </tr>
    <tr>
        <td>iPad4,8</td>
        <td>J86mAP</td>
    </tr>
    <tr>
        <td>iPad4,9</td>
        <td>J87mAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone 5s</td>
        <td>iPhone6,1</td>
        <td>N51AP</td>
        <td rowspan="2" align="center">12.0 beta 2</td>
    </tr>
    <tr>
        <td>iPhone6,2</td>
        <td>N53AP</td>
    </tr>
    <tr>
        <td rowspan="7" align="center">A8</td>
        <td rowspan="2">iPad mini 4</td>
        <td>iPad5,1</td>
        <td>J96AP</td>
        <td rowspan="4" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad5,2</td>
        <td>J97AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Air 2</td>
        <td>iPad5,3</td>
        <td>J81AP</td>
    </tr>
    <tr>
        <td>iPad5,4</td>
        <td>J82AP</td>
    </tr>
    <tr>
        <td>iPhone 6+</td>
        <td>iPhone7,1</td>
        <td>N56AP</td>
        <td rowspan="2" align="center">12.0 beta 1</td>
    </tr>
    <tr>
        <td>iPhone 6</td>
        <td>iPhone7,2</td>
        <td>N61AP</td>
    </tr>
    <tr>
        <td>iPod touch 6G</td>
        <td>iPod7,1</td>
        <td>N102AP</td>
        <td align="center">12.0 beta 2</td>
    </tr>
    <tr>
        <td rowspan="14" align="center">A9</td>
        <td rowspan="2">iPad Pro (9.7in)</td>
        <td>iPad6,3</td>
        <td>J127AP</td>
        <td rowspan="14" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad6,4</td>
        <td>J128AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Pro (12.9in)</td>
        <td>iPad6,7</td>
        <td>J98aAP</td>
    </tr>
    <tr>
        <td>iPad6,8</td>
        <td>J99aAP</td>
    </tr>
    <tr>
        <td rowspan="4">iPad 5</td>
        <td rowspan="2">iPad6,11</td>
        <td>J71sAP</td>
    </tr>
    <tr>
        <td>J71tAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad6,12</td>
        <td>J72sAP</td>
    </tr>
    <tr>
        <td>J72tAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone 6s</td>
        <td rowspan="2">iPhone8,1</td>
        <td>N71AP</td>
    </tr>
    <tr>
        <td>N71mAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone 6s+</td>
        <td rowspan="2">iPhone8,2</td>
        <td>N66AP</td>
    </tr>
    <tr>
        <td>N66mAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone SE</td>
        <td rowspan="2">iPhone8,4</td>
        <td>N69AP</td>
    </tr>
    <tr>
        <td>N69uAP</td>
    </tr>
    <tr>
        <td rowspan="10" align="center">A10</td>
        <td rowspan="2">iPad Pro 2 (12.9in)</td>
        <td>iPad7,1</td>
        <td>J120AP</td>
        <td rowspan="10" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad7,2</td>
        <td>J121AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Pro 2 (10.5in)</td>
        <td>iPad7,3</td>
        <td>J207AP</td>
    </tr>
    <tr>
        <td>iPad7,4</td>
        <td>J208AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad 6</td>
        <td>iPad7,5</td>
        <td>J71bAP</td>
    </tr>
    <tr>
        <td>iPad7,6</td>
        <td>J72bAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone 7</td>
        <td>iPhone9,1</td>
        <td>D10AP</td>
    </tr>
    <tr>
        <td>iPhone9,3</td>
        <td>D101AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone 7+</td>
        <td>iPhone9,2</td>
        <td>D11AP</td>
    </tr>
    <tr>
        <td>iPhone9,4</td>
        <td>D111AP</td>
    </tr>
    <tr>
        <td rowspan="10" align="center">A11</td>
        <td rowspan="4">iPhone 8</td>
        <td rowspan="2">iPhone10,1</td>
        <td>D20AP</td>
        <td rowspan="10" align="center">N/A</td>
    </tr>
    <tr>
        <td>D20AAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone10,4</td>
        <td>D201AP</td>
    </tr>
    <tr>
        <td>D201AAP</td>
    </tr>
    <tr>
        <td rowspan="4">iPhone 8+</td>
        <td rowspan="2">iPhone10,2</td>
        <td>D21AP</td>
    </tr>
    <tr>
        <td>D21AAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone10,5</td>
        <td>D211AP</td>
    </tr>
    <tr>
        <td>D211AAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone X</td>
        <td>iPhone10,3</td>
        <td>D22AP</td>
    </tr>
    <tr>
        <td>iPhone10,6</td>
        <td>D221AP</td>
    </tr>
    <tr>
        <td rowspan="12" align="center">A12</td>
        <td rowspan="4">iPad Pro 3 (11.0in)</td>
        <td>iPad8,1</td>
        <td>J317AP</td>
        <td rowspan="8" align="center">12.1</td>
    </tr>
    <tr>
        <td>iPad8,2</td>
        <td>J317xAP</td>
    </tr>
    <tr>
        <td>iPad8,3</td>
        <td>J318AP</td>
    </tr>
    <tr>
        <td>iPad8,4</td>
        <td>J318xAP</td>
    </tr>
    <tr>
        <td rowspan="4">iPad Pro 3 (12.9in)</td>
        <td>iPad8,5</td>
        <td>J320AP</td>
    </tr>
    <tr>
        <td>iPad8,6</td>
        <td>J320xAP</td>
    </tr>
    <tr>
        <td>iPad8,7</td>
        <td>J321AP</td>
    </tr>
    <tr>
        <td>iPad8,8</td>
        <td>J321xAP</td>
    </tr>
    <tr>
        <td>iPhone XS</td>
        <td>iPhone11,2</td>
        <td>D321AP</td>
        <td rowspan="4" align="center">12.0 GM</td>
    </tr>
    <tr>
        <td rowspan="2">iPhone XS Max</td>
        <td>iPhone11,4</td>
        <td>D331AP</td>
    </tr>
    <tr>
        <td>iPhone11,6</td>
        <td>D331pAP</td>
    </tr>
    <tr>
        <td rowspan="1">iPhone XR</td>
        <td>iPhone11,8</td>
        <td>N841AP</td>
    </tr>
</table>
