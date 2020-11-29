# IOKit resymbolication

### What is this?

These are symbol maps. `iometa` by itself can find the names of classes, but the ones of methods are simply not preserved in (almost all) release kernels. So these symbol maps are essentially huge lookup tables for virtual method names, which can be passed to `iometa` as last argument to recover most symbols.  
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

With the iOS 12.0 beta 1, Apple introduced a new kernelcache format for some devices where kexts were no longer just prelinked like before, but actually directly compiled in. This new format allows for many optimisations, and had as a consequence the complete removal of _all_ symbols (previously we had some 4000-and-something symbols left). However, on the very first beta, Apple accidentally shipped kernels for A7 iPads and A8 iPhones with **all symbols left in, more than 90'000 in total!** Out of all of those, about 25'000 are symbols corresponding to virtual methods, and the original symbol maps were generated from that with `iometa -M`.  
Those are the [`A7-dense.txt`](https://github.com/Siguza/iometa/blob/master/sym/beta/iOS-12.0b1/A7-dense.txt) and [`A8-dense.txt`](https://github.com/Siguza/iometa/blob/master/sym/beta/iOS-12.0b1/A8-dense.txt) files you'll find in the [`12.0b1`](https://github.com/Siguza/iometa/tree/master/sym/beta/iOS-12.0b1) folder, but you'll notice that those aren't the only symbol maps in there. I've tried my best to match those symbols against the kernelcaches of all other devices, and for those methods that got no match, to recover their names and argument list from panic strings or debugging information left in the kernels - with not overwhelming, but I think reasonable results. At the time of writing, I've also ported these symbol maps forward in time to the iOS 12 beta 2 (which additionally switched the iPhone 5s and iPod touch 6G to the new kernelcache format) and iOS 12.0 Golden Master (which was the first version to include A12 devices).  
Two years later, the exact same thing happened again: iOS 14 beta IPSWs for the iPhone 11 shipped, next to the normal kernel, a "research" kernel. For betas 3 through 5, these kernels had once again all symbols left in, this time about 150k in total and about 32k corresponding to virtual methods.

### Where are we going from here?

I will obviously continue porting these symbols onto newer versions, because that's the entire point of keeping these maps. While we may never recover every last symbol, there are some very good indicators that we can use to guide our efforts. If you find any mistake in these maps or `iometa` spews a warning at you about anything in them, I would greatly appreciate if you could [notify me about that](https://github.com/Siguza/iometa/issues/new).

So let's start with how these lists are organised. Originally I had planned to stuff everything into a single file, and just have one such file per iOS version. However attempting to do that made `iometa` complain at me:

> \[WRN\] Symmap entry for AppleBCMWLANBusInterface has 60 methods, vtab has 88.  
> \[WRN\] Symmap entry for AppleBCMWLANCore has 84 methods, vtab has 136.  
> \[WRN\] Symmap entry for AppleBCMWLANBSSBeacon has 61 methods, vtab has 66.  
> \[WRN\] Symmap entry for AppleBCMWLANIO80211APSTAInterface has 88 methods, vtab has 83.  
> \[WRN\] Symmap entry for AppleBCMWLANProximityInterface has 88 methods, vtab has 83.

You can reproduce that by attempting to use an A7 symbol map on an A8 cache or vice versa. Basically different device generations have, under the same name, different classes implementing different methods. In order to account for that, each SoC generation gets its own file per OS version. With the maps provided in this repo, you should never get any warnings (if using iometa >= 1.6.4) - if you do, please report them to me.

Then the next split is by kernelcache format. This is `A8-dense.txt` vs `A8-legacy.txt`. The reason these need a split is optimisation, namely abstract classes having been optimised out. The problem arises when you have a class hierarchy like so:

- Class `A` is a non-abstract base class declaring virtual method `x()`.
- Class `B` is an abstract class inheriting from class `A` and declaring virtual method `y()`.
- Class `C` is a non-abstract class inheriting from class `B` and declaring virtual method `z()`.

In the "legacy" kernelcache format, class `B` usually gets its own vtable and everything, and a symbol map would look as follows:

    A
    - x()
    B
    - y()
    C
    - z()

In the "dense" kernelcache format, however, class `B` will have been mostly optimised out and not get a vtable, which means that no methods for `B` will be recorded, which in turn will make it look like all of `B`'s methods were in fact introduced by `C`:

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

If you ever end up porting a symbol map for a device class that just switched from legacy to dense kernelcache format, you'll no doubt notice that this is the biggest change you'll have to make: moving methods of abstract classes into their child classes. The second biggest will probably be deleting all the stuff that has been optimised away altogether. ;P



<!--
So  any kind of error you detect in these maps, as well as any symbol name or argument list that you believe I missed or messed up. In that spirit, I'm also going to document how these lists are organised, how I try and update them to new versions/devices, as well as noteworthy things I've come across while doing so.

Ok, first of all, the symbol maps are organised by device class - A7, A8, etc. Originally I wanted to put all symbols for all devices into a single file, but in attempting to do that my own tool greeted me with warnings like:

 So in order to work around that, I gave each generation its own map, since within generations there's at best very little difference. 
-->

### How to port symbol maps

Here's how I actually go at updating symbol maps:

1.  Starting with iometa v1.6.0, I start with arm64e kernels (A12+). I simply run `iometa -M kernel old.txt >new.txt`, where `old.txt` is the symbol map for the closest version I have symbols for. This is the normal strategy for all devices and will usually throw a bunch of warnings and turn between a few hundred and a few thousand functions into `fn_0x...` just due to differing vtable sizes. Exclusively on arm64e though, iometa can additionally verify whether a given symbol is correct or not. This is because the PAC diversifier (see below) is the hash of the mangled C++ symbol, and iometa 1.6.0 added support for calculating that. It will throw a warning on every run for every non-matching symbol, so there is no need to manually record anything.
2.  I go through all classes with `fn_0x...` methods and, before even looking at assembly, compare a bunch of vtables between this and the last generation. Of particular interest are "pure virtual" methods (i.e. those showing up red in `iometa` output) as well as those overridden in child classes:  
    <table>
        <tr>
            <td><img src="https://user-images.githubusercontent.com/1659374/56452914-19e16b80-6339-11e9-9eaa-276ba67880be.png" alt="vtab-1a"></td>
            <td><img src="https://user-images.githubusercontent.com/1659374/56452918-367da380-6339-11e9-9583-f8c960fc9368.png" alt="vtab-1b"></td>
        </tr>
        <tr>
            <td><img src="https://user-images.githubusercontent.com/1659374/56452933-662cab80-6339-11e9-8886-47cfa2df908c.png" alt="vtab-2a"></td>
            <td><img src="https://user-images.githubusercontent.com/1659374/56452934-6e84e680-6339-11e9-9ca2-a5114caa8871.png" alt="vtab-2b"></td>
        </tr>
        <tr>
            <td><img src="https://user-images.githubusercontent.com/1659374/56452937-76dd2180-6339-11e9-8631-d20272be61a6.png" alt="vtab-3a"></td>
            <td><img src="https://user-images.githubusercontent.com/1659374/56452939-7e9cc600-6339-11e9-81ae-cb1db510ea06.png" alt="vtab-3b"></td>
        </tr>
    </table>

    You can tell a damn lot from just those patterns, and this should be enough to tell you where methods were inserted or deleted.
3.  If pattern matching leaves any ambiguity as to where methods were inserted, removed or shuffled around, we can harness the power of arm64e:  
    <table>
        <tr>
            <td><img src="https://user-images.githubusercontent.com/1659374/93288596-81287700-f7dc-11ea-831c-92f5583f07d8.png" alt="vtab-4a"></td>
            <td><img src="https://user-images.githubusercontent.com/1659374/93288674-bc2aaa80-f7dc-11ea-9194-42e4951bd113.png" alt="vtab-4b"></td>
        </tr>
    </table>

    The second image shows one method more than the first, and the `pac` field tells us exactly which one.
4.  Once all the methods which kept their PAC diversifier have been moved to the right place, it's time to dive into assembly and look at the methods that we couldn't match up. For new methods, you kinda have to get lucky and find some logging that prints the name (or be very very good at guessing). For existing methods however, chances are that it was just the argument list that was changed, and there are some tricks with which we can recover most of the information about that:
    - Unless arguments are _only_ passed through to other functions, the code will already tell us whether they are 64- or 32-bit. And since 32-bit ones can't be pointers, there's a rather small list of types to try.
    - When variables are stored to the stack, their exact size should be revealed (although this is really only relevant for 16- or 8-bit types).
    - When arguments are passed to printf-like functions, that will give away their exact size, signedness and kind (pointer vs scalar).
    - For 64-bit arguments, there's a few scalar types to try and if none of those match, chances are it's a pointer.
    - For pointer types we can have C++ and non-C++ objects. C++ objects on which virtual methods are called are extremely easy to match up with a type on arm64e, because a virtual method call looks like this:

            0xfffffff00809f4e8      080040f9       ldr x8, [x0]
            0xfffffff00809f4ec      e83bc1da       autdza x8
            0xfffffff00809f4f0      09e11691       add x9, x8, 0x5b8
            0xfffffff00809f4f4      08dd42f9       ldr x8, [x8, #1464]
            0xfffffff00809f4f8      6944fdf2       movk x9, 0xea23, lsl #48
            0xfffffff00809f4fc      e10302aa       mov x1, x2
            0xfffffff00809f500      09093fd7       blraa x8, x9
        
        And this neat little value `0xea23` is the same thing that `iometa -A` displays for each method with `pac=0xNNNN`. In most cases, that alone should be unique to a single method. When it isn't, combine it with the vtable offset (`0x5b8` here) and it will _definitely_ allow you to uniquely identify the method.  
    -   For the absolute hardest cases, which are arguments that are either blindly passed through to other functions or simply ignored, the same PAC trick as above can help again, just in reverse this time. By looking up the PAC tag of the current method and searching the kernelcache for all instructions of the form `movk x.*, 0xNNNN, lsl #48`, you should be able to find any last invocation of that method, and thus can look at how the arguments are loaded.
5.  Once I'm done with arm64e, I diff all the changes I've had to make to the symbol maps and transfer them to arm64 as best as I can, then repeat the processes above on those devices as well, as far as possible.
6.  I do this for each device belonging to a generation, collect all newly generated symbol maps, and then merge them back into one with [my ugly script](https://github.com/Siguza/iometa/blob/master/sym/symmerge). This is necessary because there are certain classes/kexts that only exist on iPhones and others that only exist on iPads, and we wanna keep both of those, yet drop any classes that were actually removed between versions.

And that's about it. Every now and then you'll come across methods whose names are simply lost (like when the function consists of a single `ret`) or whose arguments are passed around way too long before their type becomes obvious. Just put those down as `-` in the symbol map, and if someone ever goes on to reverse that method/class/kext, they can hit me up once they've figured it out. ;)

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
        <td rowspan="2">iPhone 5s</td>
        <td>iPhone6,1</td>
        <td>N51AP</td>
        <td rowspan="2" align="center">iOS 12.0 beta 2</td>
    </tr>
    <tr>
        <td>iPhone6,2</td>
        <td>N53AP</td>
    </tr>
    <tr>
        <td rowspan="3">iPad Air</td>
        <td>iPad4,1</td>
        <td>J71AP</td>
        <td rowspan="9" align="center">iOS 12.0 beta 1</td>
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
        <td rowspan="8" align="center">A8</td>
        <td>iPhone 6+</td>
        <td>iPhone7,1</td>
        <td>N56AP</td>
        <td rowspan="2" align="center">iOS 12.0 beta 1</td>
    </tr>
    <tr>
        <td>iPhone 6</td>
        <td>iPhone7,2</td>
        <td>N61AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad mini 4</td>
        <td>iPad5,1</td>
        <td>J96AP</td>
        <td rowspan="2" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad5,2</td>
        <td>J97AP</td>
    </tr>
    <tr>
        <td>iPod touch 6</td>
        <td>iPod7,1</td>
        <td>N102AP</td>
        <td align="center">iOS 12.0 beta 2</td>
    </tr>
    <tr>
        <td>Apple TV 4</td>
        <td>AppleTV5,3</td>
        <td>J42dAP</td>
        <td align="center">tvOS 13.0 beta 1</td>
    </tr>
    <tr>
        <td rowspan="2">Homepod</td>
        <td>AudioAccessory1,1</td>
        <td>B238aAP</td>
        <td rowspan="2" align="center">audioOS 13.4</td>
    </tr>
    <tr>
        <td>AudioAccessory1,2</td>
        <td>B238AP</td>
    </tr>
    <tr>
        <td rowspan="2" align="center">A8X</td>
        <td rowspan="2">iPad Air 2</td>
        <td>iPad5,3</td>
        <td>J81AP</td>
        <td rowspan="2" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad5,4</td>
        <td>J82AP</td>
    </tr>
    <tr>
        <td rowspan="10" align="center">A9</td>
        <td rowspan="2">iPhone 6s</td>
        <td rowspan="2">iPhone8,1</td>
        <td>N71AP</td>
        <td rowspan="10" align="center">N/A</td>
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
        <td rowspan="4" align="center">A9X</td>
        <td rowspan="2">iPad Pro (9.7")</td>
        <td>iPad6,3</td>
        <td>J127AP</td>
        <td rowspan="4" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad6,4</td>
        <td>J128AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Pro (12.9")</td>
        <td>iPad6,7</td>
        <td>J98aAP</td>
    </tr>
    <tr>
        <td>iPad6,8</td>
        <td>J99aAP</td>
    </tr>
    <tr>
        <td rowspan="9" align="center">A10</td>
        <td rowspan="2">iPhone 7</td>
        <td>iPhone9,1</td>
        <td>D10AP</td>
        <td rowspan="9" align="center">N/A</td>
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
        <td rowspan="2">iPad 6</td>
        <td>iPad7,5</td>
        <td>J71bAP</td>
    </tr>
    <tr>
        <td>iPad7,6</td>
        <td>J72bAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad 7</td>
        <td>iPad7,11</td>
        <td>J171AP</td>
    </tr>
    <tr>
        <td>iPad7,12</td>
        <td>J172AP</td>
    </tr>
    <tr>
        <td>iPod touch 7</td>
        <td>iPod9,1</td>
        <td>N112AP</td>
    </tr>
    <tr>
        <td rowspan="5" align="center">A10X</td>
        <td rowspan="2">iPad Pro 2 (12.9")</td>
        <td>iPad7,1</td>
        <td>J120AP</td>
        <td rowspan="4" align="center">N/A</td>
    </tr>
    <tr>
        <td>iPad7,2</td>
        <td>J121AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Pro 2 (10.5")</td>
        <td>iPad7,3</td>
        <td>J207AP</td>
    </tr>
    <tr>
        <td>iPad7,4</td>
        <td>J208AP</td>
    </tr>
    <tr>
        <td>Apple TV 4K</td>
        <td>AppleTV6,2</td>
        <td>J105aAP</td>
        <td align="center">tvOS 13.0 beta 1</td>
    </tr>
    <tr>
        <td rowspan="10" align="center">A11</td>
        <td rowspan="4">iPhone 8</td>
        <td rowspan="2">iPhone10,1</td>
        <td>D20AP</td>
        <td rowspan="10" align="center">iOS 13.0 beta 1</td>
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
        <td rowspan="11" align="center">A12</td>
        <td>iPhone XS</td>
        <td>iPhone11,2</td>
        <td>D321AP</td>
        <td rowspan="4" align="center">iOS 12.0</td>
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
    <tr>
        <td rowspan="2">iPad 8</td>
        <td>iPad11,6</td>
        <td>J171aAP</td>
        <td rowspan="2" align="center">iOS 14.0</td>
    </tr>
    <tr>
        <td>iPad11,7</td>
        <td>J172aAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Air 3</td>
        <td>iPad11,3</td>
        <td>J217AP</td>
        <td rowspan="4" align="center">iOS 12.2</td>
    </tr>
    <tr>
        <td>iPad11,4</td>
        <td>J218AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad mini 5</td>
        <td>iPad11,1</td>
        <td>J210AP</td>
    </tr>
    <tr>
        <td>iPad11,2</td>
        <td>J211AP</td>
    </tr>
    <tr>
        <td>Apple TV 4K 2</td>
        <td>AppleTV11,1</td>
        <td>J305AP</td>
        <td align="center">tvOS 14.5</td>
    </tr>
    <tr>
        <td rowspan="15" align="center">A12X</td>
        <td rowspan="4">iPad Pro 3 (11.0")</td>
        <td>iPad8,1</td>
        <td>J317AP</td>
        <td rowspan="8" align="center">iOS 12.1</td>
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
        <td rowspan="4">iPad Pro 3 (12.9")</td>
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
        <td rowspan="2">iPad Pro 4 (11.0")</td>
        <td>iPad8,19</td>
        <td>J417AP</td>
        <td rowspan="4" align="center">iOS 13.4</td>
    </tr>
    <tr>
        <td>iPad8,10</td>
        <td>J418AP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Pro 4 (12.9")</td>
        <td>iPad8,11</td>
        <td>J420AP</td>
    </tr>
    <tr>
        <td>iPad8,12</td>
        <td>J421AP</td>
    </tr>
    <tr>
        <td rowspan="3">DTK</td>
        <td>ADP3,1</td>
        <td>J273AP</td>
        <td rowspan="3" align="center">N/A</td>
    </tr>
    <tr>
        <td>ADP3,2</td>
        <td>J273aAP</td>
    </tr>
    <tr>
        <td>iProd99,1</td>
        <td>T485AP</td>
    </tr>
    <tr>
        <td rowspan="4" align="center">A13</td>
        <td>iPhone 11</td>
        <td>iPhone12,1</td>
        <td>N104AP</td>
        <td rowspan="3" align="center">iOS 13.0</td>
    </tr>
    <tr>
        <td>iPhone 11 Pro</td>
        <td>iPhone12,3</td>
        <td>D421AP</td>
    </tr>
    <tr>
        <td>iPhone 11 Pro Max</td>
        <td>iPhone12,5</td>
        <td>D431AP</td>
    </tr>
    <tr>
        <td>iPhone SE 2</td>
        <td>iPhone12,8</td>
        <td>D79AP</td>
        <td align="center">iOS 13.4</td>
    </tr>
    <tr>
        <td rowspan="6" align="center">A14</td>
        <td>iPhone 12 mini</td>
        <td>iPhone13,1</td>
        <td>D52gAP</td>
        <td rowspan="4" align="center">iOS 14.1</td>
    </tr>
    <tr>
        <td>iPhone 12</td>
        <td>iPhone13,2</td>
        <td>D53gAP</td>
    </tr>
    <tr>
        <td>iPhone 12 Pro</td>
        <td>iPhone13,3</td>
        <td>D53pAP</td>
    </tr>
    <tr>
        <td>iPhone 12 Pro Max</td>
        <td>iPhone13,4</td>
        <td>D54pAP</td>
    </tr>
    <tr>
        <td rowspan="2">iPad Air 4</td>
        <td>iPad13,1</td>
        <td>J307AP</td>
        <td rowspan="2" align="center">iOS 14.0</td>
    </tr>
    <tr>
        <td>iPad13,2</td>
        <td>J308AP</td>
    </tr>
    <tr>
        <td rowspan="13" align="center">M1</td>
        <td rowspan="4">iPad Pro 5 (11.0")</td>
        <td>iPad13,4</td>
        <td>J517AP</td>
        <td rowspan="8" align="center">iOS 14.5</td>
    </tr>
    <tr>
        <td>iPad13,5</td>
        <td>J517xAP</td>
    </tr>
    <tr>
        <td>iPad13,6</td>
        <td>J518AP</td>
    </tr>
    <tr>
        <td>iPad13,7</td>
        <td>J518xAP</td>
    </tr>
    <tr>
        <td rowspan="4">iPad Pro 5 (12.9")</td>
        <td>iPad13,8</td>
        <td>J522AP</td>
    </tr>
    <tr>
        <td>iPad13,9</td>
        <td>J522xAP</td>
    </tr>
    <tr>
        <td>iPad13,10</td>
        <td>J523AP</td>
    </tr>
    <tr>
        <td>iPad13,11</td>
        <td>J523xAP</td>
    </tr>
    <tr>
        <td>Mac mini 2020</td>
        <td>Macmini9,1</td>
        <td>J274AP</td>
        <td rowspan="5" align="center">N/A</td>
    </tr>
    <tr>
        <td>MacBook Air 2020</td>
        <td>MacBookAir10,1</td>
        <td>J313AP</td>
    </tr>
    <tr>
        <td>MacBook Pro 2020</td>
        <td>MacBookPro17,1</td>
        <td>J293AP</td>
    </tr>
    <tr>
        <td rowspan="2">iMac 2021 (24")</td>
        <td>iMac21,1</td>
        <td>J456AP</td>
    </tr>
    <tr>
        <td>iMac21,2</td>
        <td>J457AP</td>
    </tr>
    <tr>
        <td colspan="5"></td>
    </tr>
    <tr>
        <td rowspan="4" align="center">S4</td>
        <td rowspan="4">Apple Watch Series 4</td>
        <td>Watch4,1</td>
        <td>N131sAP</td>
        <td rowspan="4" align="center">watchOS 5.0</td>
    </tr>
    <tr>
        <td>Watch4,2</td>
        <td>N131bAP</td>
    </tr>
    <tr>
        <td>Watch4,3</td>
        <td>N141sAP</td>
    </tr>
    <tr>
        <td>Watch4,4</td>
        <td>N141bAP</td>
    </tr>
    <tr>
        <td rowspan="9" align="center">S5</td>
        <td rowspan="4">Apple Watch Series 5</td>
        <td>Watch5,1</td>
        <td>N144sAP</td>
        <td rowspan="4" align="center">watchOS 6.0</td>
    </tr>
    <tr>
        <td>Watch5,2</td>
        <td>N144bAP</td>
    </tr>
    <tr>
        <td>Watch5,3</td>
        <td>N146sAP</td>
    </tr>
    <tr>
        <td>Watch5,4</td>
        <td>N146bAP</td>
    </tr>
    <tr>
        <td rowspan="4">Apple Watch SE</td>
        <td>Watch5,9</td>
        <td>N140sAP</td>
        <td rowspan="4" align="center">watchOS 7.0</td>
    </tr>
    <tr>
        <td>Watch5,10</td>
        <td>N140bAP</td>
    </tr>
    <tr>
        <td>Watch5,11</td>
        <td>N142sAP</td>
    </tr>
    <tr>
        <td>Watch5,12</td>
        <td>N142bAP</td>
    </tr>
    <tr>
        <td>Homepod mini</td>
        <td>AudioAccessory5,1</td>
        <td>B520AP</td>
        <td align="center">audioOS 14.1</td>
    </tr>
    <tr>
        <td rowspan="4" align="center">S6</td>
        <td rowspan="4">Apple Watch Series 6</td>
        <td>Watch6,1</td>
        <td>N157sAP</td>
        <td rowspan="4" align="center">watchOS 7.0</td>
    </tr>
    <tr>
        <td>Watch6,2</td>
        <td>N157bAP</td>
    </tr>
    <tr>
        <td>Watch6,3</td>
        <td>N158sAP</td>
    </tr>
    <tr>
        <td>Watch6,4</td>
        <td>N158bAP</td>
    </tr>
    <tr>
        <td colspan="5"></td>
    </tr>
    <tr>
        <td rowspan="18" align="center">T2</td>
        <td rowspan="18">iBridge T2</td>
        <td>iBridge2,1</td>
        <td>J137AP</td>
        <td rowspan="8" align="center">bridgeOS 4.0</td>
    </tr>
    <tr>
        <td>iBridge2,3</td>
        <td>J680AP</td>
    </tr>
    <tr>
        <td>iBridge2,4</td>
        <td>J132AP</td>
    </tr>
    <tr>
        <td>iBridge2,5</td>
        <td>J174AP</td>
    </tr>
    <tr>
        <td>iBridge2,6</td>
        <td>J160AP</td>
    </tr>
    <tr>
        <td>iBridge2,7</td>
        <td>J780AP</td>
    </tr>
    <tr>
        <td>iBridge2,8</td>
        <td>J140kAP</td>
    </tr>
    <tr>
        <td>iBridge2,10</td>
        <td>J213AP</td>
    </tr>
    <tr>
        <td>iBridge2,11</td>
        <td>J230AP</td>
        <td align="center">bridgeOS 4.4</td>
    </tr>
    <tr>
        <td>iBridge2,12</td>
        <td>J140aAP</td>
        <td align="center">bridgeOS 4.0</td>
    </tr>
    <tr>
        <td>iBridge2,13</td>
        <td>J214AP</td>
        <td align="center">bridgeOS 4.4</td>
    </tr>
    <tr>
        <td>iBridge2,14</td>
        <td>J152fAP</td>
        <td align="center">bridgeOS 4.2</td>
    </tr>
    <tr>
        <td>iBridge2,15</td>
        <td>J230kAP</td>
        <td align="center">bridgeOS 4.3</td>
    </tr>
    <tr>
        <td>iBridge2,16</td>
        <td>J214kAP</td>
        <td align="center">bridgeOS 4.4</td>
    </tr>
    <tr>
        <td>iBridge2,19</td>
        <td>J185AP</td>
        <td rowspan="2" align="center">bridgeOS 4.6</td>
    </tr>
    <tr>
        <td>iBridge2,20</td>
        <td>J185fAP</td>
    </tr>
    <tr>
        <td>iBridge2,21</td>
        <td>J223AP</td>
        <td align="center">bridgeOS 4.4</td>
    </tr>
    <tr>
        <td>iBridge2,22</td>
        <td>J215AP</td>
        <td align="center">bridgeOS 4.6</td>
    </tr>
</table>
