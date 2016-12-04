# CapKeyStone
Alfred Workflow to convert hex string to assembly and vice versa.

It is based on [capstone](http://www.capstone-engine.org/) and [keystone](http://www.keystone-engine.org/)

There are two vesions of workflow available:  
&nbsp;&nbsp;**Standalone** - with build-in capstone/keystone libraries and python bindings   
&nbsp;&nbsp;**Lite** - using capstone/keystone engines installed in the system

## Trigger

By default workflow can be triggered with:  
### ```ks``` - to convert from assembly to hex stiring.  
![Assemble](./Resources/screenshots/ks_example.png?raw=true "Assemble")   
&nbsp;&nbsp;&nbsp;&nbsp;Use modifier keys to **swap endianness** and **remove spaces** before copy.

### ```cs``` - to convert from hex string to assembly.  
![Disasseble](./Resources/screenshots/cs_example.png?raw=true "Disasseble")   
&nbsp;&nbsp;&nbsp;&nbsp;Use **ALT** key to make string **upper case** before copy.

## Configuration

You can set required architectures using **Workflow Enviroment Variables**

![Config](./Resources/screenshots/config_archs.png?raw=true "Workflow")

#### For capstone:

&nbsp;&nbsp;**X86:** x16 x32 x64 x16att x32att x64att  
&nbsp;&nbsp;**ARM:** arm armb arml thumb thumbbe thumble arm64  
&nbsp;&nbsp;**MIPS:** mips mipsbe mips64 mips64be  
&nbsp;&nbsp;**PPC:** ppc64 ppc64be
&nbsp;&nbsp;**Sparc:** sparc systemz 
&nbsp;&nbsp;**SystemZ:** sysz s390x 
&nbsp;&nbsp;**XCore:** xcore 

#### For keystone:

&nbsp;&nbsp;**X86:** x16 x32 x64 x16att x32att x64att x16nasm x32nasm x64nasm  
&nbsp;&nbsp;**ARM:** arm armbe thumb thumbbe armv8 armv8be thumbv8 thumbv8be arm64  
&nbsp;&nbsp;**Hexagon:** hex hexagon  
&nbsp;&nbsp;**MIPS:** mips mipsbe mips64 mips64be  
&nbsp;&nbsp;**PPC:** ppc32be ppc64 ppc64be  
&nbsp;&nbsp;**Sparc:** sparc sparcbe sparc64 sparc64be  
&nbsp;&nbsp;**SystemZ:** systemz sysz s390x  

## Workflow Structure

![Workflow](./Resources/screenshots/workflow.png?raw=true "Workflow")
