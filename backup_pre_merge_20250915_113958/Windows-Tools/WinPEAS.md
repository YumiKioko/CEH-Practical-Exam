WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths.
You can find more information about winPEAS and download either the precompiled executable or a .bat script.

WinPEAS will run commands similar to the ones listed in the previous task and print their output.

The output from winPEAS can be lengthy and sometimes difficult to read.
This is why it would be good practice to always redirect the output to a file, as shown below:

```Command-Prompt
winpeas.exe > outputfile.txt
```


WinPEAS can be downloaded [here](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS).