---
title: "IDA Pro plugins (2025)"
date: 2025-01-22 11:00:00 -0700
categories: [Blogging]
tags: [ida, plugins]
---

## Summary
Coming into the new year I did a personal review of plugins and frameworks that I currently use.  There are also some that I am in the process of experimenting with as I may be able to apply them to work I'm doing.  This year will be one of plugin development for me and I'll be creating some new ones and updating/contributing to existing ones.

The following are a list that I have found useful and that I have confirmed work on IDA Pro 8.4.

## Plugins

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Flare CAPA Explorer</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/mandiant/capa">https://github.com/mandiant/capa</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Detects capabilities in executable files.</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Install notes</td>
    <td>Reference the well-documented install instructions at:<br /><a href="https://github.com/mandiant/capa/blob/master/doc/installation.md">https://github.com/mandiant/capa/blob/master/doc/installation.md</a></td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Diaphora</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/joxeankoret/diaphora">https://github.com/joxeankoret/diaphora</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>An advanced program diff'ing tool integrated into IDA Pro. Can compared two IDB databases <br />and display the differences.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">HexRaysPyTools</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/igogo-x86/HexRaysPyTools">https://github.com/igogo-x86/HexRaysPyTools</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>It assists in the creation of classes/structures and detection of virtual tables.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">ClassInformer</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/herosi/classinformer">https://github.com/herosi/classinformer</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Parses disassembly to reconstruct classes from RTTI.</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Install notes</td>
    <td>
      <ul>
        <li>Download the release DLLs from <a href="https://github.com/herosi/classinformer/releases">https://github.com/herosi/classinformer/releases</a></li>
        <li>There is one DLL if on IDA Pro 9 or 2 DLLs if on IDA Pro 8</li>
      </ul>
    </td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">idaclu</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/harlamism/IdaClu">https://github.com/harlamism/IdaClu</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>It helps you find similarities in functions and group them in bulk.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">auto_dword.py</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://gist.github.com/herrcore/4595a884345a60d3e9c1b6a8f17f93d9">https://gist.github.com/herrcore/4595a884345a60d3e9c1b6a8f17f93d9</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Allows you to highlight raw data and right click and select "Auto-DWORD" to transform<br />it into a list of DWORDS.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">HashDB</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/OALabs/hashdb-ida">https://github.com/OALabs/hashdb-ida</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Can be used to look up strings that have been hashed in malware (typically to resolve<br />function hashing).</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">FindYara</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/OALabs/findyara-ida">https://github.com/OALabs/findyara-ida</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Allows you to scan your binary with yara rules.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">HexCopy</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/OALabs/hexcopy-ida">https://github.com/OALabs/hexcopy-ida</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Allows you to quickly copy disassembly as encoded hex bytes.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Lucid</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/gaasedelen/lucid">https://github.com/gaasedelen/lucid</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Lucid is a developer-oriented IDA Pro plugin for exploring the Hex-Rays microcode. It<br />was designed to provide a seamless, interactive experience for studying microcode<br />transformations in the decompiler pipeline.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">D810</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://gitlab.com/eshard/d810">https://gitlab.com/eshard/d810</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>D-810 is an IDA Pro plugin which can be used to deobfuscate code at decompilation<br />time by modifying IDA Pro microcode.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Highlight target instructions</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/tdmathison/HelperScripts/blob/master/AGDCservices/AGDCservices_highlight_target_instructions_plugin.py">AGDCservices_highlight_target_instructions_plugin.py</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>These were two scripts that were original written for Ghidra by somebody else and I converted<br />them into IDA Pro equivalent ones.  They will highlight (or unhighlight) call statements as<br />well as many other things related to encryption and math operations.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Gepetto</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td><a href="https://github.com/JusticeRage/Gepetto">https://github.com/JusticeRage/Gepetto</a></td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>A Python plugin which uses various large language models to provide meaning to functions<br />decompiled by IDA Pro (≥ 7.4). It can leverage them to explain what a function does, and to<br />automatically rename its variables.</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Install notes</td>
    <td>
      <ul>
        <li>This may be the best working plugin to integrate IDA Pro with ChatGPT (so far)
          <ul>
            <li>Set env variable OPENAI_API_KEY to your key</li>
            <li>Create a key from: <a href="https://platform.openai.com/api-keys">https://platform.openai.com/api-keys</a></li>
          </ul>
        </li>
        <li>Models and costs can be seen below:
          <ul>
            <li><a href="https://platform.openai.com/docs/models#gpt-4o-mini">https://platform.openai.com/docs/models#gpt-4o-mini</a></li>
            <li>NOTE: You have to pay for API usage which is separate of paying for ChatGPT on its own<br />(to ask questions, etc.)</li>
          </ul>
        </li>
        <li>Install all requirements in requirements.txt
          <ul>
            <li>You may need to use the --user switch when installing them</li>
          </ul>
        </li>
        <li>In the config we need to make the following changes:
          <code><br />
            [Gepetto]<br />
            MODEL = gpt-4o-mini<br />
            [OpenAI]<br />
            # Set your API key here, or put it in the OPENAI_API_KEY<br /># environment variable.<br />
            API_KEY = YOUR_API_KEY
          </code>
        </li>
        <li>NOTE: It may be better to update the code to read it from the env variable OPENAI_API_KEY<br />instead.</li>
        <li>Code updates:
          <ul>
            <li>The usage of the OpenAI API has changed a bit since this plugin was created and I made<br />the following changes to get it to work properly.</li>
            <li>In openai.py:
              <code><br />
                # Set the API key directly now.<br />
                openai.api_key = api_key<br />
                #self.client = openai.OpenAI(<br />
                #    api_key=api_key,<br />
                #    base_url=base_url,<br />
                #    http_client=_httpx.Client(<br />
                #        proxies=proxy,<br />
                #    ) if proxy else None<br />
                #)
              </code>
            </li>
            <li>In openai.py:
              <code><br />
                # from<br />
                response = self.client.chat.completions.create(<br />
                    model=self.model,<br />
                    messages=conversation,<br />
                    **additional_model_options)<br /><br />
                
                # to<br />
                response = openai.ChatCompletion.create(<br />
                    model=self.model,<br />
                    messages=conversation,<br />
                    **additional_model_options)<br />
              </code>
            </li>
          </ul>
        </li>
      </ul>
    </td>
  </tr>
</table>


## Tools and frameworks

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Sark Framework</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td>
      <a href="https://github.com/tmr232/Sark">https://github.com/tmr232/Sark</a><br />
      <a href="https://sark.readthedocs.io/en/latest/Installation.html">https://sark.readthedocs.io/en/latest/Installation.html</a>
    </td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>IDA Plugins & IDAPython Scripting Library.</td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Flare-Emu</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td>
      <a href="https://github.com/mandiant/flare-emu">https://github.com/mandiant/flare-emu</a>
    </td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>An emulation framework to provide an easy to use and flexible interface for scripting emulation<br />tasks.</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Install notes</td>
    <td><code>python -m pip install rzpipe flare-emu unicorn</code></td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Flare-FLOSS</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td>
      <a href="https://github.com/mandiant/flare-floss">https://github.com/mandiant/flare-floss</a>
    </td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>This is an Obfuscated String Solver that uses advanced static analysis techniques to<br />automatically extract and deobfuscate all strings from malware binaries.</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Install notes</td>
    <td>
      <ul>
        <li>Download source and the release binary to put into the source directory</li>
        <li>Put directly into the IDA Pro (or a tools) directory</li>
        <li>To parse the resulting JSON file from FLOSS you can install the jq tool
          <code><br />
            type .\stealc.json | jq -r '.strings.decoded_strings | map(.string) | unique<br />
            type .\stealc.json | jq -r '.strings.stack_strings | map(.string) | unique<br />
            type .\stealc.json | jq -r '.strings.static_strings | map(.string) | unique<br />
            type .\stealc.json | jq -r '.strings.tight_strings | map(.string) | unique
          </code>
        </li>
        <li>There are also scripts to import the results back into IDA Pro
          <ul>
            <li><a href="https://github.com/mandiant/flare-floss/blob/master/scripts/README.md">https://github.com/mandiant/flare-floss/blob/master/scripts/README.md</a></li>
          </ul> 
        </li>
      </ul>
    </td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">Angr Framework</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td>
      <a href="https://github.com/angr/angr">https://github.com/angr/angr</a><br />
      <a href="https://github.com/andreafioraldi/IDAngr">https://github.com/andreafioraldi/IDAngr</a><br />
      <a href="https://github.com/andreafioraldi/angrdbg">https://github.com/andreafioraldi/angrdbg</a><br />
      <a href="https://github.com/degrigis/awesome-angr">https://github.com/degrigis/awesome-angr</a>
    </td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>A platform-agnostic binary analysis framework.</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Install notes</td>
    <td><code>python -m pip install angr angrdbg angr-management capstone-windows</code></td>
  </tr>
</table>

<table style="width:100%">
  <tr>
    <td style="font-weight:bold;width:1px">Name</td>
    <td style="font-weight:bold;color:#d2603a">QScripts</td>
  </tr>
  <tr>
    <td style="font-weight:bold">Link</td>
    <td>
      <a href="https://github.com/allthingsida/qscripts">https://github.com/allthingsida/qscripts</a>
    </td>
  </tr>
  <tr>
    <td style="font-weight:bold">Description</td>
    <td>Allows you to develop and run any supported scripting language (*.py; *.idc, etc.) from the comfort<br />of your own favorite text editor as soon as you save the active script, the trigger file or any of its<br />dependencies.</td>
  </tr>
</table>
