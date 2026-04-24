---
title: "Bringing Local AI Assistance into IDA Pro (Without Leaving Your Lab)"
date: 2026-04-24 07:35:00 -0700
categories: [Blogging]
tags: [ida, ollama, gepetto, ai, plugin]
---

## Summary
Reverse engineering is still a very manual craft.

Even with tools like IDA Pro and Binary Ninja doing heavy lifting on disassembly and decompilation, the actual thinking is still on you—understanding control flow, reconstructing intent, tracking data transformations, and making sense of what is often intentionally confusing code.

That’s where local AI starts to become interesting to assist in making sense of confusing assembly or decompilation.

Used correctly, an LLM can:
* Quickly summarize large functions so you know where to focus
* Suggest meaningful variable/function names based on behavior
* Help reason through decryption or parsing logic
* Generate helper scripts (IDA Python, CyberChef recipes, etc.)
* Act as a second set of eyes when you’re deep in a rabbit hole

The key point: **you stay in control of the analysis**. The model just helps reduce the cognitive overhead.

There’s also a major constraint in our field:
* You’re often working with sensitive samples
* You don’t want to send binaries, configs, or proprietary telemetry to external APIs

That’s why running models **locally** is such a strong fit for malware analysis.

This post walks through building a setup where:
* AI models run locally on your machine (or lab host)
* IDA Pro connects to them like it would OpenAI
* Everything stays inside your lab

## What is Ollama
Ollama is essentially a lightweight local runtime for large language models.

Think of it as:
* A model manager
* A local inference server
* An OpenAI-compatible API endpoint

All wrapped into something you can install and use in a few minutes.

### Why Ollama works well for RE workflows
There are a few reasons it fits particularly well in a reverse engineering lab:
* Dead simple setup
  * You can go from install → running model → API endpoint in minutes
* Local-first by design
  * No external calls, no data leaving your environment
* OpenAI-compatible API
  * This is the important part—your IDA plugin doesn’t need to know it’s not talking to OpenAI
* Model flexibility
  * You can swap models depending on your use case without changing your tooling

## Model Selection
Not all models are equal for reverse engineering (and there are limits to small models).

You want models that:
* Understand code reasonably well
* Handle structured reasoning
* Don’t completely fall apart on pseudocode

In practice, smaller models work fine for most day-to-day tasks.

Good starting points

| Model | Description |
|:---|:----|
| Qwen2.5-Coder (7B / 14B) | * Can perform some code reasoning<br/>* Good balance of speed vs quality |
| deepseek-coder:6.7b | * May be better than Qwen for pseudo-C reasoning |
| Phi-4  | * Lightweight and surprisingly capable<br/>* Good for quick summaries and scripting tasks |
| Mistral / Mistral-Nemo | * Solid general-purpose reasoning<br/>* Works well when code + logic are mixed |
| Gemma 2 (9B) | * Another good general-purpose option |

## Architecture Overview
The setup I landed on looks like this:
```
macOS (M2 MacBook Pro)
  └── Ollama (local model server using Apple Silicon acceleration)
         │
         │  HTTP (OpenAI-compatible API)
         ▼
FlareVM (Windows)
  └── IDA Pro + AI plugin
```

Why this design works well:
* Apple Silicon handles inference efficiently (GPU via Metal/MLX)
* FlareVM stays clean and focused on analysis
* Communication is just HTTP over your local network

## Installation & Configuration
### 1. Install Ollama on your host machine (macOS in my case)
 1. macOS - [https://ollama.com/download/mac](https://ollama.com/download/mac)
 2. Windows - [https://ollama.com/download/windows](https://ollama.com/download/windows)

Once installed, verify it’s working:

```bash
ollama --version
ollama ps
```
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/00.png"/><br/>
Figure 1: Running and verifying the model</div><br />

### 2. Pull a Model
Pick a model to start with:
```bash
ollama pull qwen3:8b
ollama list
```

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/01.png"/><br/>
Figure 2: Downloading ollama model</div><br />

Test for proper responses:
```bash
curl http://127.0.0.1:11434/api/tags
curl http://127.0.0.1:11434/v1/models
```
<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/02.png"/><br/>
Figure 3: Testing queries against the model</div><br />

### 3. Expose Ollama to Your Lab Network
By default, Ollama binds to localhost. To allow FlareVM to connect, you need to expose it.

#### On macOS
```bash
launchctl setenv OLLAMA_HOST "0.0.0.0:11434"

# Recommended for a local-only lab workflow
launchctl setenv OLLAMA_NO_CLOUD "1"

# Set a larger default context window
launchctl setenv OLLAMA_CONTEXT_LENGTH "8192"
```

#### On Windows
Create system-wide environment variables:
1. Navigate to and open: `System Properties → Advanced → Environment Variables`
2. Under User variables (or System variables), add:

| Variable | Value |
|:---|:----|
| OLLAMA_HOST | 0.0.0.0:11434 |
| OLLAMA_NO_CLOUD | 1 |
| OLLAMA_CONTEXT_LENGTH | 8192 |

Alternate option is to use PowerShell:
```powershell
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")
[System.Environment]::SetEnvironmentVariable("OLLAMA_NO_CLOUD", "1", "User")
[System.Environment]::SetEnvironmentVariable("OLLAMA_CONTEXT_LENGTH", "8192", "User")
```

#### Determine your host machine IP
```bash
ipconfig getifaddr en0    # macOS / GNU/Linux
ipconfig | findstr IPv4   # Windows
```

Your API endpoint becomes: `http://192.168.1.27:11434/v1` (where `192.168.1.27` is changed to your local IP)


### 4. Validate from FlareVM
From your Windows VM:
```powershell
# Reachability
Test-NetConnection 192.168.1.27 -Port 11434

# Model listing
Invoke-RestMethod -Method Get -Uri "http://192.168.1.27:11434/v1/models"

# Chat completion test
$body = @{
model = "qwen2.5-coder:7b"
messages = @(
@{ role = "user"; content = "Reply with only the text: flarevm connectivity works" }
)
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
-Uri "http://192.168.1.27:11434/v1/chat/completions" `
-ContentType "application/json" `
-Body $body
```

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/03.png"/><br/>
Figure 4: Testing connetivity from FlareVM</div><br />


### 5. Configure IDA Plugin
#### Download plugin files
The IDA Pro plugin I'm using for this is called Gepetto and can be downloaded from GitHub at:

**Gepetto** - [https://github.com/JusticeRage/Gepetto](https://github.com/JusticeRage/Gepetto)

Unip the latest release and drop the "gepetto" directory and "gepetto.py" plugin script into the IDA Pro plugins folder:

Example:<br/>
`C:\Program Files\IDA Pro 8.4\plugins`


#### Install dependencies
The plugin folder contains a `requirements.txt` file you can use to install dependencies.
```bash
python -m pip install -r .\requirements.txt
```
NOTE: If you have multiple python interpreters installed on the FlareVM make sure you know which one IDA Pro is using.  You can get a hint of which one by using the `idapyswitch.exe`.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/04.png"/><br/>
Figure 5: Using idapyswitch.exe to determine python interpreter used</div><br />

#### Configuration updates
There are a few changes you need to make to support the use of the local Ollama model.

**openai.py adjustments**
1. Open the following file `<IDA_DIR>\plugins\gepetto\models\openai.py`
2. Add the local model name into the existing ones to make it available in the plugin:

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/05.png"/><br/>
Figure 6: Adding Qwen2.5-Coder model as an option</div><br />

**gepetto.py adjustments**
3. Open the following file `<IDA_DIR>\plugins\gepetto.py`
4. Add the new model name, openai key, and the URL to the localhost service it is exposed on
   1. NOTE: The Ollama API key for the local instance is `"ollama"` by default

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/06.png"/><br/>
Figure 7: Adding local ollama instance information to the plugin config</div><br />

### Testing the plugin in IDA Pro
Upon starting IDA Pro you should see the Gepetto window pane upon opening a binary. If configured correctly we should see the new model name as the default at the bottom.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/07.png"/><br/>
Figure 8: Default view of Gepetto plugin pane with local model name selected</div><br />

We can now navigate to a function and utilize the Gepetto menu to perform several default prompts to help explain the decompilation better.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/08.png"/><br/>
Figure 9: Gepetto plugin default prompts</div><br />

## Limitations
There is a reality check here (at least at this point in time): small models like this will not perform as well as frontier models like ChatGPT.

* Small models (7–8B) are:
  * Fast
  * Lightweight
  * But not great at deep reasoning

* They struggle with:
  * Long decompiled functions
  * Control flow inference
  * Multi-step decoding logic

You can experiment with other models that may perform annotation operations better like `deepseek-coder:6.7b` (this will continue to change).  For getting quick assessments of the decompilation, adding comments, and small targeted assessments this can still work well.  For larger assessments to understand multiple full functions and larger decoding solutions you will still need to switch back over to using a full ChatGPT or Anthropic model (but can be pricy due to how many tokens are generated with assembly and pseudo-C).

An example would be that this:

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/09.png"/><br/>
Figure 10: A function to explain</div><br />

Turns into the following after running the explain/comment prompts.

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/10.png"/><br/>
Figure 11: A function once commenting has been added from the model</div><br />

Further, a markdown document can be created with a Python representation:

<div align="center"><img style="align:left" src="{{ site.url }}/assets/img/20260424_0/11.png"/><br/>
Figure 12: Generated python from the pseudo-C</div><br />

## Conclusion
The goal is this was to experiment with being able to take things offline and maintain some AI assistance.  This can be used if you don't have Internet access for some reason, are in an isolated lab, or just want to reduce some of the cost of using the frontier models.  As hardware gets faster, specific hardware for running AI models "at home" becomes more mainstream, this will continue to perform better.