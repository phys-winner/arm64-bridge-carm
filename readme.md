# Carmageddon ARM64 Bridge

A game-specific Android compatibility bridge that runs Carmageddon's original
ARMv7 native engine inside an ARM64 process using Dynarmic. The bridge translates
ARM32 code and forwards its native API calls to Android's ARM64 libraries.

The target is the Android release **1.8.507** (`com.stainlessgames.carmageddon`),
including devices that provide only the `arm64-v8a` ABI. This is an unofficial
restoration project, not a source port of the game engine.

## What the bridge does

- Loads and relocates the original ELF32 ARM libraries in a 32-bit guest address
  space and executes them through Dynarmic's A32 frontend.
- Bridges libc, pthread, JNI, Android assets and input, EGL, OpenGL ES 1.x/2.x,
  OpenSL ES and zlib calls to the host platform.
- Connects the original FMOD audio libraries to Android audio output.
- Provides game-specific repairs for formatting, scanning, checkpoint sorting,
  memory handling and Android lifecycle behavior.
- Reads the original OBB from an uncompressed APK asset, with a checked external
  OBB fallback, without extracting its contents on the device.
- Produces an ARM64 shared library with 16 KiB ELF load-segment alignment.

## Repository contents

| Path | Purpose |
| --- | --- |
| `arm64_bridge/src/` | Native loader, execution host, JNI integration and API thunks |
| `arm64_bridge/tests/` | Component regressions and host-side symbol-check tests |
| `arm64_bridge/build_arm64.ps1` | Windows Android NDK build and ELF validation |
| `arm64_bridge/build_arm64.bat` | PowerShell build launcher |
| `arm64_bridge/check_symbols.py` | Relocation-backed guest import coverage check |
| `arm64_bridge/memcheck.sh` | Optional ADB memory sampling for a debuggable app |
| `build.sh` | Package and validate an independently prepared apktool application tree |

Game binaries, assets, decoded application code, signing keys, device captures
and local investigation history are excluded. Dependencies are downloaded
separately into the ignored `arm64_bridge/third_party/` directory.

## Requirements

The supplied native build wrapper targets Windows and requires:

- PowerShell, Git and an Android SDK installation.
- Android NDK **27.2.12479018**, SDK CMake **3.22.1** and its bundled Ninja.
- Boost **1.83.0** headers and the pinned Dynarmic checkout described below.
- Python **3.11 or newer** for the symbol checker, tests and APK validation.

Set `ANDROID_SDK_ROOT` to your SDK installation, or pass `-SdkRoot` to the build
wrapper. Its default SDK location is resolved from the current user's
`LOCALAPPDATA`; no developer-specific paths are required.

## Obtain dependencies

Run these commands in PowerShell from the repository root. The Boost archive
hash is pinned to the official release metadata.

```powershell
New-Item -ItemType Directory -Force arm64_bridge/third_party/boost | Out-Null
Invoke-WebRequest https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.gz -OutFile boost_1_83_0.tar.gz
if ((Get-FileHash boost_1_83_0.tar.gz -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'c0685b68dd44cc46574cce86c4e17c0f611b15e195be9848dfd0769a0a207628') {
    throw 'Boost archive checksum mismatch'
}
tar -xzf boost_1_83_0.tar.gz --strip-components=1 -C arm64_bridge/third_party/boost
if ($LASTEXITCODE -ne 0) { throw 'Boost extraction failed' }

git clone --no-checkout https://github.com/azahar-emu/dynarmic.git arm64_bridge/third_party/dynarmic
if ($LASTEXITCODE -ne 0) { throw 'Dynarmic clone failed' }
git -C arm64_bridge/third_party/dynarmic checkout --detach e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
if ($LASTEXITCODE -ne 0) { throw 'Dynarmic checkout failed' }
git -C arm64_bridge/third_party/dynarmic submodule update --init --recursive
if ($LASTEXITCODE -ne 0) { throw 'Dynarmic submodule checkout failed' }
```

The native wrapper uses this local Dynarmic tree without fetching again.
Alternatively, after installing Boost, pass `-AllowNetwork` to let CMake fetch
the same pinned Dynarmic revision on the first build. Subsequent cached builds
can run offline.

## Build the native bridge

```powershell
./arm64_bridge/build_arm64.ps1 -BridgeTarget Parsons
```

The output is `arm64_bridge/dist/libParsons.so`. The wrapper strips unneeded
symbols, checks that it is ELF64/AArch64 and verifies at least 16 KiB alignment
for every `PT_LOAD` segment. The default platform is `android-26`.

Normal wrapper builds disable bridge logging and collision probes. For a
diagnostic build, add `-EnableBridgeLogs`; enable other probes only when needed.
The `-TestForceExternalObb` switch creates a diagnostic-only library, which the
packaging script refuses by default.

## Game integration and optional APK packaging

**Building the bridge alone does not produce an installable game.** Supply your
own original game files and a separately prepared apktool application tree.
This repository does not include a stock-APK-to-adapted-application conversion
script or the modified Java/smali wrapper. Simply decoding the original APK and
replacing its native library is insufficient: the application must expose the
bridge's surface, input, lifecycle and audio JNI integration.

The optional `build.sh` expects this local layout:

```text
app/
  apktool.yml
  AndroidManifest.xml
  assets/
    main.507.com.stainlessgames.carmageddon.obb
    guest_libs/
      libParsons.so
      libfmodevent.so
      libfmodeventL.so
      libfmodex.so
      libfmodexL.so
  lib/arm64-v8a/libParsons.so
main.507.com.stainlessgames.carmageddon.obb
```

The files in `assets/guest_libs/` are the original **ARM32** libraries. The file
in `lib/arm64-v8a/` is the newly built **ARM64** bridge. Configure apktool to
store the guest libraries and the complete OBB uncompressed. No ARM32 library
may remain under the APK's `lib/` directory.

The expected original OBB is 78,692,000 bytes, with SHA-256:

```text
f35bed98ef82c7c5b316437a3bb5cb89d2c0f917f06a9e07e4718024dc4a59e3
```

Copy the bridge into your prepared application tree:

```powershell
Copy-Item arm64_bridge/dist/libParsons.so app/lib/arm64-v8a/libParsons.so -Force
```

Packaging additionally requires Bash (Git Bash on Windows), Java, apktool and
Android SDK Build Tools **37.0.0** or tools with equivalent 16 KiB page-alignment
support. Supply your own PKCS#8 signing key, X.509 certificate and expected
certificate SHA-256 digest. With `ANDROID_SDK_ROOT` already set, run in Bash:

```bash
export APKTOOL_JAR=tools/apktool.jar
export SIGNING_KEY=signing/signing-key.pk8
export SIGNING_CERT=signing/signing-cert.pem
export SIGNING_CERT_SHA256="$(openssl x509 -in "$SIGNING_CERT" -outform DER | openssl dgst -sha256 -r | cut -d ' ' -f 1)"
./build.sh
```

`JAVA_EXE` and `PYTHON_EXE` default to `java` and `python` on `PATH`.
`ANDROID_BUILD_TOOLS` can override the build-tools directory. Local keys,
application files, dependencies and generated outputs are ignored by Git.

The script writes `out/Carmageddon.apk`, verifies its signature and certificate,
checks ZIP alignment and the ARM64-only native ABI, and validates the complete
embedded OBB and uncompressed guest-library set.

## Checks

Run the host-side symbol-checker and packaging configuration tests without game
files or a device. Packaging tests use Bash and are skipped if it is unavailable:

```powershell
python -m unittest discover -s arm64_bridge/tests -p 'test_*.py' -v
```

To check the strong relocation-backed imports of your original libraries:

```powershell
$GuestLibraries = (Get-ChildItem app/assets/guest_libs/*.so).FullName
python arm64_bridge/check_symbols.py @GuestLibraries --src arm64_bridge/src
```

This checks provider coverage; it does not prove complete runtime ABI behavior.
`guest_varargs32_test.cpp` and `checkpoint_sort32_test.cpp` are standalone
assert-based C++ tests. Build Android component tests with `-BuildTests`, then
run `arm64_bridge/tests/run_android_tests.ps1 -Serial $env:ANDROID_SERIAL` on a
device you explicitly select. Device testing and memory sampling are optional
and are never part of a normal native build.

## Project status and limitations

Historical local testing reached menus and live 3D races with sound and touch
input, including an ARM64-only environment with 16 KiB pages. Checkpoint
progression, Back handling and background/resume paths also received targeted
checks. These observations apply to the tested game build and selected routes;
they are not a compatibility guarantee for every device or every race.

Long-duration thermal behavior, some effect and touch combinations, and private
or secondary-storage scenarios still need broader validation. Several repairs
depend on addresses and layouts in version 1.8.507. Other game versions require
their own analysis. Legacy diagnostics remain in the source and are normally
disabled by the supplied release wrapper. This publication does not claim a
new round of hardware acceptance testing.

## License

The original bridge code and scripts in this repository are licensed under
**GNU General Public License version 3 only (`GPL-3.0-only`)**. See [LICENSE](LICENSE).

Dependency licenses and game ownership remain separate; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No game files or rights to them
are provided by this repository.
