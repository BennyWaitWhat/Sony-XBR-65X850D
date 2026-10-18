# Build the persistence APK (Windows / PowerShell)
#
# Prerequisites: JDK 17, Android SDK build-tools, NDK (r21e used here).
# Produces: pwn.apk  (debuggable APK containing the JNI patcher + console service)
$ErrorActionPreference = 'Stop'
$Sdk      = "$env:LOCALAPPDATA\Android\Sdk"
$BuildTools = "$Sdk\build-tools\37.0.0"
$Jar      = "$Sdk\platforms\android-36\android.jar"
$Ndk      = "$Sdk\ndk\21.4.7075529"
$Clang    = "$Ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$Sysroot  = "$Ndk\toolchains\llvm\prebuilt\windows-x86_64\sysroot"
$Javac    = 'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin\javac.exe'
$JarTool  = 'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin\jar.exe'
$Out      = "$PSScriptRoot\out"; $Src = "$PSScriptRoot\src"; $Jni = "$PSScriptRoot\jni"

Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue
foreach ($d in "$Out\classes", "$Out\dex", "$Out\native\lib\armeabi-v7a") { New-Item -ItemType Directory -Force -Path $d | Out-Null }

Write-Host '[1/6] native library'
# -D_FILE_OFFSET_BITS=64 is REQUIRED: without it the 64-bit GPU VA used as an
# mmap() offset is truncated and the event mmap fails with ENOMEM.
& $Clang --target=armv7a-linux-androideabi21 --sysroot=$Sysroot -D_FILE_OFFSET_BITS=64 `
    -shared -fPIC -O2 -I "$Sysroot\usr\include" -llog `
    -o "$Out\native\lib\armeabi-v7a\libpwn.so" "$Jni\pwn.c"

Write-Host '[2/6] java'
$srcs = Get-ChildItem "$Src\com\pwn\probe\*.java" | ForEach-Object { $_.FullName }
& $Javac -source 8 -target 8 -cp $Jar -d "$Out\classes" $srcs

Write-Host '[3/6] dex'
$classes = Get-ChildItem "$Out\classes\com\pwn\probe\*.class" | ForEach-Object { $_.FullName }
& "$BuildTools\d8.bat" --lib $Jar --min-api 26 --output "$Out\dex" $classes

Write-Host '[4/6] package'
& "$BuildTools\aapt2.exe" link -o "$Out\base.apk" --manifest "$PSScriptRoot\AndroidManifest.xml" -I $Jar
& $JarTool -uf "$Out\base.apk" -C "$Out\dex" classes.dex
& $JarTool -uf "$Out\base.apk" -C "$Out\native" lib

Write-Host '[5/6] align'
& "$BuildTools\zipalign.exe" -f 4 "$Out\base.apk" "$Out\aligned.apk"

Write-Host '[6/6] sign'
$ks = "$PSScriptRoot\pwn.keystore"
if (-not (Test-Path $ks)) {
    & 'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin\keytool.exe' -genkeypair -v `
        -keystore $ks -alias k -keyalg RSA -keysize 2048 -validity 10000 `
        -storepass android -keypass android -dname "CN=pwn" | Out-Null
}
& "$BuildTools\apksigner.bat" sign --ks $ks --ks-pass pass:android --key-pass pass:android `
    --out "$PSScriptRoot\pwn.apk" "$Out\aligned.apk"

Write-Host ''
Write-Host "built: $PSScriptRoot\pwn.apk"
Write-Host 'install: adb install -r pwn.apk'
