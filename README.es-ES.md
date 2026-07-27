# Morok

Morok es un ofuscador de IR de LLVM New-PM modular escrito en C++23. Se carga como un plugin de paso (pass plugin) dentro de `clang` u `opt`, reescribe el IR de LLVM y emite un programa conductualmente equivalente con menos puntos de referencia estáticos estables, un flujo de datos y control más hostil y autoprotección en tiempo de ejecución opcional.

El proyecto sigue deliberadamente un enfoque de "pruebas primero". Las primitivas puras de aritmética y codificación residen por debajo de LLVM y son ejercitadas mediante pruebas unitarias exhaustivas y de propiedad. Los pasos de LLVM se prueban como emisores de IR y luego como una tubería completa compilando y ejecutando programas reales de C/C++ limpios frente a ofuscados.

Morok está destinado a binarios que poseas o que estés explícitamente autorizado a proteger y probar. Aumenta el costo del análisis estático y dinámico; no es un límite de confianza, un sistema de licencias por sí mismo, ni un sustituto de la firma de plataforma, atestación, sandboxing o políticas del lado del servidor.

No utilices Morok para ocultar malware, robo de credenciales, trampas, bypass no autorizados de terceros u otras actividades que no tengas permitido realizar.

## Contenidos

- [Alcance](#alcance)
- [Diseño del Repositorio](#diseño-del-repositorio)
- [Requisitos de Compilación](#requisitos-de-compilación)
- [Compilación](#compilación)
- [Puerta de Pruebas Autoritativa](#puerta-de-pruebas-autoritativa)
- [Uso Rápido](#uso-rápido)
- [Compilaciones Cruzadas y Sellado Post-Enlace](#compilaciones-cruzadas-y-sellado-post-enlace)
- [Modelo de Configuración](#modelo-de-configuración)
- [Presets](#presets)
- [Anotaciones](#anotaciones)
- [Orden del Planificador](#orden-del-planificador)
- [Inventario de Pasos](#inventario-de-pasos)
- [Referencia de Opciones TOML](#referencia-de-opciones-toml)
- [Notas de Plataforma](#notas-de-plataforma)
- [Notas sobre Resistencia a la Recuperación Estática](#notas-sobre-resistencia-a-la-recuperación-estática)
- [FAQ](#faq)
- [Flujo de Desarrollo](#flujo-de-desarrollo)
- [Resolución de Problemas](#resolución-de-problemas)
- [Documentos Relacionados y Ejemplos](#documentos-relacionados-y-ejemplos)
- [Licencia](#licencia)

## Alcance

Morok puede hacer cosas que un paso de IR de LLVM puede producir:

- Reescribir IR de enteros, punto flotante, punteros, pila, PHI, saltos, llamadas, cadenas, constantes, vtables y bytecode de VM.
- Emitir constructores, funciones auxiliares, hilos auxiliares, ensamblador en línea, manejadores de señales/excepciones, syscalls directas y sondas de tiempo de ejecución específicas de la plataforma en el binario objetivo.
- Generar diversidad determinista por compilación y por sitio de llamada a partir de una semilla (seed).
- Emitir manifiestos post-enlace para parches posteriores donde se necesiten los bytes nativos finales, con puertas de lanzamiento que eliminan los datos de bypass retenidos después del sellado.
- Mantener el crecimiento acotado con límites (caps) de funciones, módulos, sitios de llamada, tablas, payloads, clones, rutas y visitas.

Morok no puede hacer cosas que requieran infraestructura externa:

- No puede firmar archivos Mach-O o PE, provisionar entitlements, habilitar HVCI/PPL, ni activar características del compilador/enlazador como CFG/XFG/CET/PAC/BTI/RELRO.
- No puede proporcionar raíces de confianza remotas de TPM/SGX/TrustZone/SEV/Secure-Enclave.
- No puede hacer que un kernel, depurador, hipervisor o administrador hostil sea confiable.
- No puede hacer que todas las plataformas estén igualmente completas. Algunas rutas de tiempo de ejecución de alta intensidad están actualmente priorizadas para Apple y están restringidas en la suite de pruebas en otras partes.

El backlog de protecciones implementables se rastrea en [`docs/insurance-tasks.md`](docs/insurance-tasks.md). Los detalles de algoritmos y pasos residen en [`docs/algorithms.md`](docs/algorithms.md) y [`docs/hardness.md`](docs/hardness.md).

## Diseño del Repositorio

Morok está organizado en capas para que cada nivel dependa estrictamente del inferior:

```text
morok::core       Algoritmos puros: PRNGs, Feistel, GF(2^8), compartido XOR,
                  identidades MBA/sustitución, ayudantes MQ/T-function/Knuth.
                  Sin LLVM, sin E/S.

morok::config     Presets, carga de TOML, resolución de políticas, opciones de pasos.
                  Sin LLVM; el demangling es inyectado.

morok::ir         Capa auxiliar de LLVM: anotaciones, encubrimiento de símbolos,
                  adaptadores aleatorios de IR, utilidades de emisión compartidas.

morok::runtime    Emisores de IR de tiempo de ejecución compartido para primitivas de plataforma como
                  políticas de syscalls directas, protección de páginas, acceso a archivos y
                  selección de modo de tiempo de ejecución de Windows.

morok::passes     Implementaciones de pasos New-PM más funciones libres testeables.

morok::packer     Validación de ELF64 independiente de LLVM, finalización autenticada post-enlace
                  y verificación de artefactos finalizados.

morok_plugin      Plugin de paso New-PM cargable, emitido como libMorok.

morok-native-pack Ejecutable host utilizado por la etapa de construcción native-pack de Linux.
```

## Requisitos de Compilación

- CMake 3.28 o superior.
- Ninja.
- Un toolchain capaz de C11 y C++23.
- LLVM 18 o superior con la API de plugins New-PM que Morok requiere. Los toolchains actuales de CI y desarrollo utilizan el encabezado de plugin API-v2 en `<llvm/Plugins/PassPlugin.h>`.

Morok requiere que los encabezados de LLVM y los binarios de `clang`/`opt` utilizados en tiempo de ejecución coincidan en el mismo ABI de plugin de paso New-PM. La compilación verifica actualmente `<llvm/Plugins/PassPlugin.h>` con `LLVM_PLUGIN_API_VERSION == 2`; las instalaciones de LLVM más antiguas que solo exponen `<llvm/Passes/PassPlugin.h>` con la versión de API 1 tienen un ABI de plugin diferente y son rechazadas por [`cmake/MorokLLVM.cmake`](cmake/MorokLLVM.cmake) en lugar de fallar más tarde con un error críptico de carga de plugin.

El ayudante de prueba/compilación predetermina una instalación local de LLVM en `/Users/int/local`. Sobrescríbelo con `CC`, `CXX` y `LLVM_DIR` cuando uses otro LLVM compatible.

## Compilación

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
cmake --build build
ctest --test-dir build -j
```

Opciones útiles de CMake:

```text
MOROK_BUILD_TESTS=ON       compilar pruebas
MOROK_BUILD_PLUGIN=ON      compilar libMorok
MOROK_WERROR=OFF           tratar advertencias como errores cuando esté en ON
MOROK_SANITIZE=OFF         ASan/UBSan para capas puras/pruebas cuando esté en ON
```

Nombres de salida del plugin:

```text
macOS:   build/src/pipeline/libMorok.dylib
Linux:   build/src/pipeline/libMorok.so
Windows: build/src/pipeline/libMorok.dll
```

En Unix, el plugin es un módulo cargable que resuelve los símbolos de LLVM desde el proceso `clang`/`opt` que lo carga. En Windows, el plugin enlaza estáticamente las bibliotecas de componentes de LLVM que utiliza y exporta explícitamente `llvmGetPassPluginInfo`.

## Puerta de Pruebas Autoritativa

Utiliza el script de nivel superior a menos que estés intencionalmente limitando el ciclo:

```sh
./run_tests.sh            # configuración/compilación incremental + suite ctest configurada
./run_tests.sh --clean    # eliminar build/ y configurar desde cero
./run_tests.sh -R passes  # regex de nombre de ctest
./run_tests.sh -L ir      # filtro de etiquetas; las etiquetas incluyen core/config/ir/e2e,
                          # security/adversarial/programs/max/linux/threading,
                          # y core/config/ir/unit/aggregate
```

Cuando la validación de LLVM falla, CMake aún puede configurar solo las pruebas puras de core/config. Trata eso como una compilación parcial, no como la puerta completa para el trabajo de plugin o tubería. Con LLVM disponible, la puerta completa cubre:

| Capa | Estilo de prueba | Evidencia |
|---|---|---|
| `core` | suites doctest exhaustivas/de propiedad | las primitivas aritméticas, de campo, cifrado, PRNG, compartido e identidad son correctas independientemente de LLVM |
| `config` | suites doctest | presets, precedencia de fusión, resolución de políticas, parseo de TOML y rutas de error |
| `ir` / `passes` | pruebas de IR enlazadas a LLVM | cada paso emite IR limpio según el verificador y se activa en formas representativas |
| tubería completa | diferenciales limpio-vs-ofuscado | los binarios compilados preservan la salida a través de presets/configs/semillas |
| higiene de build/release | puertas e2e de shell/Python | el apilamiento de configuración estática, el default de compilación cruzada con semilla de entropía, GitHub Actions privilegiadas ancladas, política de auditoría de lanzamiento, guardias de falsos positivos en runtime y el comportamiento de fallo cerrado no sellado permanecen aplicados |
| corpus `programs/` | barridos de compilación y runtime, si están presentes | programas reales de C/C++ compilan en intensidad alta/máxima; programas deterministas curados también se ejecutan byte por byte igual |

Comportamiento de plataforma en la suite e2e:

| Host | Comportamiento E2E |
|---|---|
| Apple | Ejercita `high`/`max` integrados, `tests/e2e/max.toml`, pruebas diferenciales específicas de VM, auditoría de lanzamiento y pruebas de parcheo post-enlace adversario/fallo cerrado cuando Python está disponible. |
| No-Apple | Utiliza `tests/e2e/portable.toml` para rutas e2e de alta intensidad donde la virtualización y algunas rutas de runtime de anti-análisis/guardia-mutua aún no se han portado completamente. |
| Windows | Omite las pruebas e2e de carga de plugin behavioral dlopen; la cobertura proviene de pruebas core/config/IR y chequeos dirigidos a nivel de objeto. |

## Uso Rápido

Configura la ruta del plugin una vez:

```sh
PLUGIN=build/src/pipeline/libMorok.dylib  # macOS
# PLUGIN=build/src/pipeline/libMorok.so   # Linux
# PLUGIN=build/src/pipeline/libMorok.dll  # Windows
```

Tubería completa desde `clang`:

```sh
clang -O2 -fpass-plugin="$PLUGIN" \
  -mllvm -morok \
  -mllvm -morok-preset=high \
  -mllvm -morok-seed=1234 \
  prog.c -o prog
```

Tubería completa desde `opt`:

```sh
opt -load-pass-plugin "$PLUGIN" \
  -passes=morok prog.ll -o out.bc
```

Un paso independiente:

```sh
opt -load-pass-plugin "$PLUGIN" \
  -passes=morok-strenc prog.ll -o out.bc
```

La configuración se puede suministrar por bandera o entorno:

```sh
clang -O2 -fpass-plugin="$PLUGIN" \
  -mllvm -morok \
  -mllvm -morok-config=morok.toml \
  -mllvm -morok-seed=0xC0FFEE \
  prog.c -o prog

MOROK_CONFIG=morok.toml \
MOROK_SEED=0xC0FFEE \
clang -O2 -fpass-plugin="$PLUGIN" -mllvm -morok prog.c -o prog
```

Interruptores de entorno reconocidos por el plugin:

```text
MOROK_ENABLE=1                         activa la auto-inyección principal de clang sin -mllvm -morok
MOROK_CONFIG=path                      fallback de archivo de config cuando -morok-config está ausente
MOROK_PRESET=high                      fallback de preset cuando no se carga ningún archivo de config
MOROK_SEED=1234                        fallback de semilla cuando -morok-seed está ausente o es cero
MOROK_CKD_SEAL_REQUIRED=1              requiere un sello CKD post-enlace en lugar del fallback de auto-sellado al iniciar
MOROK_FAIL_CLOSED_ON_UNSEALED=1        envenena rutas dependientes de sellado si los manifiestos retenidos siguen sin sellar
MOROK_NATIVE_PACK=1                    habilita la frontera de IR native-pack ELF64 de Linux
MOROK_DISTRIBUTION_SIGNED=1            trata los hallazgos de get-task-allow de macOS como fallos de firma de lanzamiento
```

Cuando `-morok-config` o `MOROK_CONFIG` se cargan con éxito, ese archivo suministra la base del preset a través de `[global].preset`; `-morok-preset` solo se utiliza cuando no se carga ningún archivo de configuración. `-morok-seed` y `MOROK_SEED` sobrescriben la semilla de la configuración para compilaciones reproducibles.

Los equivalentes de línea de comandos para los interruptores estrictos de lanzamiento son `-mllvm -morok-ckd-seal-required` y `-mllvm -morok-fail-closed-on-unsealed`; la aserción de firma de distribución de macOS es `-mllvm -morok-distribution-signed`. Habilita los interruptores de sellado estricto solo para compilaciones donde el binario será sellado post-enlace antes de la primera ejecución; una compilación estricta no sellada debe fallar cerrada en lugar de recuperarse silenciosamente.

Para `clang -fpass-plugin`, Morok también registra callbacks de puntos de extensión:

- vectorizer-start: amplificación del optimizador temprano cuando está habilitado.
- pipeline-early-simplification: preservación de candidatos de VM para `-mllvm -morok`.
- optimizer-last: el planificador principal de Morok.

Usa la bandera explícita `-mllvm -morok` para compilaciones pesadas de VM. La ruta de solo entorno `MOROK_ENABLE` actualmente habilita los callbacks principales del optimizador pero no activa el callback temprano de preservación de candidatos de VM.

## Compilaciones Cruzadas y Sellado Post-Enlace

El ayudante en [`cross_build.sh`](cross_build.sh) compila un archivo fuente a través de Morok para Linux y/o macOS. En hosts Linux, las compilaciones de macOS están deshabilitadas por defecto y el ayudante utiliza el plugin ELF (`libMorok.so`) con el target nativo de GNU Linux. En hosts macOS, el default sigue siendo Linux más macOS con el plugin Mach-O (`libMorok.dylib`) y el target cruzado musl:

```sh
./cross_build.sh --source programs/cf_license_crackme.c --out-dir build/cross
./cross_build.sh --linux-only --source programs/01_hello_world.c --out-dir build/cross
./cross_build.sh --macos-arches "arm64 x86_64" --preset max
./cross_build.sh --config morok.toml --seed 832040
```

Opciones comunes:

| Opción | Significado |
|---|---|
| `--source PATH` | Archivo fuente a compilar. También se acepta una ruta de fuente posicional. |
| `--out-dir DIR` | Directorio de salida. |
| `--preset NAME` | Preset a utilizar cuando no se suministra `--config`. |
| `--config PATH` | Archivo de configuración TOML a utilizar en lugar de una compilación solo con preset. |
| `--seed N` | Semilla determinista de Morok. |
| `--clang PATH`, `--clangxx PATH` | Drivers de compilador C/C++ que coincidan con el ABI de LLVM del plugin. |
| `--plugin PATH` | Ruta del plugin de Morok. |
| `--linux-target TRIPLE` | Triple de target de Linux. |
| `--linux-cc PATH` | Driver de toolchain cruzado de Linux compatible con GCC para búsqueda de crt/libgcc. |
| `--macos-arches LIST` | Arcos de macOS o triples de target separados por espacios; requiere un host Darwin. |
| `--macos-min VERSION` | Target de despliegue de macOS. |
| `--linux-only`, `--macos-only` | Compilar solo una familia de plataformas. |
| `--no-linux`, `--no-macos` | Omitir una familia de plataformas. |
| `--no-strip` | Dejar los binarios producidos sin strip. |
| `--no-audit` | Omitir la puerta de lanzamiento final de `morok-audit`. |
| `--clean` | Borrar el directorio de salida antes de compilar, tras rechazar rutas inseguras fuera del árbol de compilación canónico. Esto es opcional para el aislamiento de la auditoría. |
| `--dynamic` | Compilar Linux dinámicamente; el modo Linux predeterminado es estático. |
| `--elf-shadow` | Para salidas dinámicas de Linux/x86-64, aplicar el sombreado de símbolos/offsets `DT_JMPREL` post-enlace. |
| `--no-elf-shadow` | Deshabilitar el sombreado de relocalización ELF (predeterminado). |
| `--native-pack` | Compilar una salida ELF64 de Linux con empaquetado de código nativo autenticado perezoso; implica `--linux-only`. |
| `--no-native-pack` | Deshabilitar el empaquetado de código nativo (predeterminado). |
| `--extra-cflags FLAGS` | Banderas adicionales del compilador. |
| `--extra-sources PATHS` | Archivos fuente adicionales compilados junto con la fuente principal. |
| `--libs FLAGS` | Bibliotecas de enlace adicionales. |
| `--c-std STD` | Sobrescribir el estándar del lenguaje C/C++ para el comando de compilación. |
| `-h`, `--help` | Mostrar la ayuda del script. |

Los sobrescritores de entorno reconocidos incluyen `BUILD_DIR`, `OUT_DIR`, `CLANG`, `CLANGXX`, `PLUGIN`, `PRESET`, `SEED`, `OPT_LEVEL`, `LINUX_TARGET`, `LINUX_CC`, `LINUX_STATIC`, `LINUX_SYSROOT`, `LINUX_STRIP`, `MACOS_ARCHES`, `MACOS_MIN`, `MACOS_SDK`, `EXTRA_SOURCES`, `EXTRA_CFLAGS`, `LIBS`, `SEAL_BINARIES`, `SEAL_WINDOW`, `SEAL_TOOL`, `AUDIT_BINARIES`, `AUDIT_TOOL`, `AUDIT_PROVENANCE`, `AUDIT_ALLOWLIST`, `ELF_SHADOW`, `ELF_SHADOW_TOOL`, `ELF_SHADOW_MAX_BYTES`, `NATIVE_PACK`, `NATIVE_PACK_TOOL`, `NATIVE_PACK_LOADER`, `NATIVE_PACK_META`, `NATIVE_PACK_SCRIPT`, y `PYTHON`.

Valores predeterminados importantes:

```text
fuente:       programs/cf_license_crackme.c
dir salida:   build/cross
preset:       max, a menos que se proporcione --config
semilla:      0, lo que significa entropía por compilación
optimización: -O3
clang:        clang-23
plugin:       build/src/pipeline/libMorok.so en Linux, libMorok.dylib en macOS
target Linux: triple GNU nativo en hosts Linux, x86_64-linux-musl en otros lugares
macos min:    13.0, usado solo cuando las compilaciones de macOS están habilitadas
strip:        habilitado
sellado:      habilitado
```

Para salidas estáticas de Linux, `cross_build.sh` deriva una configuración TOML temporal que fuerza `[passes.function_call_obfuscate].enabled = false` y establece `[passes.platform_runtime].static_link_expected = true`. Un binario totalmente estático no tiene cargador dinámico, por lo que la búsqueda de importaciones dinámicas no tiene una superficie de ocultación útil y puede chocar si se deja habilitada. La bandera de enlace estático también habilita el tripwire `AT_BASE` de Linux, que pliega un mapeo de cargador dinámico en el sello de runtime solo para compilaciones que se espera que sean `-static`; las salidas dinámicas ordinarias deben dejarlo desactivado.

Algunos drivers de Linux compatibles con GCC reportan un sysroot vacío mientras siguen devolviendo rutas usables de `crt1.o` y `libgcc.a`. En ese caso, el ayudante omite `--sysroot` y sigue usando los directorios de búsqueda de CRT/biblioteca proporcionados por el driver.

El sellado post-enlace es obligatorio para binarios distribuibles que dependen de ventanas de código nativo de `self_checksum_constants`, `mutual_guard_graph` o `caller_keyed_dispatch`. Los pasos de IR reservan manifiestos retenidos, pero los rangos finales de bytes de código solo se conocen después del enlace y el strip. `cross_build.sh` sella automáticamente después del strip y falla cerrado si no hay manifiestos presentes. El sellador post-enlace utiliza la ventana `--window` solicitada como límite de cobertura de hash de código nativo; el ajuste `region_bytes` de datos aleatorios de auto-chequeo no limita la cobertura de código. Luego ejecuta `tools/morok-audit.py` con un selector `--include` por cada artefacto producido por la invocación actual. Esto mantiene el directorio de salida como la raíz de procedencia sin tratar archivos no relacionados en un `--out-dir` existente como salidas de lanzamiento. Los artefactos seleccionados se chequean en busca de manifiestos no sellados, estado de manifiesto marcador de posición (placeholder), rutas de desarrollo embebidas, marcadores de lanzamiento de alto valor en texto plano y marcadores mágicos/centinela en texto plano.

Cuando el sellado de macOS está habilitado, `cross_build.sh` también pasa las banderas de sellado estricto (`-morok-ckd-seal-required` y `-morok-fail-closed-on-unsealed`) antes del paso de sellado post-enlace/re-firma. Las salidas de Linux siguen siendo selladas y auditadas por defecto, pero el ayudante deja esas banderas estrictas del plugin desactivadas para la ruta de compilación de Linux; añádelas solo en una tubería que haya demostrado que su paso de sellado de Linux es obligatorio y se ejecuta antes de que el binario pueda ejecutarse.

El sellado manual es:

```sh
python3 tests/e2e/adversarial_binary.py seal path/to/binary --window 262144
```

En macOS, un sellado en el sitio invalida la firma ad hoc, por lo que el ayudante vuelve a firmar el binario después del parcheo.

La auditoría de lanzamiento manual es:

```sh
python3 tools/morok-audit.py build/cross --release --require-sealed-manifest \
  --provenance build/cross/morok-audit.json
```

La auditoría verifica los registros post-enlace de auto-chequeo, guardia-mutua y despacho basado en el llamador, escanea archivos adjuntos, secciones de símbolos privados/depuración, variantes de binarios no soportados, etiquetas de salida en texto plano y cadenas de marcadores de alto valor, y luego escribe un manifiesto de procedencia con hashes de archivos, formatos de binarios detectados, recuentos de manifiestos sellados y cualquier hallazgo. Los hallazgos de lanzamiento son fallos críticos. Los accesorios de prueba deben ser incluidos en la lista blanca explícitamente con un archivo JSON versionado:

Sin `--include`, una auditoría de directorio manual sigue siendo recursiva. Repite `--include path/to/artifact` para restringir una auditoría a archivos nombrados debajo de la raíz de auditoría; los archivos faltantes, directorios, escapes de enlaces simbólicos y rutas fuera de la raíz fallan con `invalid-audit-include`.

```json
{
  "version": 1,
  "allow": [
    {"path": "fixtures/*.pem", "checks": ["private-key-sidecar"]}
  ]
}
```

### Empaquetado de código nativo ELF64 de Linux

El empaquetado nativo es un modo explícito de tubería de compilación para artefactos `ET_EXEC`/`ET_DYN` de Linux x86-64 y AArch64. No está habilitado por un preset porque cambia el contrato de enlace:

```toml
[passes.string_encryption]
enabled = true
probability = 100

[passes.native_code_pack]
enabled = true
probability = 100
max_functions = 32
min_instructions = 1
protect_generated = false
```

```sh
./cross_build.sh --native-pack --linux-target x86_64-linux-gnu \
  --source programs/01_hello_world.c --config morok.toml
```

El paso final de IR mueve cada implementación seleccionada a una sección de entrada protegida y deja un stub de entrada ABI-equivalente en el símbolo original. El stub invoca un cargador independiente oculto en la primera entrada protegida, verifica una ecuación diversa según la semilla por stub y realiza una transferencia de cola (tail-transfer) a la implementación solo después de que la región protegida esté lista. Esto es perezoso; ningún constructor ELF realiza la decodificación. Una máquina de estado de futex privado serializa la primera entrada concurrente y cachea la región abierta para llamadas posteriores.

`cross_build.sh` inyecta exactamente un objeto cargador/metadatos, enlaza una región ejecutable aislada de 64 KiB, realiza el strip y el sellado primero, y luego ejecuta `morok-native-pack finalize`. El finalizador resuelve direcciones virtuales ELF autorrelativas, audita relocalizaciones y constructos de ejecución temprana, cifra los bytes de máquina finales acolchados por página con [RFC 8439 ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html), elimina los nombres descriptivos de las secciones y recalcula el GNU build ID de 20 bytes sobre el archivo finalizado. En tiempo de ejecución, el cargador autentica el texto cifrado antes de hacer que las páginas aisladas sean `RW`, descifra, realiza el mantenimiento del caché de instrucciones AArch64 cuando es necesario y restaura `RX`; nunca solicita `RWX`.

El productor rechaza en lugar de adivinar cuando encuentra GNU IFUNC, `R_*_IRELATIVE`, `DT_TEXTREL`, una relocalización dinámica hacia texto cifrado, una dirección `DT_INIT` dentro de texto cifrado, límites no aislados, variantes de ELF no soportadas, manifiestos múltiples/ausentes o un GNU build ID de tamaño SHA-1 faltante. Todas las direcciones de runtime son autorrelativas, por lo que PIE y los objetos compartidos siguen siendo correctos según ASLR. El sidecar de la clave tiene modo `0600`, se consume después de la finalización exitosa y es rechazado por la auditoría de lanzamiento si entra en el paquete de salida.

La verificación está disponible independientemente de la clave:

```sh
build/src/packer/morok-native-pack verify path/to/artifact
python3 tools/morok-audit.py path/to/bundle --release \
  --require-native-pack \
  --native-pack-tool build/src/packer/morok-native-pack
```

La región autenticada detecta la corrupción y hace que el desensamblado solo de archivo de los cuerpos seleccionados opere sobre texto cifrado. Es una capa de endurecimiento de análisis estático y código en reposo, no un límite de confidencialidad en tiempo de ejecución: tanto las partes de la clave como el texto plano necesariamente se vuelven disponibles dentro del proceso en ejecución. Un observador local capaz de instrumentar el cargador o leer la memoria del proceso puede recuperar los bytes abiertos. El cifrado/descifrado tiene un tiempo `Theta(N)` para `N` bytes protegidos y un espacio auxiliar `Theta(1)`; el grupo del enlazador actual ensucia privadamente aproximadamente `ceil(N/P)` páginas para el tamaño de página de runtime `P`. Usa la selección de funciones y `max_functions` para acotar el trabajo de inicio y la memoria privada sucia.

### Sombreado de relocalizaciones ELF de Linux

Las compilaciones dinámicas de Linux/x86-64 pueden optar por la divergencia de vista del cargador después del enlace, el strip y el sellado:

```sh
./cross_build.sh --linux-only --dynamic --elf-shadow \
  --source programs/01_hello_world.c
```

La transformación post-enlace envenena ambos campos independientes que las herramientas estáticas utilizan para atribuir llamadas PLT. Cada registro convencional `R_X86_64_JUMP_SLOT` nombra un símbolo dinámico señuelo similar a una función y diverso según la semilla. Cuando existen al menos dos relocalizaciones PLT, sus valores `r_offset` convencionales también se colocan en una desorganización de ciclo único basada en semilla: cada registro parece poblar el slot GOT de otro sitio de llamada, sin puntos fijos. La selección de señuelos excluye tanto el símbolo ordinal real del registro como el símbolo real perteneciente a su objetivo GOT aparente. En consecuencia, los analizadores que asocian llamadas por ordinal de relocalización y los analizadores que las asocian por destino GOT reciben nombres falsos. Una tabla de entrada única conserva la decepción de símbolos porque no tiene una permutación `r_offset` no trivial.

La transformación preserva las páginas de relocalización originales completas en un offset de archivo alineado por página adjunto y reutiliza un encabezado de programa `PT_NULL` o `PT_NOTE` posterior como un `PT_LOAD`. Cuando se habilita a través de `cross_build.sh`, el enlace añade una nota de build-ID SHA-1 estándar para que los diseños compactos de lld/musl también reserven tal encabezado sin descartar `PT_PHDR`, `PT_DYNAMIC`, `PT_GNU_EH_FRAME`, `PT_GNU_STACK` o `PT_GNU_RELRO`. Linux procesa la nueva carga después del segmento ordinario y mapea el rango de páginas preservadas sobre las mismas páginas virtuales. Por lo tanto, el cargador de runtime consume los valores originales de `r_info`, `r_offset` y el adendo. El enlace perezoso y ansioso, el RELRO completo y el almacenamiento en caché normal de una sola vez del GOT permanecen sin cambios.

El productor es de fallo cerrado y acotado. Acepta solo archivos `ET_EXEC`/`ET_DYN` de Linux/x86-64 little-endian con páginas de cargador de 4096 bytes, relocalizaciones PLT `Elf64_Rela`, un mapa de carga de entrada no superpuesto y unívoco, al menos dos símbolos dinámicos similares a funciones y un encabezado `PT_NULL`/`PT_NOTE` posterior reutilizable. Si no existe ninguno de los dos tipos de repuesto, la aplicación independiente rechaza el binario e instruye al llamador a relinkear con `--build-id`. El límite de sombra predeterminado es 1 MiB. El crecimiento del archivo es la extensión de la relocalización redondeada por página más un máximo de 4095 bytes de alineación; las llamadas no tienen instrucciones de estado estacionario ni asignaciones de memoria añadidas. Los binarios estáticos, otras arquitecturas, diseños pre-superpuestos y binarios sin un encabezado seguro de repuesto son rechazados sin escribir la salida.

La entrada `PT_NOTE` reservada del build-ID es consumida por el `PT_LOAD` de la sombra. La sección de la nota y los bytes del archivo siguen estando disponibles para los lectores estáticos, pero el código de runtime que enumera los encabezados del programa no descubrirá el build ID como un `PT_NOTE`. Las tuberías que requieren la detección del build-ID en tiempo de ejecución deben dejar este mecanismo deshabilitado o proporcionar un slot de encabezado de programa desechable separado.

Este mecanismo cambia la atribución del sitio de llamada, no el inventario completo de símbolos importados, y la superposición de `PT_LOAD` redondeada por página sigue siendo una señal de detección consciente del cargador. La permutación de offset convencional es recuperable como una permutación una vez que se reconstruye la imagen original del cargador; aumenta el desacuerdo entre los modelos de análisis precisos de segmento pero no oculta el mapeo superpuesto en sí. Por lo tanto, el mecanismo se compone con la ofuscación de llamadas a funciones pero no la reemplaza. La implementación sigue las reglas de alineación de encabezados de programa ELF64 en el [System V gABI](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html), el mapeo ordenado redondeado por página de Linux en [`fs/binfmt_elf.c`](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c) y el modelo de cargador dinámico documentado de glibc en el [manual de la GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker.html).

La aplicación y verificación manuales son:

```sh
python3 tools/morok_elf_shadow.py apply path/to/binary --seed 832040
python3 tools/morok_elf_shadow.py verify path/to/binary
```

## Modelo de Configuración

El apilamiento de configuración es intencionalmente simple:

1. `[global].preset` carga `low`, `mid`, `high`, `max`, o `none`.
2. Las secciones `[passes.*]` sobrescriben solo los campos que mencionan.
3. Las reglas `[[policy]]` ordenadas pueden aplicar otro preset y/o sobrescrituras de pasos a regex de módulos/funciones coincidentes.
4. `-mllvm -morok-seed=N` o `MOROK_SEED=N` sobrescribe la semilla de la configuración para compilaciones deterministas.

Claves globales de nivel superior:

```toml
[global]
preset = "high"
seed = 0xDEADBEEF1337
verbose = false
trace = false
demangle_names = true
```

Ejemplo:

```toml
[global]
preset = "high"
seed = 0xDEADBEEF1337
demangle_names = true

[passes.string_encryption]
enabled = true
probability = 100
skip_content = ["Usage:"]

[passes.function_call_obfuscate]
enabled = true

[passes.windows_process_mitigations]
enabled = true

[[policy]]
function = "^main$"
passes.bcf.enabled = false
passes.substitution.enabled = false

[[policy]]
function = "license|verify|decrypt"
passes.mba.enabled = true
passes.external_opaque_predicates.enabled = true
passes.virtualization.enabled = true
```

Las políticas se evalúan en el orden del archivo por [`src/config/Resolver.cpp`](src/config/Resolver.cpp). Las regex coinciden con el nombre del archivo fuente del módulo y/o el nombre de la función. Si `demangle_names = true`, la coincidencia de funciones de política utiliza nombres demangled donde sea posible.

## Presets

| Preset | Intención |
|---|---|
| `none` | Sin base de preset. Solo se aplican las secciones de pasos o políticas habilitadas explícitamente. |
| `low` | Reescritura ligera de escalares/control, cifrado de cadenas, compartido de constantes, bloques divididos y cadenas señuelo retenidas. |
| `mid` | Ofuscación de escalares/control más amplia con más densidad y características de vector/tabla que `low`. |
| `high` | Modo agresivo acotado: rebanadas limitadas de VM/auto-descifrado/integridad/tabla/MQ/microstress/envoltorio-de-función mientras se mantienen controladas las búsquedas costosas en todo el grafo. Los controles de payload de página con falla están preestablecidos pero son opcionales, mientras que el backend portable es `lazy_accessor`. |
| `max` | Stack completo gestionado por preset: probabilidades altas, presupuestos máximos probados, bundle de anti-debug/anti-hook/timing/trap, FCO, VM, auto-descifrado, integridad, enrutamiento, envoltorios, interruptores de pasos de Windows y señuelos. La entrega de payload de página con falla sigue siendo opcional hasta que un backend respaldado por el SO cumpla con la puerta de runtime máxima. |

El planificador impone límites de instrucciones, bloques, funciones, módulos, bytes, tablas, rutas, sitios de llamada, clones, payloads y visitas. Si una función o módulo crece más allá del presupuesto relevante, los pasos de crecimiento posteriores se omiten en lugar de permitir una expansión de IR ilimitada.

## Anotaciones

Las anotaciones de fuente se copian de `llvm.global.annotations` de Clang a los metadatos de Morok antes de la planificación:

```c
__attribute__((annotate("sub")))       static int force_sub(int x) { return x + 1; }
__attribute__((annotate("nosub")))     static int skip_sub(int x)  { return x + 1; }
__attribute__((annotate("sensitive"))) static int hot_secret(int x) { return x * 7; }
```

Las claves de anotación por función son las etiquetas del planificador:

```text
aliasop, bcf, csm, constenc, decoy, dfi, dispatchless, entfla, extop,
fla, ifsm, indibran, mba, microstress, mq, mutualguard, nistate, optamp,
nativepack, pathexplode, phitangle, ptrlaunder, selfcheck, shamir, split,
stackcoalesce, stackdelta, stackrebase, stateop, sub, tablearith, threshold,
tracekey, typepun, uniform, vobf
```

Antepon `no` a cualquier clave para forzar la desactivación de ese paso para una función, por ejemplo `nomba`, `nobcf` o `noconstenc`.

`nativepack` fuerza una función al grupo protegido ELF64 de Linux incluso por debajo del umbral de instrucciones configurado; `nonativepack` la excluye. Los constructores, destructores, formas de ABI no soportadas y funciones de dirección de bloque permanecen excluidos incluso cuando la selección de probabilidad ordinaria los elegiría.

`sensitive` es especial: cuando BCF, MBA o predicados opacos externos están desactivados o habilitados, el planificador aumenta su densidad en esa función. Las anotaciones negativas explícitas siguen ganando.

## Orden del Planificador

El paso `morok` de la tubería completa está ordenado para preservar la semántica y maximizar la composición:

```text
configuración de runtime de plataforma / política de syscalls directas
-> planificación de clones/hubs de Mirage
-> material de claves de prueba externa, entorno, trazador y blobs sellados
-> marcado de prioridad de VM
-> VM(código de usuario)
-> entrega de payload de VM por página con falla
-> auto-descifrado de VM restringido por hash para payloads ansiosos restantes
-> anti-hook / anti-class-dump / sustrato de Windows y sondas de Windows
-> anti-debug / timing / paso-del-planificador / trap / falla-de-página / caché / sondas microarquitecturales
-> cadenas señuelo
-> cifrado de cadenas
-> integridad de vtable
-> fisión de funciones
-> pasos estructurales, escalares, CFG, flujo de datos, integridad y literales por función
-> puesta al día de integridad garantizada
-> vinculación de sellos de ayudantes-hoja y semillas de cadena
-> VM/endurecimiento para ayudantes de protección generados
-> entrega de payload de VM tardía / auto-descifrado para payloads de ayudantes generados
-> nanomites
-> auto-ajuste adversario / fusión de funciones
-> ofuscación de llamadas a funciones
-> despacho basado en el llamador
-> despacho sin retorno
-> envoltorios de funciones
-> polimorfismo por compilación
-> metadatos engañosos
-> frontera de ABI de empaquetado de código nativo
-> limpieza de privacidad de símbolos generados
```

Dentro del bucle por función, Morok ejecuta transformaciones estructurales y de nivel de valor antes del enrutamiento/integridad/ocultación de literales:

```text
des-switch de constantes de puerta anchas
-> split
-> BCF
-> amplificación del optimizador
-> sustitución
-> MBA
-> persistencia por debajo del umbral
-> alias/predicados opacos externos
-> señuelos coherentes
-> exactamente un miembro de la familia de aplanado: NiState / EntFla / CSM / Flatten
-> predicados opacos de estado
-> FSM interprocedural
-> enredo de PHI
-> punteo de tipos (type punning)
-> coalescencia de pila
-> juegos de delta de pila
-> rebase de pila
-> lavado de punteros
-> DFI
-> aritmética de tablas
-> reducción de primitivas uniformes
-> ofuscación de vectores
-> explosión de rutas
-> puertas MQ
-> claveo de traza
-> enrutamiento sin despachador
-> estrés de microcódigo
-> constantes de auto-checksum
-> grafo de guardia-mutua
-> compartido de Shamir
-> cifrado de constantes
-> rescate de cifrado de constantes solo-condicional
-> salto indirecto
```

El código en [`src/pipeline/Scheduler.cpp`](src/pipeline/Scheduler.cpp) es la fuente de verdad para el orden mantenido; [`docs/algorithms.md`](docs/algorithms.md) expande la lógica de las restricciones de orden principales.

## Inventario de Pasos

Cada paso puede ejecutarse de forma independiente con `-passes=morok-*` donde el plugin registre ese nombre, o a través del planificador con una sección TOML. Las filas marcadas como `scheduler-only` tienen soporte de configuración pero no un callback de parseo de plugin actual. Algunas transformaciones de higiene final, como los metadatos engañosos, la vinculación de sellos de ayudantes-hoja, el endurecimiento de ayudantes de protección y la limpieza de enlace privado para ayudantes `morok.*` generados, son solo del planificador.

### Estructurales, Flujo de Control y Estrés de Descompilador

| Capacidad | nombre `-passes` | sección TOML | Resumen |
|---|---|---|---|
| Dividir bloques básicos | `morok-split` | `split_blocks` | Divide bloques en más objetivos de despacho. |
| Fisión de funciones | solo planificador | `function_fission` | Extrae regiones de una sola entrada/una sola salida de una función en nuevos llamados internos `morok.fission.*` (vía `CodeExtractor`), por lo que los límites de la función fuente ya no coinciden con el binario y el grafo de llamadas se expande. Encoger las originales también devuelve las funciones sobredimensionadas bajo los presupuestos de ofuscación/integridad por función para que los pasos de vinculación de sellos puedan alcanzarlas. Las partes se marcan `noinline`; las funciones EH/`setjmp`/varargs/goto-computado se omiten. |
| Flujo de control falso | `morok-bcf` | `bcf` | Añade aristas de basura/señuelo guardadas por opacos-verdaderos con entropía opcional y presión de asm-en-línea. |
| Aplanado | `morok-flatten` | `flattening` | Aplanado de flujo de control clásico mediante despachador switch. |
| Aplanado entrelazado de datos | `morok-entfla` | `data_entangled_flattening` | Almacena el estado sucesor a través de datos vivos y tokens de estado previo. |
| Estado no invertible | `morok-nistate` | `non_invertible_state` | Utiliza hashes con pérdida claveados para estados de despachador codificados. |
| Predicados opacos de estado | `morok-stateop` | `state_opaque_predicates` | Coloca guardias opacos sobre el estado aplanado más términos vivos escalares. |
| FSM interprocedural | `morok-ifsm` | `interprocedural_fsm` | Enruta transiciones de estado aplanadas a través de llamadas a ayudantes mutuamente recursivos. |
| Máquina de estado de caos | `morok-csm` | `chaos_state_machine` | Aplanado a través de la evolución del estado de mapa logístico o T-function. |
| Aplanado de T-function | `morok-tfa` | `chaos_state_machine` | Variante de CSM independiente conveniente que utiliza un generador de T-function de ciclo único. |
| Enrutamiento sin despachador | `morok-dispatchless` | `dispatcherless_routing` | Reemplaza aristas de salto/switch directos con DAGs de `indirectbr` entrelazados con el estado. |
| Salto indirecto | `morok-indbr` | `indirect_branch` | Reduce las aristas condicionales/switch sobrevivientes a través de tablas `indirectbr` aleatorizadas. |
| Estrés de microcódigo | `morok-microstress` | `microcode_stress` | Emite tablas de `blockaddress` sobredimensionadas y destinos señuelo aliasados. |
| Explosión de rutas | `morok-pathexplode` | `path_explosion` | Añade bucles señuelo derivados de la entrada guardados por opacos y almacenes simbólicos volátiles. |
| Señuelos coherentes | `morok-decoy` | `coherent_decoys` | Añade computaciones de retorno alternativas plausibles muertas y estado de manipulación señuelo oculto. |
| Mirage | `morok-mirage` | `mirage` | Sustrato de computación falsificada. Reemplaza el cuerpo de una función tipo veredicto seleccionada con un hub de despacho sin saltos sobre una tabla de candidatos privada de `2` clones reales equivalentes más `2` algoritmos falsificados plausibles pero incorrectos (plantillas integradas de `license_check`/`signature_verify`/`token_validate`/`feature_flag`). En un estado de sello de runtime limpio, el hub enruta a un clon real elegido de una época por invocación — por lo que una traza dinámica nunca observa toda la población; en un estado de sello sucio (evidencia de anti-debug/vinculación-entorno/trazador) enruta a un falsificado, por lo que la manipulación produce una denegación plausible en lugar de un trap. Los clones reales son equivalentes por construcción (clon + transformaciones normales de Morok); el clon real 1 tiene prioridad de VM con un fallback pesado en nativo divergente. Los candidatos tienen enlace privado (los nombres nunca llegan a la tabla de símbolos). Desactivado por defecto; opcional vía `[passes.mirage]`. La guardia mutua entre candidatos es una extensión de fase 2. |
| Predicados opacos de alias | `morok-aliasop` | `alias_opaque_predicates` | Mantiene invariantes de puntero/alias que guardan aristas señuelo. |
| Predicados opacos externos | `morok-extop` | `external_opaque_predicates` | Utiliza guardias de ayudantes volátiles bloqueados por IPO y brazos señuelo de rascado. |
| Puerta MQ | `morok-mq` | `mq_gate` | Planta puertas opacas cuadráticas GF(2) sobre bits derivados de argumentos. |
| Nanomites | `morok-nanomites` | `nanomites` | Reemplaza saltos seleccionados con búsqueda de objetivos cifrados mediados por traps en triples POSIX soportados. |
| Fusión/extracción adversaria | `morok-afm` | `adversarial_function_merging` | Fusiona funciones con la misma firma detrás de despachadores selectores y extrae fragmentos escalares. |
| Auto-ajuste adversario | `morok-selftune` | `adversarial_self_tuning` | Puntúa bundles de candidatos clonados y reproduce el bundle más fuerte limpio según el verificador. |
| Polimorfismo por compilación | `morok-polymorph` | `per_build_polymorphism` | Reordena funciones/bloques y añade anclajes de retorno volátiles neutros desde la semilla. |

### Ofuscación de Escalares, Flujo de Datos, Pila y Literales

| Capacidad | nombre `-passes` | sección TOML | Resumen |
|---|---|---|---|
| Sustitución de instrucciones | `morok-substitution` | `substitution` | Reescribe ops de enteros en árboles de expresión equivalentes. |
| Aritmética Booleana Mixta (MBA) | `morok-mba` | `mba` | Capas identidades MBA y términos de ruido cero. |
| Amplificación del optimizador | `morok-optamp` | `optimizer_amplification` | Emite formas equivalentes seleccionadas por entrada antes de la reducción del optimizador. |
| Persistencia por debajo del umbral | `morok-threshold` | `sub_threshold_persistence` | Añade términos opacos-cero de semilla local volátil por debajo de los umbrales de plegado. |
| Cifrado de constantes | `morok-constenc` | `constant_encryption` | Reconstruye literales a partir de partes XOR volátiles y capas opcionales de Feistel/compartido. |
| Compartido de umbral Shamir | `morok-shamir` | `shamir_share` | Reconstruye literales escalares seleccionados a partir de partes de umbral GF(2^8) volátiles. |
| Aritmética de tablas | `morok-tablearith` | `table_arithmetic` | Reduce ops de rango estrecho/indexadas por constante a tablas de búsqueda perezosas cifradas. |
| Reducción de primitivas uniformes | `morok-uniform` | `uniform_primitive_lowering` | Reduce ops de bytes y saltos seleccionados a despacho cargado desde memoria mediante tablas. |
| Ofuscación de vectores | `morok-vec` | `vector_obfuscation` | Eleva ops/casts/comparaciones/selecciones escalares a carriles SIMD. |
| Coalescencia de pila | `morok-stackcoalesce` | `stack_coalescing` | Colapsa allocas estáticas en un único buffer de bytes opaco. |
| Juegos de delta de pila | `morok-stackdelta` | `stack_delta_games` | Añade deltas dinámicos del puntero de pila y toques de pila volátiles superpuestos. |
| Rebase de pila | `morok-stackrebase` | `stack_rebase` | Presiona el backend hacia marcos de pila realineados/dinámicos, escapa direcciones de marco seleccionadas a través de sumideros volátiles y opcionalmente inserta ruido de VLA no entrada acotado antes del lavado de punteros. Omite código generado, targets de Windows, varargs, EH/personality, funciones sensibles a sanitizers/endurecimiento, intrínsecos riesgosos de corrutina/SJLJ/localescape/statepoint, llamadas musttail/asm-en-línea/operand-bundle y llamados tipo setjmp. |
| Lavado de punteros | `morok-ptrlaunder` | `pointer_laundering` | Envía punteros/escalares a través de fronteras de puntero-int y vector-de-bytes. |
| Punteo de tipos | `morok-typepun` | `type_punning` | Realiza viajes redondos de escalares a través de cadenas de reinterpretación de buffer de unión volátiles. |
| Enredo de PHI | `morok-phitangle` | `phi_tangling` | Construye redes de PHI escalares redundantes y copias de valores en aristas cruzadas. |

### Cadenas, Importaciones, Llamadas y Despacho C++

| Capacidad | nombre `-passes` | sección TOML | Resumen |
|---|---|---|---|
| Cifrado de cadenas | `morok-strenc` | `string_encryption` | Cifra globales de arrays de bytes privados elegibles con un cifrador único por cadena. Las llamadas seguras a C-strings se materializan en buffers de pila por uso; los usos no soportados reciben descifradores de constructor por cadena. |
| Blobs sellados | `morok-sealedblob` | `sealed_blob` | Cifra globales de arrays de bytes `.morok.sealed` explícitos y reescribe lecturas soportadas a través de accesores perezosos por blob claveados por el material de RuntimeSeal/prueba externa, con diagnósticos opcionales de prefijo mágico claveado en runtime. |
| Ofuscación de llamadas a funciones | `morok-fco` | `function_call_obfuscate` | Oculta llamadas externas detrás de una indirección de importación por sitio. Las rutas de 64 bits de Linux/macOS utilizan resolutores manuales de exportación-por-hash donde sea soportado; los targets no soportados utilizan una búsqueda dinámica encubierta por sitio. |
| Despacho basado en el llamador | `morok-ckd` | `caller_keyed_dispatch` | Colapsa llamadas de usuario directas sobrevivientes a través de hubs de despacho nativos claveados por contexto del llamador y bytes de integridad sellados post-enlace. Con `carriers > 1`, el salto indirecto rota a través de distintos registros portadores guardados por el llamado (despachadores por registro `br x19`/`br x21`/…), por lo que la transferencia de control en cada sitio parece personalizada. |
| Despacho sin retorno | solo planificador | `returnless_dispatch` | Reescribe retornos en posición de cola (`return f(...)`) en saltos de cola indirectos: la función sale a través de un `br x16` / `jmp *rax` computado leído desde un slot oculto en lugar de un `ret`, y el objetivo del llamado ya no es una arista directa. Los sitios de reenvío perfecto utilizan `musttail` (sin `ret` garantizado); otros utilizan una pista `tail`. Solo califican los retornos genuinos en posición de cola — los retornos de valores computados mantienen un retorno ABI normal, y los sitios de escape/EH/`setjmp`/varargs/`sret`/`byval` se omiten. Desactivado por defecto; opcional mientras se valida por plataforma. |
| Envoltorio de función | `morok-funcwrap` | `function_wrapper` | Envuelve llamadas después de las transformaciones por función para que los llamadores vean aristas proxy. |
| Integridad de VTable | `morok-vtable` | `vtable_integrity` | Protege los despachos virtuales de Itanium C++ mediante vptr, slot, objetivo y hash de cookie esperados. |
| Cadenas señuelo | `morok-decoystr` | `decoy_strings` | Distribuye diagnósticos honeypot retenidos e infraestructura de logging falsa. Cuando el cifrado de cadenas también se ejecuta, las globales señuelo se enrutan a través de la misma ruta de cifrado que las cadenas reales para que el triaje estático no pueda clasificarlas como cebo obvio. |

Las globales `morok.decoy.str.*` generadas son intencionalmente elegibles para el cifrado de cadenas. Si solo se ejecuta `decoy_strings`, permanecen como cebo en texto plano; en tuberías normales donde también se ejecuta `string_encryption`, se cifran, se acolchan en longitud donde sea seguro y se materializan como cadenas de usuario reales para que el triaje barato no pueda separarlas por la sola visibilidad del texto plano.

Los blobs sellados son opcionales: marca una global de array de bytes privada con la sección `.morok.sealed` o un prefijo `morok.sealed.`. Los usos de llamada de carga/no-captura soportados se materializan en buffers de pila por uso vía un ayudante `morok.sealed.open.*` por blob, y luego ponen el buffer temporal en cero volátil cuando está configurado. Con `runtime_keyed_magic=true`, cada accesor generado deriva una etiqueta de prefijo por blob desde el canal de RuntimeSeal anti-debug y el id del blob, la compara contra el prefijo de texto plano materializado sin salida temprana, y almacena solo una palabra de diagnóstico volátil opaca. La comparación no es la puerta de acceso primaria y no requiere que un centinela de texto plano sobreviva en `.rodata`.

### Virtualización y Entrelazamiento de Integridad

| Capacidad | nombre `-passes` | sección TOML | Resumen |
|---|---|---|---|
| Virtualización | `morok-vm` | `virtualization` | Eleva núcleos de computación de enteros/punteros elegibles a VMs de bytecode hilado cifrado, incluyendo multi-bloque, memoria, cast, comparación, división, intrínsecos seleccionados y llamadas directas a ayudantes internos cuando sea seguro. |
| Entrega de payload por página con falla | `morok-fpp` | `fault_paged_payload` | Cifra el bytecode de la VM por página y reemplaza las cargas directas de bytecode con un accesor perezoso que descifra un caché local por página a la vez, limpia el estado de la página en los cambios y vincula el acceso anómalo al canal de sello de runtime `fault_paged_payload`. |
| Auto-descifrado restringido por hash | `morok-selfdecrypt` | `hash_gated_self_decrypt` | Descifra perezosamente el bytecode de la VM desde hashes/contexto de runtime y vuelve a cifrar al salir del ayudante. |
| Empaquetado de código nativo | `morok-nativepack` | `native_code_pack` | Paso de frontera ELF64 de Linux final. Mueve implementaciones finales de IR seleccionadas detrás de stubs de entrada de texto plano perezosos; `cross_build.sh --native-pack` suministra el cargador independiente, la región del enlazador aislada, el finalizador ChaCha20-Poly1305 post-enlace y la verificación de build-ID/auditoría. Desactivado en cada preset. |
| Vinculación de prueba externa | `morok-proofbind` | `external_secret_binding` | Materializa una API de alimentación/finalización de prueba y pliega la diferencia del digest de la prueba en el canal de sello de runtime `external_proof`, por lo que solo la prueba esperada mantiene el estado de clave limpio. |
| KDF de vinculación de entorno | `morok-envbind` | `env_binding_kdf` | Recolecta material de identidad del host inscrito, pliega las discrepancias en el canal de sello de runtime `env_binding` y alimenta los esquemas de claves de cadenas, blobs sellados y VM. |
| Atestación de trazador | `morok-tracer` | `tracer_attestation` | Utiliza un trazador compañero de Linux/x86_64 para inyectar palabras de parte solo en runtime al padre y pliega solo las deltas de discrepancia de entrega en los canales de sello de runtime de `tracer` y anti-debug. |
| Constantes de auto-checksum | `morok-selfcheck` | `self_checksum_constants` | Fusiona constantes con deltas de checksum de runtime para que la manipulación corrompa los datos en lugar de generar saltos. |
| Grafo de guardia-mutua | `morok-mutualguard` | `mutual_guard_graph` | Emite nodos de checksum superpuestos cuyo delta agregado envenena los retornos escalares. |
| Integridad del flujo de datos | `morok-dfi` | `data_flow_integrity` | Decodifica tablas de ops estrechas desde hashes de integridad de runtime y estado oculto señuelo. |
| Claveo de traza de ejecución | `morok-tracekey` | `execution_trace_keying` | Transporta un acumulador de traza rotativo y muestras de manipulación retardadas a través del estado de datos/control. |

Las funciones seleccionadas explícitamente con `annotate("vm")`, `annotate("virtualization")`, o una política de virtualización específica de función son requisitos de cobertura estrictos. Reciben prioridad sobre los candidatos ordinarios, pueden omitir la heurística de rendimiento de bucle-llamado-caliente y emiten un error de compilación si su IR optimizado no es elevable; Morok no deja silenciosamente un objetivo seleccionado explícitamente en nativo. La selección global probabilística de VM sigue siendo del mejor esfuerzo y continúa evitando los bucles calientes no seleccionados.

Para `external_secret_binding`, `expected_digest` es el acumulador de prueba final de 64 bits esperado aceptado por `morok.proof.finish`. Si se omite o es inválido, el paso utiliza un valor esperado aleatorio por compilación, por lo que la presencia de una prueba arbitraria falla cerrada en lugar de mantener el estado de sello limpio.

El despacho de la VM es total sobre los 256 IDs de manejador decodificados. Los opcodes decodificados inválidos, registros, índices de tabla de punteros, objetivos de salto y operandos de div/rem inseguros se pliegan en un acumulador de veneno local y se canonicalizan a un estado dentro de los límites en lugar de generar un trap o indexar fuera de rango. Cada instrucción cifrada embebe una etiqueta de 32 bits que vincula sus doce bytes de texto cifrado interno al manejador decodificado; el runtime recalcula la etiqueta antes del despacho y envenena cualquier registro manipulado o válido-pero-incorrecto. Deliberadamente no hay una tabla de opcodes separada por PC: tal tabla sería una copia sombra estáticamente decodificable de la secuencia de manejadores. Los campos de opcode/registro y los ocho bytes inmediatos se permutan independientemente por función; el paso de instrucción varía de 16 a 32 bytes con relleno cifrado y objetivos de salto reescalados; la decodificación de bytes selecciona una de cuatro familias de mezcladores aritméticos por función; los manejadores reales están dispersos por el espacio de objetivos de 252 entradas; y cada VM emite solo su subconjunto de ISA utilizado más un subconjunto señuelo acotado que varía con la semilla. La entrega de payload por página con falla es preferida para los payloads de VM configurados y deja el bytecode ya protegido como mutable, por lo que el auto-descifrado restringido por hash solo envuelve los payloads ansiosos restantes. No asigna un buffer de rascado de texto plano para el payload completo; el accesor descifra la página solicitada en un caché de tamaño fijo y la limpia antes de que se materialice otra página. El auto-descifrado restringido por hash sigue la misma política de modo de lanzamiento: un hash de payload fallido envenena el bytecode y lo publica como listo, por lo que la manipulación se manifiesta como una salida de VM incorrecta, no como un oráculo `llvm.trap` fijo.

El planificador ejecuta una segunda etapa de VM/endurecimiento restringida sobre los ayudantes de protección generados en la lista blanca para que la lógica de anti-debug, anti-hook, descifrador e integridad no quede como una simple isla de texto plano nativo.

### Pasos de Anti-Análisis y Runtime de Plataforma

| Capacidad | nombre `-passes` | sección TOML | Resumen |
|---|---|---|---|
| Anti-depuración | `morok-antidbg` | `anti_debugging` | Sondas de depurador POSIX en capas, cadencia de watchdog, syscalls directas donde sea soportado, rutas de ayudantes de re-exec/memfd/seccomp/Landlock de Linux, rutas de ptrace/sysctl/csops/estado-debug de Mach en macOS, y plegado de estado oculto. |
| Anti-hooking | `morok-antihook` | `anti_hooking` | Diferencial de bytes ejecutables de copia limpia, escaneo de hooks en el prólogo, MACs de ventana de función, validación de GOT/PLT o fixups de Mach-O, cumplimiento de W^X, censo del espacio de direcciones, páginas guardadas, anti-dump, chequeos de origen de la pila de llamadas, divergencia de métodos, heurísticas anti-VM/DBI, verificación de espacio negativo y puntuación de corroboración. |
| Anti-class-dump | `morok-antiacd` | `anti_class_dump` | Desordena los metadatos de Objective-C cuando están presentes. |
| Runtime de plataforma | API interna | `platform_runtime` | Centraliza el fallback de syscalls directas/libc de POSIX, syscall de anti-debug directo de Darwin, protección de páginas, archivos y decisiones de política de runtime de Windows para los productores de anti-análisis. |
| Oráculo de timing | `morok-timing` | `timing_oracles` | Muestrea tramos cortos con relojes independientes y pliega distribuciones lentas/divergentes en el estado privado. |
| Oráculo de paso-del-planificador | `morok-step` | `scheduler_step_oracles` | Muestrea contadores de cambio de contexto o sesgo de tiempo-de-hilo/reloj-de-pared en tramos cortos y pliega anomalías de alta confianza en el sello anti-debug. |
| Oráculo de trap | `morok-trap` | `trap_oracles` | Instala manejadores de trap temporales y verifica la entrega de traps. |
| Oráculo de falla-de-página/TLB | `morok-pftlb` | `page_fault_oracles` | Mapea islas de código protegidas, valida la procedencia de las fallas y pliega fallas faltantes/extra/lentas en el estado. |
| Oráculo de timing de caché | `morok-cachetime` | `cache_timing_oracles` | Persecución de punteros pseudo-aleatorios sobre bytes de código con chequeos de distribución de reloj. |
| Canario microarquitectural | `morok-microcanary` | `microarchitectural_canaries` | Muestrea efectos secundarios de predicción de saltos/especulación como evidencia de timing de baja confianza. |
| Metadatos engañosos | solo planificador | automático | Planta símbolos locales falsos retenidos, alias y metadatos de depuración contradictorios pero válidos, luego oculta los símbolos de ayudantes generados con enlace privado. |

### Pasos de Windows x86_64

Los pasos de Windows son pasos de módulo opcionales. Comparten los ayudantes de base de PE de Windows en lugar de codificar offsets o rutas de importación duplicados.

| Capacidad | nombre `-passes` | sección TOML | Resumen |
|---|---|---|---|
| Base de PE | `morok-winpe` | `windows_pe_foundation` | Emite lectores de TEB/PEB relativos a GS, resolutor de encabezados PE/exportación-por-hash, escáner de stubs de syscall, thunks de syscall directos/indirectos y sustrato de registro de VEH. |
| Chequeos de depuración de PEB/heap | `morok-winpeb` | `windows_peb_heap_debug` | Lee `BeingDebugged`, `NtGlobalFlag`, `ProcessHeap`, `Flags` y `ForceFlags` directamente. |
| Batería de objetos de depuración | `morok-windbgobj` | `windows_debug_object` | Resuelve APIs de NT por exportación hasheada y sondea el puerto/objeto/flags de depuración más el recuento de tipos de objetos de depuración. |
| Ocultar hilos | `morok-winthide` | `windows_thread_hide` | Recorre los hilos, aplica `ThreadHideFromDebugger`, lo consulta de nuevo y pliega los fallos. |
| Anti-adjuntar | `morok-winattach` | `windows_anti_attach` | Parchea ayudantes de adjunto de depurador, sondea el comportamiento de handles inválidos y evita nombres de API en texto plano. |
| Censo del depurador del kernel | `morok-winkdbg` | `windows_kernel_debugger` | Lee `SharedUserData`, consulta el estado del depurador del kernel, la muestra señales de módulo/padre/clase-de-ventana. |
| Syscalls directas/indirectas | `morok-winsys` | `windows_syscalls` | Resuelve números de syscall desde stubs de runtime y compara rutas de syscall directas frente a gadgets reciclados. |
| Censo de proceso/módulo | `morok-winprocmod` | `windows_process_modules` | Escanea instantáneas acotadas de procesos y módulos en busca de telemetría de herramientas de depuración y módulos inyectados. |
| Des-hook de KnownDlls | `morok-winunhook` | `windows_unhook` | Mapea la sección de texto prístina de `ntdll.dll`/`kernel32.dll` desde KnownDlls y refresca localmente el `.text` con hooks. |
| Auditoría de VEH | `morok-winveh` | `windows_veh_audit` | Localiza/decodifica candidatos de la lista interna de VEH y pliega hallazgos de manejadores sospechosos sin mutar el estado de VEH de todo el proceso. |
| Mitigaciones de proceso | `morok-winmitigate` | `windows_process_mitigations` | Resuelve por hash `SetProcessMitigationPolicy` y opta por ACG/CIG después de la reparación del texto de inicio de Morok. |

## Referencia de Opciones TOML

Cada campo por paso es opcional. Los campos no establecidos caen hacia el preset, la política o el valor predeterminado del paso. Los porcentajes usan `0..100` a menos que se indique lo contrario.

Usa los nombres de sección exactamente como se enumeran a continuación. Los nombres cortos internos como `sub`, `const_enc`, `stack_delta`, `vec`, `csm` y `anti_dbg` no son alias de TOML; `environment_binding_kdf` es el alias de compatibilidad aceptado para `env_binding_kdf`.

### Global y Política

| Alcance | Claves |
|---|---|
| `[global]` | `preset`, `seed`, `verbose`, `trace`, `demangle_names` |
| `[passes]` | `fail_closed_on_unsealed` más secciones de pasos anidadas |
| `[[policy]]` | `module`, `function`, `preset`, sobrescrituras anidadas `passes.<sección>.<clave>` |

`fail_closed_on_unsealed` es un interruptor de lanzamiento transversal. Cuando está habilitado, las rutas de runtime que dependen de manifiestos post-enlace fallan cerradas si un binario aún contiene centinelas de manifiesto no sellados en lugar de metadatos de ventana de código sellados.

### Secciones Estructurales y de Flujo de Control

| Sección | Claves |
|---|---|
| `bcf` | `enabled`, `probability`, `iterations`, `complexity`, `entropy_chain`, `junk_asm`, `junk_asm_min`, `junk_asm_max` |
| `split_blocks` | `enabled`, `splits`, `stack_confusion` |
| `flattening` | `enabled` |
| `data_entangled_flattening` | `enabled`, `max_terms` |
| `non_invertible_state` | `enabled`, `max_terms`, `rounds` |
| `state_opaque_predicates` | `enabled`, `probability`, `max_blocks`, `max_terms` |
| `interprocedural_fsm` | `enabled`, `probability`, `max_sites`, `max_terms` |
| `chaos_state_machine` | `enabled`, `generator`, `tf_const`, `nested_dispatch`, `warmup` |
| `dispatcherless_routing` | `enabled`, `probability`, `max_routes`, `max_terms` |
| `indirect_branch` | `enabled` |
| `microcode_stress` | `enabled`, `probability`, `max_sites`, `table_entries`, `decoy_blocks`, `alias_stores` |
| `path_explosion` | `enabled`, `probability`, `max_blocks`, `max_iterations` |
| `coherent_decoys` | `enabled`, `probability`, `max_blocks`, `depth` |
| `alias_opaque_predicates` | `enabled`, `probability`, `iterations`, `max_blocks` |
| `external_opaque_predicates` | `enabled`, `probability`, `max_blocks`, `decoy_stores` |
| `mq_gate` | `enabled`, `probability`, `vars`, `eqs`, `density`, `max_gates`, `fold_diff` |
| `nanomites` | `enabled`, `probability`, `max_sites` |
| `mirage` | `enabled`, `sensitive_only`, `clone_count`, `counterfeit_count`, `max_functions`, `max_instructions`, `counterfeit_domains`, `seal_gated_reality`, `per_invocation_epoch`, `cross_guard`, `force_route` |

`chaos_state_machine.generator` acepta `logistic` o `tfunction`. `nested_dispatch` y `warmup` se parsean como controles reservados pero actualmente son ignorados por el paso.

`mirage` está desactivado en cada preset — opta por él vía `[passes.mirage] enabled = true`. Transforma solo funciones tipo veredicto anotadas como `sensitive`/`mirage` (retorno entero/`i1`, argumentos enteros/punteros escalares, sin vararg/EH/recursión/efectos secundarios a menos que estén marcadas explícitamente como `mirage`). `counterfeit_domains` selecciona entre las plantillas integradas de `license_check`, `signature_verify`, `token_validate` y `feature_flag` (vacío = las cuatro, elegidas por compilación). `force_route` (`auto` | `real` | `fake`) es un diagnóstico de tiempo de compilación que fija la ruta del hub al emitir — solo cambia el IR generado, nunca el binario enviado, por lo que una compilación `fake` ejerce determinísticamente la ruta falsificada para pruebas sin un productor de sellos vivo. La guardia mutua entre candidatos (`cross_guard`) es una extensión de fase 2 documentada y actualmente es un no-op.

### Secciones de Escalares, Datos, Pila y Literales

| Sección | Claves |
|---|---|
| `substitution` | `enabled`, `probability`, `iterations` |
| `mba` | `enabled`, `probability`, `layers`, `heuristic` |
| `optimizer_amplification` | `enabled`, `probability`, `max_forms` |
| `sub_threshold_persistence` | `enabled`, `probability`, `max_terms` |
| `constant_encryption` | `enabled`, `iterations`, `share_count`, `feistel`, `substitute_xor`, `substitute_xor_prob`, `globalize`, `globalize_prob`, `skip_value`, `force_value` |
| `shamir_share` | `enabled`, `probability`, `threshold`, `shares`, `max_secrets` |
| `table_arithmetic` | `enabled`, `probability`, `max_tables` |
| `uniform_primitive_lowering` | `enabled`, `op_probability`, `branch_probability`, `max_tables`, `max_branches` |
| `vector_obfuscation` | `enabled`, `probability`, `width`, `shuffle`, `lift_comparisons` |
| `stack_coalescing` | `enabled`, `probability`, `opaque_offsets` |
| `stack_delta_games` | `enabled`, `probability`, `max_blocks`, `min_bytes`, `max_extra_bytes`, `touches` |
| `stack_rebase` | `enabled`, `realign_align`, `dynamic_size`, `relocate_probability`, `alias_amplify`, `nonentry_shuffle` |
| `pointer_laundering` | `enabled`, `pointer_probability`, `integer_probability` |
| `type_punning` | `enabled`, `probability`, `include_floating`, `max_targets` |
| `phi_tangling` | `enabled`, `probability`, `layers`, `max_phis` |

`constant_encryption.globalize` y `globalize_prob` se parsean por compatibilidad futura. El paso actual ya emite partes XOR como globales privadas leídas con cargas volátiles, por lo que estos controles no cambian la salida.

`vector_obfuscation.width` acepta los valores de ancho SIMD soportados por el paso `128`, `256` y `512`.

### Secciones de Cadenas, Llamadas, VM, Integridad y Runtime

| Sección | Claves |
|---|---|
| `string_encryption` | `enabled`, `probability`, `skip_content`, `force_content` |
| `function_call_obfuscate` | `enabled` |
| `caller_keyed_dispatch` | `enabled`, `probability`, `max_calls`, `region_bytes`, `seal_required`, `carriers` |
| `returnless_dispatch` | `enabled`, `probability`, `max_sites` |
| `function_fission` | `enabled`, `probability`, `max_splits`, `min_region_blocks`, `max_region_blocks` |
| `function_wrapper` | `enabled`, `probability`, `times` |
| `vtable_integrity` | `enabled` |
| `decoy_strings` | `enabled` |
| `virtualization` | `enabled`, `probability`, `max_functions`, `max_instructions`, `max_registers` |
| `fault_paged_payload` | `enabled`, `probability`, `max_payloads`, `max_payload_bytes`, `page_size`, `delivery`, `backend`, `per_page_keys`, `reseal_after_use`, `decoy_pages`, `fallback`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `hash_gated_self_decrypt` | `enabled`, `probability`, `max_payloads`, `max_payload_bytes`, `context_keying` |
| `native_code_pack` | `enabled`, `probability`, `max_functions`, `min_instructions`, `protect_generated` |
| `external_secret_binding` | `enabled`, `mode`, `public_key`, `expected_digest`, `identity_policy`, `entitlement_gate`, `entitlement_required_mask`, `entitlement_not_before_epoch`, `entitlement_not_after_epoch`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `env_binding_kdf` | `enabled`, `mode`, `expected_digest`, `identity_policy`, `min_factors`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `tracer_attestation` | `enabled`, `mode`, `shares`, `renewal`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `sealed_blob` | `enabled`, `max_blobs`, `max_blob_bytes`, `key_sources`, `delivery`, `zeroize_after_use`, `runtime_keyed_magic`, `magic_bytes` |
| `self_checksum_constants` | `enabled`, `probability`, `max_constants`, `region_bytes` |
| `data_flow_integrity` | `enabled`, `probability`, `max_tables`, `region_bytes` |
| `mutual_guard_graph` | `enabled`, `probability`, `nodes`, `region_bytes`, `max_returns` |
| `execution_trace_keying` | `enabled`, `probability`, `max_blocks` |
| `adversarial_function_merging` | `enabled`, `probability`, `max_groups`, `max_functions`, `outline_probability`, `max_outlines` |
| `adversarial_self_tuning` | `enabled`, `max_candidates`, `max_candidate_passes`, `score_floor`, `emit_marker` |
| `per_build_polymorphism` | `enabled`, `function_order`, `block_order`, `anchor_probability`, `max_anchors` |

`environment_binding_kdf` se acepta como alias de `env_binding_kdf`. `skip_content`, `force_content`, `skip_value` y `force_value` son arrays de cadenas.

### Secciones de Interruptores Anti-Análisis y Plataforma

Estas secciones actualmente aceptan solo `enabled`:

```text
anti_hooking
anti_class_dump
windows_pe_foundation
windows_peb_heap_debug
windows_debug_object
windows_thread_hide
windows_anti_attach
windows_kernel_debugger
windows_syscalls
windows_process_modules
windows_unhook
windows_veh_audit
windows_process_mitigations
timing_oracles
scheduler_step_oracles
trap_oracles
page_fault_oracles
cache_timing_oracles
microarchitectural_canaries
```

`anti_debugging` acepta `enabled`, `allow_self_trace` y `distribution_signed`. `allow_self_trace` está activado por defecto; ponlo en false para configuraciones que prefieran los chequeos de `TracerPid` de Linux reforzados por sello sobre el auto-trazado `PTRACE_TRACEME`. La clave `distribution_signed` también es forzada por `-mllvm -morok-distribution-signed` o `MOROK_DISTRIBUTION_SIGNED=1`.

`platform_runtime` acepta `enabled`, `direct_syscalls` (`auto`, `always`, `never`), `windows_mode` (`documented_api`, `hashed_import`, `direct_syscall`), `per_build_stubs`, `minimize_imports`, `import_table_audit` y `static_link_expected`. El runtime es una capa emisora interna; estos campos documentan y preestablecen la política de plataforma utilizada por los productores de anti-análisis en lugar de añadir una entrada `-passes` independiente.

## Notas de Plataforma

- macOS arm64/x86_64: target principal de la tubería e2e completa. La ruta de prueba de Apple ejerce los presets `high`/`max` completos, pruebas específicas de VM y pruebas de parcheo post-enlace adversario cuando Python está disponible.
- Linux x86_64: soportado para core/config/IR y puertas e2e portables. Las compilaciones cruzadas estáticas deshabilitan FCO automáticamente a menos que una configuración explícita decida lo contrario. El empaquetado nativo soporta salidas ELF64 estáticas, PIE y de objetos compartidos.
- Linux arm64: el empaquetado nativo soporta salidas ELF64 estáticas, PIE y de objetos compartidos. Otras rutas de runtime de alta intensidad utilizan la configuración e2e portable hasta que sus backends de runtime estén completamente portados.
- Windows x86_64: los pasos específicos de Windows emiten ayudantes de PE/PEB/TEB/exportación/syscall/VEH en el IR dirigido a Windows. La carga del plugin e2e conductual se omite en hosts Windows; la cobertura proviene de pruebas core/config/IR y pruebas rápidas dirigidas a objetos.
- Los triples no soportados mantienen fallbacks conservadores o no-ops para los pasos que necesitan diseños de contexto específicos de la plataforma.

## Notas sobre Resistencia a la Recuperación Estática

La estrategia actual de cadenas/importaciones está diseñada contra decodificadores estáticos simples:

- Las cadenas reales de arrays de bytes privados no comparten un descifrador global. Los usos seguros de C-strings obtienen materialización en la pila por uso; los usos no soportados obtienen un constructor privado por cadena.
- Cada cadena tiene material de clave independiente, variante de flujo de clave, combinación ADD/XOR y multiplicador impar, todos perturbados a través del estado de runtime volátil.
- FCO de Linux/macOS evita cadenas de símbolos en texto plano para las rutas de resolutor manual de 64 bits soportadas y, en otros casos, recurre conservadoramente.
- Los punteros de función almacenados en caché por sitio de llamada están codificados con material de semilla/clave volátil y existen como punteros brutos solo inmediatamente antes de la llamada indirecta.
- El despacho basado en el llamador, los envoltorios de funciones, la fusión/extracción adversaria y el polimorfismo por compilación reducen la forma estable de llamador/llamado entre compilaciones.
- Las cadenas señuelo se retienen y son de texto plano por diseño, por lo que `strings` debería encontrar el cebo mientras las cadenas reales del usuario permanecen ocultas.
- Los ayudantes `morok.*` generados se degradan a enlace privado al final del planificador para que los nombres descriptivos de los ayudantes no lleguen a la tabla de símbolos del objeto.

## FAQ

El manejo detallado de objeciones está en [`docs/objections.md`](docs/objections.md). Esta sección mantiene la declaración pública corta.

**¿Qué afirma realmente Morok que logra?**

Morok pretende hacer que la recuperación estática barata sea poco atractiva: `strings`, recorridos de importaciones, grafos de llamadas directas, recuperación ordinaria de switch/saltos, elevación masiva de IR y limpieza de descompilador de un solo paso deberían dejar de dar un mapa limpio del programa protegido. El objetivo es el costo del atacante, no el secreto permanente.

**¿Qué no afirma vencer?**

Un depurador, una traza DBI, un emulador o un kernel hostil que alcance el contexto de runtime adecuado puede observar el estado concreto. Si bytes en texto plano, un flujo de VM decodificado, un puntero de función resuelto o un secreto reconstruido existen en la memoria del proceso, entonces una traza dinámica suficientemente bien colocada puede verlo. Morok puede acortar las ventanas, vincular valores a chequeos de runtime y hacer que el analista trabaje por la condición de activación; no puede eliminar el límite básico del "hombre al final".

**¿Siguen produciendo algo útil IDA, Ghidra o Binary Ninja?**

Sí. Un descompilador siempre producirá algo. La cuestión es si la salida es lo suficientemente buena para un triaje rápido: cadenas estables, importaciones obvias, relaciones llamador/llamado recuperables, despachadores limpios, aritmética legible y puertas de autorización obvias. Morok intenta dañar esos puntos de referencia. No hace que la semántica original sea matemáticamente irrecuperable.

**¿Son las reescrituras MBA y los predicados opacos la frontera de seguridad?**

No. Trátalos como ruido y presión, no como protección estructural. Las identidades MBA y muchos predicados opacos son objetivos conocidos de los desofuscadores. Su trabajo es añadir superficie y forzar trabajo de prueba alrededor de mecanismos más fuertes como la recuperación de cadenas por sitio, la ofuscación de llamadas a funciones, el enrutamiento indirecto, las transformaciones de VM y el estado de runtime sellado.

**¿Se supone que las cadenas y las importaciones deben ser invisibles?**

Las cadenas protegidas reales no deben residir en el binario como texto plano ni fluir a través de un único descifrador global. Los sitios de llamada soportados utilizan la materialización por sitio, y los punteros de función se resuelven y almacenan en caché por sitio de llamada. Existen rutas de fallback, el soporte de plataforma difiere y las cadenas señuelo se dejan legibles intencionalmente. Una compilación de lanzamiento debe verificarse con herramientas estáticas normales antes de confiar en ella.

**¿La virtualización o el auto-descifrado detienen la ingeniería inversa dinámica?**

No. Cambian la tarea de "leer la función original" a "recuperar la semántica ejecutada o el flujo decodificado". Eso puede ser mucho más costoso, especialmente cuando hay sellos de runtime y condiciones de activación involucradas, pero sigue siendo un problema de análisis dinámico recuperable.

**¿El hecho de que sea de código abierto hace que el proyecto no tenga sentido?**

No, pero elimina cualquier excusa para confiar en plantillas de transformación ocultas. Asume que el atacante ha leído cada paso. Los únicos secretos que importan son las elecciones basadas en semillas por compilación, los valores restringidos por runtime y el estado específico del despliegue. La disponibilidad del código fuente también le indica a un atacante dinámico dónde buscar, por lo que las afirmaciones deben probarse en binarios, no argumentarse desde la forma del código fuente.

**¿Cuál es el listón de lanzamiento?**

Ejecuta la puerta de pruebas completa, luego inspecciona el binario como lo haría un atacante: `strings`, `nm`/`otool`/`objdump`, salida del descompilador, tablas de importaciones, trazas de runtime para rutas restringidas y estado de sello post-enlace cuando esas funciones están habilitadas. Si una compilación protegida todavía expone cadenas claras, importaciones sensibles directas o una ruta de autorización simple, trátalo como una configuración fallida o un error.

## Flujo de Desarrollo

Para una edición pequeña de un paso, utiliza primero las pruebas más enfocadas y pequeñas:

```sh
cmake --build build --target morok_ir_tests morok_config_tests morok_plugin
./build/tests/ir/morok_ir_tests
./build/tests/unit/config/morok_config_tests
```

Para ediciones de core/config:

```sh
cmake --build build --target morok_core_tests morok_config_tests
./build/tests/unit/core/morok_core_tests
./build/tests/unit/config/morok_config_tests
```

Antes de fusionar o subir una característica de código completada, ejecuta:

```sh
./run_tests.sh
git diff --check
```

Al tocar emisores de runtime de plataforma, añade una prueba rápida de objeto/binario que demuestre que las cadenas/símbolos relevantes están ausentes donde se espera y que el objeto emitido contiene la forma de constructor/ayudante esperada.

Al tocar la integridad post-enlace, verifica ambas mitades:

```sh
./run_tests.sh -L adversarial
python3 tests/e2e/adversarial_binary.py seal path/to/binary --window 262144
```

El comando de sellado predeterminado debe cubrir la ventana completa de código nativo solicitada. No uses `region_bytes` como un límite de ventana de código; este solo dimensiona la región de datos sintéticos de auto-chequeo.

## Resolución de Problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| CMake no puede encontrar `llvm/Plugins/PassPlugin.h` | Al LLVM del host le falta el encabezado de plugin New-PM API-v2 | Apunta `LLVM_DIR` a la misma instalación de LLVM API-v2 utilizada por `clang`/`opt`. |
| La carga del plugin reporta un desajuste de API/versión | `clang`/`opt` y Morok fueron compilados contra diferentes ABIs de plugin de LLVM | Recompila Morok con el mismo LLVM utilizado por el driver del host. |
| `-mllvm -morok` es desconocido en Windows | Las `cl::opts` del plugin de Windows no son parseadas por el clang del host de la misma manera | Usa `MOROK_ENABLE=1` más `MOROK_CONFIG`, `MOROK_PRESET` y `MOROK_SEED`. |
| Binario estático de Linux choca alrededor de la indirección de importación | FCO se dejó habilitado en un enlace estático | Usa `cross_build.sh` o fuerza `[passes.function_call_obfuscate].enabled = false` y `[passes.platform_runtime].static_link_expected = true`. |
| El auto-checksum no detecta un parche nativo | Los manifiestos post-enlace no fueron sellados | Sella después del enlace/strip final y ejecuta `tools/morok-audit.py --release --require-sealed-manifest`. |
| La finalización de native-pack reporta que no hay rango protegido | Ninguna función elegible sobrevivió a la probabilidad/umbral configurado | Baja `min_instructions`, aumenta `probability`/`max_functions`, o anota las funciones requeridas con `nativepack`. |
| La finalización de native-pack rechaza IFUNC/IRELATIVE/relocalización de texto | El artefacto contiene código que puede ejecutarse o ser reescrito antes de la apertura perezosa | Deja ese constructo fuera de la compilación protegida o elimínalo; el finalizador falla cerrado intencionalmente. |
| E2E max falla fuera de Apple | Algunas rutas de runtime/backend de nivel máximo siguen siendo prioritarias para Apple | Usa `tests/e2e/portable.toml` y consulta los comentarios en ese archivo. |
| Una entrada enorme deja de recibir transformaciones posteriores | Los presupuestos de crecimiento del planificador se están activando | Limita con políticas/anotaciones o aumenta el presupuesto del paso específico después de añadir pruebas. |

## Documentos Relacionados y Ejemplos

- [`docs/algorithms.md`](docs/algorithms.md): referencia de algoritmos y planificador.
- [`docs/hardness.md`](docs/hardness.md): especificaciones de primitivas basadas en dureza.
- [`docs/insurance-tasks.md`](docs/insurance-tasks.md): lista de tareas implementables.
- [`docs/objections.md`](docs/objections.md): limitaciones y manejo de objeciones.
- [`tests/e2e/*.toml`](tests/e2e): configuraciones de tubería probadas.
- [`tools/morok-audit.py`](tools/morok-audit.py): puerta de auditoría de binarios de lanzamiento.
- [`crackmes/zorya/AUTHORS_NOTE.md`](crackmes/zorya/AUTHORS_NOTE.md): ejemplo de verificador sellado y modelo de seguridad.

## Licencia

MIT. Mira [`LICENSE`](LICENSE).
