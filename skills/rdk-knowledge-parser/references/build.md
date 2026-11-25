# Build dependencies

## Yocto (`meta-rdk-*` layers)

Find the recipe: `find <layers> -name '<component>*.bb*'`. Read the `.bb` and **every** `.bbappend` (vendor
and platform layers override). Extract:

| Variable | Meaning |
|---|---|
| `DEPENDS` | build-time (headers, libs, native tools). Each entry is a recipe. |
| `RDEPENDS:${PN}` / `RDEPENDS_${PN}` | runtime packages on target (scripts, CLIs, daemons). |
| `RRECOMMENDS`, `RPROVIDES`, `PROVIDES`, `RCONFLICTS` | soft/alias relations. |
| `EXTRA_OECONF`, `EXTRA_OECMAKE`, `EXTRA_OEMAKE`, `PACKAGECONFIG` | feature switches into the build. |
| `CFLAGS:append`, `LDFLAGS:append` | `-D` defines and `-l` libraries added by the layer. |
| `bb.utils.contains('DISTRO_FEATURES', 'x', ...)` | distro gate. Record it with the dep it gates. |
| `inherit autotools pkgconfig systemd coverity breakpad` | build classes. |
| `SYSTEMD_SERVICE:${PN}`, `do_install` `${D}${bindir}/...` | installed units and files (runtime contracts). |
| `SRC_URI` (patches, files) | patched behavior, extra scripts. |

Override syntax: both old `_append`/`_${PN}` and new `:append`/`:${PN}` exist. Check `MACHINE` and `DISTRO` overrides
(`:broadband`, `:dunfell`, `:<machine>`).

## Autotools

- `configure.ac`: `PKG_CHECK_MODULES([DBUS],[dbus-1 >= 1.6.18])`, `AC_CHECK_LIB`, `AC_CHECK_HEADERS`,
  `AC_ARG_ENABLE([firewall-nft])`, `AM_CONDITIONAL([CPC_FIREWALL_ENABLE], ...)`, `AC_SUBST`.
- `Makefile.am`: `<target>_LDADD`, `<target>_LIBADD`, `<target>_LDFLAGS`, `<target>_CFLAGS`, `AM_CPPFLAGS`,
  `SUBDIRS`, `if FEATURE ... endif` blocks.
- Internal libs: `$(top_builddir)/source/syscfg/lib/libsyscfg.la`: inter-module dependency inside the repo.
- External libs: `-lccsp_common -lsecure_wrapper -ltelemetry_msgsender -lsysevent -lsyscfg -lulog -lutctx -lutapi ...`.

## CMake / Make / Meson

- CMake: `find_package`, `pkg_check_modules`, `find_library`, `target_link_libraries`, `target_include_directories`,
  `add_subdirectory`, `option(...)`, `add_definitions(-D...)`.
- Make: `LDFLAGS += -l...`, `CFLAGS += -I... -D...`, `LIBS`.
- Meson: `dependency('x')`, `cc.find_library`.

## Flags

- `-lX`: link library (map to providing recipe). `-L<dir>`: search path (often staging sysroot).
- `-I<dir>`: header source, e.g. `-I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/ccsp` means CCSP headers.
- `-DX`: feature define. Cross-reference with `#ifdef X` in code.
- Static `.a` vs shared `.so`: `.la`/`LTLIBRARIES` → shared by default; `noinst_` → internal convenience lib.

## Headers

`#include <ccsp_base_api.h>`, `"sysevent/sysevent.h"`, `<syscfg/syscfg.h>`, `<telemetry_busmessage_sender.h>`,
`"secure_wrapper.h"`, `"safec_lib_common.h"`, `<rbus/rbus.h>`, `<msgpack.h>`, `<cjson/cJSON.h>`,
`<libnetfilter_queue/...>`, `<platform_hal.h>`. Map each non-libc header to its providing library/recipe.

## Compile-time features

Every `#if/#ifdef/#ifndef` macro (e.g. `_HUB4_PRODUCT_REQ_`, `RDKB_EXTENDER_ENABLED`, `CONFIG_CISCO_FEATURE`,
`FEATURE_SUPPORT_MAPT_NAT46`, `_PLATFORM_RASPBERRYPI_`, `MULTILAN_FEATURE`) is a gate.
Trace its source: `-D` in Makefile.am/configure.ac, `CFLAGS:append` in a `.bbappend`, or `DISTRO_FEATURES`.

## Tests

gtest/gmock (`-lgtest -lgmock`), `mocks/mock_*.h`, `test/` dirs, `cov_docker_script/`, `build_tools_workflows/`
→ test/CI dependencies only.
