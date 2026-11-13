# Реверс клиента Roblox в Sober

Заметки по тому, как устроен рантайм и как в него входиться.

## Что такое Sober 1.8

* flatpak `org.vinegarhq.Sober`, runtime `org.gnome.Platform/51`.
* Скачивает Roblox **Android** APK (`base.apk` + `split_config.x86_64.apk`) в
  `~/.var/app/org.vinegarhq.Sober/data/sober/packages/x86_64/com.roblox.client/`.
* Клиент — `lib/x86_64/libroblox.so` из сплит-APK: стрипнутый x86_64 ELF,
  собран NDK (r28c), ~116 МБ.
* Клиент **не** грузится ld.so песочницы: его стартует собственный
  загрузчик Sober (`/app/bin/libloader.so`), который достаёт библиотеки из
  APK и маппит их через memfd (в `/proc/<pid>/maps` они видны как
  `/memfd: (deleted)`).

Раскладка по процессам (внутри sandbox PID namespace):

```
1  bwrap
2  sober          ← runtime, tracer клиента
3  клиент Roblox  ← образ из memfd, здесь живёт Luau
```

## Ограничения (и как они обнаружены)

| что | как проверено |
|---|---|
| `LD_PRELOAD` вырезается из env клиента | `cat /proc/<pid>/environ` клиента: переменной нет, хотя `flatpak override --env=LD_PRELOAD=...` её задаёт |
| `LD_AUDIT` тоже: ld.so в песочнице грузит библиотеки как audit-модули | `ld.so: object '...' cannot be loaded as audit interface: undefined symbol: la_version` |
| preload не доходит до клиента | маркер из preloaded-библиотеки пишет `pid=4` (это runtime), а не pid клиента |
| клиент уже трассируется | `TracerPid` клиента = pid рантайма; gdb: `process is already traced by process ...` |
| `/proc/<pid>/mem` читается и пишется | запись 8 байт в образ клиента проходит, клиент жив |
| syscall из инжектированного кода убивает клиент | пробник `getpid`/`socket`/`mmap` в клиенте → клиент падает; тот же код в обычном процессе работает |
| файлы Sober'а проверяются | подмена `libbadcpu.so` → рантайм не стартует; APK перекачивается при каждом запуске |

Отсюда две конструктивные выводы:

1. **Агент не должен делать системных вызовов**, пока он в клиенте. Отсюда
   почтовый ящик в памяти вместо сокета.
2. **Агент должен лежать внутри образа клиента** — тогда чужой код не
   отличить от своего (и `check_security` не придраться к содержимому
   файлов Sober'а, пока он не тронул их сам).

## Восстановление Luau-API

Клиент стрипнут, символов нет. Но Luau — открытый код, и Roblox собрал
его из тех же исходников, что и upstream. Значит функции сохранили и
порядок, и размеры.

`tools/scan_symbols.py`:

1. берёт `.eh_frame` клиента → точные границы всех 225 287 функций;
2. берёт объектные файлы эталонной сборки Luau (`work/luau-src/build-rel`);
3. выравнивает последовательности функций по размерам (Needleman–Wunsch);
4. печатает `src/agent/luau_symbols.h`.

Совпадения ��а практически точные (размер функции совпадает байт в байт),
поэтому identification однозначна.

Проверенные смещения (сборка клиента на 2026-11-10):

```
API_LUA_COMPILE     0x645aeba   luau_compile
API_LUA_LOAD        0x35d8ba2   luau_load
API_LUA_PCALL       0x5008e08   lua_pcall
API_LUA_GETFIELD    0x47872e2   lua_getfield
API_LUA_GETTOP      0x3373a0a   lua_gettop
API_LUA_SETTOP      0x33b2ee6   lua_settop
API_LUA_TOLSTRING   0x3ea1046   lua_tolstring
API_LUA_TYPE        0x3691dec   lua_type
API_LUA_INTERPRETER 0x653f8fe   luau_execute<false>
```

Смещения меняются от сборки к сборке — поэтому есть генератор.

### Две копии Luau

В образе клиента лежат **две** копии Luau (одна в районе 0x22xxxx-0x25xxxx,
другая — в других местах). Выравнивание по эталону находит обе; живая —
та, чей интерпретатор реально вызывается. Сейчас это проверяется не хуком
в коде, а состоянием VM: агент находит `global_State` по якорю
`cb.userthread` и пробой спрашивает у VM, игровая ли она
(`typeof(game) .. "/" .. typeof(workspace)`).

## Инструменты

| файл | что делает |
|---|---|
| `tools/scan_symbols.py` | восстанавливает Luau-API клиента |
| `tools/ehframe.py` (в `tools/`) | функции клиента по `.eh_frame` |
| `tools/align.py` | выравнивание клиента по эталонной сборке Luau |
| `tools/patch_apk.py` | патч APK: агент в дыру между секциями + детур |
| `tools/watch_apk.py` | ловит перекачку APK и патчит сразу |
| `tools/install_preload.sh` | регистрирует агента в `ld.so.preload` рантайма |
