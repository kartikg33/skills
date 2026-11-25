# Runtime orchestration dependencies

Who starts the component, who it starts, and in what order.

## systemd

- Unit files (`*.service`, `*.path`, `*.timer`, `*.target`) in the repo or the recipe's `SRC_URI`.
- Edges: `After=`, `Before=`, `Requires=`, `Wants=`, `BindsTo=`, `PartOf=`, `Conflicts=`.
- `ExecStart*=`/`ExecStop=`: binaries and scripts run. `EnvironmentFile=`: env dependency.
- `ConditionPathExists=` / `.path` `PathExists=`: file-triggered start.
- Runtime control from code: `systemctl restart <unit>`.

## Utopia service framework (sysevent-driven)

- Registration: `scripts/init/c_registration/NN_<svc>.c` → `sm_register(name, default_handler, custom_events[])`.
  Numbers set boot order. `default_handler` (e.g. `/etc/utopia/service.d/service_syslog.sh`) handles `<svc>-start|stop|restart`.
- Custom events `"event|handler|flags|params"` subscribe `handler` to `event`.
- Shell: `service_init`, `service_start`, `service_stop`, `wait_till_end_state`, `sysevent async`.
- `execute_dir /etc/utopia/post.d` etc: runs every script in a directory.
- Init scripts: `utopia_init*.sh` start `syseventd`, create syscfg, apply defaults.

## Process monitoring

`pmon.sh` (utopia process monitor), `selfheal`, `processMonitor`, `check_*` scripts, cron jobs: they restart the
component, so they depend on its name and pid file.

## Cron and timers

`crontab` entries, `/etc/cron/cron.everyminute/`, `addCron "<sched> <cmd>"`, systemd `.timer`.

## Cross-CPU / container

`rpcclient <ip> "<cmd>"`, `arris_rpc_client`, `ncpu_exec`, `lxc-ls`, `/tmp/container_env.sh`, `/tmp/.lxcIptablesLock`:
the component runs commands on, or shares state with, another CPU or container.
