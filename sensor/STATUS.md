# Provenza egress sensor — черновик (не готов к слиянию)

## Готово и проверено
- `bpf/sensor.bpf.c` — программа ядра. Компилируется (`make bpf`, clang ≥ 14).
  Ядро 6.18 приняло 11 обязательных программ (connect/sendmsg/recvmsg/getpeername 4+6,
  sock_create, cgroup_skb egress/ingress) и программы cgroup_mkdir/rmdir.
  LSM‑программа (socket_create) не проверена: в тестовой среде lockdown.
- `internal/bpfobj` — встроенный объект и Go‑структуры; тест сверяет размеры с BTF.
- `internal/kerneltest` — проверка верификатором (`sudo make test-kernel`).
- `internal/kern/kern.go` — загрузка, Attach с закреплением в bpffs и обновлением
  на месте. Компилируется, в ядре не проверено.
- `internal/kern/policy.go` — политика по поколениям (N+1 целиком → переключение
  `globals.gen` → удаление старого), адреса из DNS, cgroups/uids, epoch, хэш путей.
- `internal/config` — sensor.json и формат политики от Provenza с проверкой.
- `internal/client` — API Provenza (config с ETag, heartbeat, violations), кэш политики.

## Не сделано
1. `internal/cgroups` — поиск cgroup по шаблонам, id через name_to_handle_at,
   создание cgroup для `run`.
2. Демон: опрос `/api/v1/egress-sensor/config` (ETag, кэш на диске), сопоставление
   шаблонов cgroup (обход + события mkdir из ringbuf), uid по имени, DNS‑прокси на
   workload (dnsmessage; режимы listed/any/off; добавление IP из ответов),
   агрегация событий → `/violations`, heartbeat, `provenza-sensor run --agent N -- cmd`
   (unix‑сокет, SO_PEERCRED), `uninstall`, systemd unit.
3. Функциональные тесты в ядре: разрешено/запрещено TCP/UDP, DNS‑перенаправление,
   сырые сокеты, входящие, изоляция, смена поколения без открытого окна.
4. Сервер: переделать черновик backend (dns_mode вместо allow_dns, run_as_users,
   ingress_allow, мягкое удаление, dst_name/kind dns в нарушениях), тесты.
5. Интерфейс: вкладка «Сенсоры» в «Шлюзах», карточка на странице агента, en/uz.
6. Документация, CI (go vet/test + clang), go.sum.

## Сборка
    cd sensor && go mod tidy   # создаст go.sum (нужен интернет)
    make bpf && make test
    sudo make test-kernel
