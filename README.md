# Операционные системы
## Курсовая работа

### Тема

Загружаемый модуль ядра для ОС Linux, позволяющий скрывать файлы или запрещать их изменение, чтение и удаление.

### Задание

Разработать загружаемый модуль ядра для ОС Linux, позволяющий скрывать файлы или запрещать их изменение, чтение и удаление. Предусмотреть возможность ввода пароля для отображения файлов или разрешения операций над ними. Предоставить пользователю возможность задавать список таких файлов.

## hidden file

файлы которые необходимо скрыть

```bash
$ echo hiddent.txt > hidden # в /proc

$ touch hidden.txt
$ ls
-- no results--
$ echo "1234" > /dev/usb15
$ ls
hidden.txt
$ echo "1234" > /dev/usb15
$ ls
-- no results--
```

## protected file

файлы, для которых необходимо запретить запись, чтение и удаление

```bash
$ echo protected.txt > protected # в /proc

$ ls
test.txt protected.txt
$ rm protected.txt
$ ls 
test.txt protected.txt
$ echo "5678" > /dev/usb15     
$ rm protected.txt
$ ls
test.txt
```

## PS
В РПЗ написано, что я подменяю open и unlink. Но на самом деле подменяются openat и unlinkat. Перехват open и unlink у меня не завелись, поэтому пришлось соврать.

Еще у меня не работает нормально write. если будете пытаться выполнить echo в файл, то терминал просто убьется. Хотя запись выполнена не будет, и формально тз выполнено)

## PPS
Идея и основной код были взяты из https://github.com/timb-machine-mirrors/CoolerVoid-casper-fs.git
